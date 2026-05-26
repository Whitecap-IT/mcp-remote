/**
 * Opportunistic background update check.
 *
 * Goals:
 *   - The user's running mcp-remote is never blocked by this code.
 *   - If the internal npm registry is unreachable, slow, or returns
 *     anything unexpected, the running proxy keeps working with the
 *     already-installed global binary.
 *   - When a newer version is available and the registry is reachable,
 *     download the exact tarball from registry metadata and run
 *     `npm install -g <downloaded tarball>` in a child process. The new
 *     code only takes effect on the next Claude Desktop restart - the
 *     currently running process is never re-execed.
 *   - Throttle to at most one check per 24h via a small state file in
 *     ~/.mcp-auth/last-update-check.json. Restarting Claude Desktop ten
 *     times in a row should not hammer Verdaccio.
 *   - Every failure is logged at debug level and swallowed. The only
 *     user-visible log line is the one-shot success notice telling them
 *     to restart Claude Desktop to use the new version.
 *
 * Opt out via MCP_REMOTE_DISABLE_UPDATE_CHECK=1.
 */

import { spawn } from 'child_process'
import { promises as fs } from 'fs'
import * as os from 'os'
import * as path from 'path'
import { log, debugLog, MCP_REMOTE_VERSION } from './utils'

const PACKAGE_NAME = '@wcap/mcp-remote'
const REGISTRY_TIMEOUT_MS = 5_000
const INSTALL_TIMEOUT_MS = 30_000
const THROTTLE_WINDOW_MS = 24 * 60 * 60 * 1000
// Wait briefly before starting the update check so a process that Claude
// Desktop spawns and immediately kills (config probe, port collision, quick
// restart) never starts an `npm install -g`. Anything that survives 5
// seconds is committed enough for us to consider updating its binary.
// MCP_REMOTE_UPDATE_STARTUP_DELAY_MS overrides for tests / debugging.
const DEFAULT_STARTUP_DELAY_MS = 5_000
function startupDelayMs(): number {
  const raw = process.env.MCP_REMOTE_UPDATE_STARTUP_DELAY_MS
  if (!raw) return DEFAULT_STARTUP_DELAY_MS
  const parsed = Number.parseInt(raw, 10)
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : DEFAULT_STARTUP_DELAY_MS
}
// Stale lock window. Legitimate installs finish well within INSTALL_TIMEOUT_MS
// (30s), but on Windows an AV scan of the tarball, npm's own retry-with-
// backoff against a slow registry, or a contended global node_modules can
// stretch a real install past 2 minutes. 10 minutes keeps a stuck process
// from blocking forever while staying generous enough that we don't
// misidentify a slow-but-healthy install as crashed and clobber it.
const LOCK_STALE_MS = 10 * 60 * 1000

interface UpdateCheckState {
  /** Unix ms of the last completed check (success OR silent failure). */
  lastCheckedAt: number
  /** The latest version observed at the last check; informational only. */
  lastSeenLatest?: string
}

interface LatestPackage {
  version: string
  tarballUrl?: string
}

function baseConfigDir(): string {
  const baseConfigDir = process.env.MCP_REMOTE_CONFIG_DIR || path.join(os.homedir(), '.mcp-auth')
  return baseConfigDir
}

function stateFilePath(): string {
  return path.join(baseConfigDir(), 'last-update-check.json')
}

function lockDirPath(): string {
  return path.join(baseConfigDir(), 'update-check.lock')
}

async function readState(): Promise<UpdateCheckState | null> {
  try {
    const raw = await fs.readFile(stateFilePath(), 'utf8')
    return JSON.parse(raw) as UpdateCheckState
  } catch {
    return null
  }
}

async function writeState(state: UpdateCheckState): Promise<void> {
  try {
    const filePath = stateFilePath()
    await fs.mkdir(path.dirname(filePath), { recursive: true })
    await fs.writeFile(filePath, JSON.stringify(state), 'utf8')
  } catch (err) {
    debugLog('update-check: failed to persist throttle state', err)
  }
}

/**
 * Resolve the latest published version from the configured npm registry.
 * Returns null on any failure (network, parse, non-200, missing field).
 */
async function fetchLatestPackage(registry: string): Promise<LatestPackage | null> {
  const url = registry.replace(/\/+$/, '') + '/' + encodeURIComponent(PACKAGE_NAME).replace('%40', '@')

  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), REGISTRY_TIMEOUT_MS)
  try {
    const res = await fetch(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
      signal: controller.signal,
    })
    if (!res.ok) {
      debugLog('update-check: registry returned non-2xx', { status: res.status })
      return null
    }
    const body = (await res.json()) as {
      'dist-tags'?: { latest?: string }
      versions?: Record<string, { dist?: { tarball?: string } }>
    }
    const latest = body['dist-tags']?.latest
    if (typeof latest !== 'string' || !latest) {
      debugLog('update-check: registry response missing dist-tags.latest')
      return null
    }
    const tarballUrl = body.versions?.[latest]?.dist?.tarball
    return {
      version: latest,
      ...(typeof tarballUrl === 'string' && tarballUrl ? { tarballUrl } : {}),
    }
  } catch (err) {
    debugLog('update-check: registry fetch failed', err)
    return null
  } finally {
    clearTimeout(timer)
  }
}

async function acquireUpdateLock(): Promise<(() => Promise<void>) | null> {
  const lockPath = lockDirPath()
  await fs.mkdir(path.dirname(lockPath), { recursive: true })

  const tryAcquire = async (): Promise<boolean> => {
    try {
      await fs.mkdir(lockPath)
      await fs.writeFile(path.join(lockPath, 'owner.json'), JSON.stringify({ pid: process.pid, createdAt: Date.now() }), 'utf8')
      return true
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'EEXIST') {
        debugLog('update-check: failed to acquire lock', err)
      }
      return false
    }
  }

  if (!(await tryAcquire())) {
    try {
      const stat = await fs.stat(lockPath)
      if (Date.now() - stat.mtimeMs > LOCK_STALE_MS) {
        debugLog('update-check: removing stale lock')
        await fs.rm(lockPath, { recursive: true, force: true })
        if (!(await tryAcquire())) {
          debugLog('update-check: another process holds updater lock')
          return null
        }
      } else {
        debugLog('update-check: another process holds updater lock')
        return null
      }
    } catch (err) {
      debugLog('update-check: failed while checking existing lock', err)
      return null
    }
  }

  return async () => {
    await fs.rm(lockPath, { recursive: true, force: true }).catch((err) => {
      debugLog('update-check: failed to release lock', err)
    })
  }
}

async function downloadTarball(tarballUrl: string, version: string): Promise<string | null> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), REGISTRY_TIMEOUT_MS)
  try {
    const res = await fetch(tarballUrl, { method: 'GET', signal: controller.signal })
    if (!res.ok) {
      debugLog('update-check: tarball download returned non-2xx', { status: res.status })
      return null
    }
    const body = Buffer.from(await res.arrayBuffer())
    const filePath = path.join(os.tmpdir(), `wcap-mcp-remote-${version}-${process.pid}-${Date.now()}.tgz`)
    await fs.writeFile(filePath, body)
    return filePath
  } catch (err) {
    debugLog('update-check: tarball download failed', err)
    return null
  } finally {
    clearTimeout(timer)
  }
}

/**
 * Compare two semver-ish strings. Returns true if `latest` should be
 * considered newer than `current`. Pure string equality short-circuits
 * to false. For everything else we do a numeric-aware lexicographic
 * compare on dot/hyphen-separated tokens. This is not full semver but
 * is sufficient for @wcap/mcp-remote's `MAJOR.MINOR.PATCH-wcap.N` shape.
 */
export function isNewerVersion(latest: string, current: string): boolean {
  if (latest === current) return false
  const tokenize = (v: string) => v.split(/[.\-]/).map((tok) => (/^\d+$/.test(tok) ? Number(tok) : tok))
  const a = tokenize(latest)
  const b = tokenize(current)
  const len = Math.max(a.length, b.length)
  for (let i = 0; i < len; i++) {
    const ai = a[i]
    const bi = b[i]
    if (ai === bi) continue
    if (ai === undefined) return false
    if (bi === undefined) return true
    if (typeof ai === 'number' && typeof bi === 'number') return ai > bi
    return String(ai) > String(bi)
  }
  return false
}

/**
 * Spawn `npm install -g <target>`. The caller runs this in the background
 * update chain, not on the proxy startup path.
 */
function spawnBackgroundInstall(registry: string, fromVersion: string, toVersion: string, installTarget: string): Promise<void> {
  const args = ['install', '-g', installTarget, '--registry', registry, '--prefer-online']
  debugLog('update-check: spawning background install', { args })

  return new Promise((resolve) => {
    let child
    try {
      child = spawn('npm', args, {
        stdio: ['ignore', 'pipe', 'pipe'],
        detached: false,
        shell: process.platform === 'win32',
        windowsHide: true,
      })
    } catch (err) {
      debugLog('update-check: spawn npm failed', err)
      resolve()
      return
    }

    const stdoutChunks: Buffer[] = []
    const stderrChunks: Buffer[] = []
    child.stdout?.on('data', (chunk: Buffer) => stdoutChunks.push(chunk))
    child.stderr?.on('data', (chunk: Buffer) => stderrChunks.push(chunk))

    const killTimer = setTimeout(() => {
      debugLog('update-check: install exceeded timeout, killing')
      try {
        child.kill()
      } catch (err) {
        debugLog('update-check: kill failed', err)
      }
    }, INSTALL_TIMEOUT_MS)

    child.on('error', (err) => {
      clearTimeout(killTimer)
      debugLog('update-check: install child errored', err)
      resolve()
    })

    child.on('exit', (code, signal) => {
      clearTimeout(killTimer)
      const stdout = Buffer.concat(stdoutChunks).toString('utf8')
      const stderr = Buffer.concat(stderrChunks).toString('utf8')
      if (code === 0) {
        log(`Background update installed: ${fromVersion} -> ${toVersion}. ` + `Restart Claude Desktop to use the new version.`)
        debugLog('update-check: install succeeded', { stdout, stderr })
      } else {
        debugLog('update-check: install failed', { code, signal, stdout, stderr })
      }
      resolve()
    })
  })
}

/**
 * Public entry point. Resolves immediately so callers can await it
 * without blocking the proxy startup path. All real work happens on a
 * detached promise chain that swallows every error.
 */
export function maybeBackgroundUpdate(registry: string): void {
  if (process.env.MCP_REMOTE_DISABLE_UPDATE_CHECK === '1' || process.env.MCP_REMOTE_DISABLE_UPDATE_CHECK === 'true') {
    debugLog('update-check: disabled via MCP_REMOTE_DISABLE_UPDATE_CHECK')
    return
  }

  // setTimeout (not setImmediate) + .catch so this code path can never
  // unhandled-reject. The STARTUP_DELAY_MS pause is the key behavior change
  // over wcap.18: if Claude Desktop SIGKILLs the mcp-remote process within
  // 5 seconds (which is its usual probe-then-kill pattern on misconfigured
  // servers, port conflicts, or restarts), the timer fires inside an
  // already-dead process and the timer reference is harmlessly GC'd. No
  // global `npm install -g` ever starts for a throwaway process.
  const timer = setTimeout(() => {
    runCheck(registry).catch((err) => {
      debugLog('update-check: top-level catch (this is a bug)', err)
    })
  }, startupDelayMs())
  // Don't let a pending update timer keep the Node event loop alive: if the
  // proxy's own cleanup path has decided we're done, the timer should not
  // delay process exit.
  if (typeof timer.unref === 'function') timer.unref()
}

async function runCheck(registry: string): Promise<void> {
  const releaseLock = await acquireUpdateLock()
  if (!releaseLock) return

  let downloadedTarball: string | null = null
  try {
    const now = Date.now()
    const state = await readState()
    if (state && now - state.lastCheckedAt < THROTTLE_WINDOW_MS) {
      debugLog('update-check: skipped, within throttle window', {
        lastCheckedAt: state.lastCheckedAt,
        ageMs: now - state.lastCheckedAt,
      })
      return
    }

    const latestPackage = await fetchLatestPackage(registry)
    const latest = latestPackage?.version
    // Always persist the check timestamp even on failure so we don't retry
    // every 30s when the registry is briefly down.
    await writeState({ lastCheckedAt: now, lastSeenLatest: latest || state?.lastSeenLatest })

    if (!latest) {
      debugLog('update-check: no latest version resolved; staying on', { current: MCP_REMOTE_VERSION })
      return
    }

    if (!isNewerVersion(latest, MCP_REMOTE_VERSION)) {
      debugLog('update-check: already on latest', { current: MCP_REMOTE_VERSION, latest })
      return
    }

    debugLog('update-check: newer version available', { current: MCP_REMOTE_VERSION, latest })
    if (latestPackage.tarballUrl) {
      downloadedTarball = await downloadTarball(latestPackage.tarballUrl, latest)
    }

    const installTarget = downloadedTarball || `${PACKAGE_NAME}@${latest}`
    await spawnBackgroundInstall(registry, MCP_REMOTE_VERSION, latest, installTarget)
  } finally {
    if (downloadedTarball) {
      await fs.unlink(downloadedTarball).catch((err) => {
        debugLog('update-check: failed to remove downloaded tarball', err)
      })
    }
    await releaseLock()
  }
}
