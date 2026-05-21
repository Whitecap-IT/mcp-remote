/**
 * Opportunistic background update check.
 *
 * Goals:
 *   - The user's running mcp-remote is never blocked by this code.
 *   - If the internal npm registry is unreachable, slow, or returns
 *     anything unexpected, the running proxy keeps working with the
 *     already-installed global binary.
 *   - When a newer version is available and the registry is reachable,
 *     run `npm install -g @wcap/mcp-remote@latest` in a detached child
 *     process. The new code only takes effect on the next Claude Desktop
 *     restart - the currently running process is never re-execed.
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

interface UpdateCheckState {
  /** Unix ms of the last completed check (success OR silent failure). */
  lastCheckedAt: number
  /** The latest version observed at the last check; informational only. */
  lastSeenLatest?: string
}

function stateFilePath(): string {
  const baseConfigDir = process.env.MCP_REMOTE_CONFIG_DIR || path.join(os.homedir(), '.mcp-auth')
  return path.join(baseConfigDir, 'last-update-check.json')
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
async function fetchLatestVersion(registry: string): Promise<string | null> {
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
    const body = (await res.json()) as { 'dist-tags'?: { latest?: string } }
    const latest = body['dist-tags']?.latest
    if (typeof latest !== 'string' || !latest) {
      debugLog('update-check: registry response missing dist-tags.latest')
      return null
    }
    return latest
  } catch (err) {
    debugLog('update-check: registry fetch failed', err)
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
 * Spawn `npm install -g @wcap/mcp-remote@latest` detached. We don't await
 * completion - the install can outlive the current process if needed.
 * stdout/stderr is captured for debug logging only, never surfaced.
 */
function spawnBackgroundInstall(registry: string, fromVersion: string, toVersion: string): void {
  const args = ['install', '-g', `${PACKAGE_NAME}@${toVersion}`, '--registry', registry]
  debugLog('update-check: spawning background install', { args })

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
    debugLog('update-check: install child errored', err)
  })

  child.on('exit', (code, signal) => {
    clearTimeout(killTimer)
    const stdout = Buffer.concat(stdoutChunks).toString('utf8')
    const stderr = Buffer.concat(stderrChunks).toString('utf8')
    if (code === 0) {
      log(
        `Background update installed: ${fromVersion} -> ${toVersion}. ` +
          `Restart Claude Desktop to use the new version.`,
      )
      debugLog('update-check: install succeeded', { stdout, stderr })
    } else {
      debugLog('update-check: install failed', { code, signal, stdout, stderr })
    }
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

  // setImmediate + .catch to make sure nothing about this code path can
  // unhandled-reject during the proxy's startup.
  setImmediate(() => {
    runCheck(registry).catch((err) => {
      debugLog('update-check: top-level catch (this is a bug)', err)
    })
  })
}

async function runCheck(registry: string): Promise<void> {
  const now = Date.now()
  const state = await readState()
  if (state && now - state.lastCheckedAt < THROTTLE_WINDOW_MS) {
    debugLog('update-check: skipped, within throttle window', {
      lastCheckedAt: state.lastCheckedAt,
      ageMs: now - state.lastCheckedAt,
    })
    return
  }

  const latest = await fetchLatestVersion(registry)
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
  spawnBackgroundInstall(registry, MCP_REMOTE_VERSION, latest)
}
