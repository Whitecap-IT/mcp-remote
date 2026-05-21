import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { promises as fs } from 'fs'
import * as os from 'os'
import * as path from 'path'

const CURRENT_VERSION = '0.1.38-wcap.17'

vi.mock('./utils', () => ({
  log: vi.fn(),
  debugLog: vi.fn(),
  MCP_REMOTE_VERSION: CURRENT_VERSION,
}))

// vi.mock() is hoisted; hoisted() makes `mockSpawn` reachable from the
// factory at hoist time so the mock returns the same fn we assert on.
const { mockSpawn } = vi.hoisted(() => ({ mockSpawn: vi.fn() }))
vi.mock('child_process', () => ({ spawn: mockSpawn }))

const ORIG_FETCH = globalThis.fetch
const ORIG_ENV = { ...process.env }

let tmpConfigDir = ''

async function withState(state: { lastCheckedAt: number; lastSeenLatest?: string } | null) {
  const stateFile = path.join(tmpConfigDir, 'last-update-check.json')
  if (state === null) {
    try {
      await fs.unlink(stateFile)
    } catch {
      // ignore
    }
    return
  }
  await fs.mkdir(tmpConfigDir, { recursive: true })
  await fs.writeFile(stateFile, JSON.stringify(state), 'utf8')
}

function makeFetchOk(latest: string) {
  return vi.fn(async () => ({
    ok: true,
    status: 200,
    json: async () => ({ 'dist-tags': { latest } }),
  })) as unknown as typeof fetch
}

function makeFetchFail() {
  return vi.fn(async () => {
    throw new Error('ECONNREFUSED')
  }) as unknown as typeof fetch
}

function makeFetchStatus(status: number) {
  return vi.fn(async () => ({
    ok: false,
    status,
    json: async () => ({}),
  })) as unknown as typeof fetch
}

function makeSpawnSuccess(): ReturnType<typeof vi.fn> {
  return mockSpawn.mockImplementation(() => {
    const handlers: Record<string, ((...args: unknown[]) => void)[]> = {}
    const child = {
      stdout: { on: vi.fn() },
      stderr: { on: vi.fn() },
      on: vi.fn((event: string, cb: (...args: unknown[]) => void) => {
        handlers[event] = handlers[event] || []
        handlers[event].push(cb)
      }),
      kill: vi.fn(),
    }
    // Simulate a clean exit on next tick.
    setImmediate(() => handlers['exit']?.forEach((cb) => cb(0, null)))
    return child
  })
}

async function awaitNextTick() {
  // The background chain is: setImmediate -> readState (async fs) ->
  // fetchLatestVersion (async fetch) -> writeState (async fs mkdir + write) ->
  // spawn. The fs operations involve multiple microtask hops, so flush
  // generously.
  for (let i = 0; i < 50; i++) {
    await new Promise((resolve) => setTimeout(resolve, 0))
  }
}

describe('update-check', () => {
  beforeEach(async () => {
    tmpConfigDir = await fs.mkdtemp(path.join(os.tmpdir(), 'mcp-remote-update-test-'))
    process.env = { ...ORIG_ENV, MCP_REMOTE_CONFIG_DIR: tmpConfigDir }
    delete process.env.MCP_REMOTE_DISABLE_UPDATE_CHECK
    mockSpawn.mockReset()
    vi.resetModules()
  })

  afterEach(async () => {
    globalThis.fetch = ORIG_FETCH
    process.env = { ...ORIG_ENV }
    await fs.rm(tmpConfigDir, { recursive: true, force: true })
  })

  describe('isNewerVersion', () => {
    it('treats wcap suffixes numerically', async () => {
      const { isNewerVersion } = await import('./update-check')
      expect(isNewerVersion('0.1.38-wcap.18', '0.1.38-wcap.17')).toBe(true)
      expect(isNewerVersion('0.1.38-wcap.17', '0.1.38-wcap.17')).toBe(false)
      expect(isNewerVersion('0.1.38-wcap.16', '0.1.38-wcap.17')).toBe(false)
    })

    it('handles patch and minor bumps', async () => {
      const { isNewerVersion } = await import('./update-check')
      expect(isNewerVersion('0.1.39-wcap.1', '0.1.38-wcap.17')).toBe(true)
      expect(isNewerVersion('0.2.0-wcap.1', '0.1.38-wcap.17')).toBe(true)
      expect(isNewerVersion('1.0.0', '0.1.38-wcap.17')).toBe(true)
    })

    it('handles the wcap.10+ vs wcap.9 edge', async () => {
      const { isNewerVersion } = await import('./update-check')
      expect(isNewerVersion('0.1.38-wcap.10', '0.1.38-wcap.9')).toBe(true)
    })
  })

  describe('maybeBackgroundUpdate', () => {
    it('opts out cleanly when MCP_REMOTE_DISABLE_UPDATE_CHECK=1', async () => {
      process.env.MCP_REMOTE_DISABLE_UPDATE_CHECK = '1'
      globalThis.fetch = makeFetchOk('0.1.38-wcap.99')
      makeSpawnSuccess()

      const { maybeBackgroundUpdate } = await import('./update-check')
      maybeBackgroundUpdate('https://npm.example.com/')
      await awaitNextTick()

      expect(globalThis.fetch).not.toHaveBeenCalled()
      expect(mockSpawn).not.toHaveBeenCalled()
    })

    it('does not install when already on the latest version', async () => {
      globalThis.fetch = makeFetchOk(CURRENT_VERSION)
      makeSpawnSuccess()

      const { maybeBackgroundUpdate } = await import('./update-check')
      maybeBackgroundUpdate('https://npm.example.com/')
      await awaitNextTick()

      expect(globalThis.fetch).toHaveBeenCalledTimes(1)
      expect(mockSpawn).not.toHaveBeenCalled()
    })

    it('spawns npm install when a newer version is available', async () => {
      globalThis.fetch = makeFetchOk('0.1.38-wcap.99')
      makeSpawnSuccess()

      const { maybeBackgroundUpdate } = await import('./update-check')
      maybeBackgroundUpdate('https://npm.example.com/')
      await awaitNextTick()

      expect(mockSpawn).toHaveBeenCalledTimes(1)
      const [cmd, args] = mockSpawn.mock.calls[0]
      expect(cmd).toBe('npm')
      expect(args).toEqual([
        'install',
        '-g',
        '@wcap/mcp-remote@0.1.38-wcap.99',
        '--registry',
        'https://npm.example.com/',
      ])
    })

    it('swallows registry network failures without spawning install', async () => {
      globalThis.fetch = makeFetchFail()
      makeSpawnSuccess()

      const { maybeBackgroundUpdate } = await import('./update-check')
      maybeBackgroundUpdate('https://npm.example.com/')
      await awaitNextTick()

      expect(mockSpawn).not.toHaveBeenCalled()
    })

    it('swallows non-2xx registry responses without spawning install', async () => {
      globalThis.fetch = makeFetchStatus(503)
      makeSpawnSuccess()

      const { maybeBackgroundUpdate } = await import('./update-check')
      maybeBackgroundUpdate('https://npm.example.com/')
      await awaitNextTick()

      expect(mockSpawn).not.toHaveBeenCalled()
    })

    it('respects the 24h throttle window', async () => {
      const recent = Date.now() - 60 * 60 * 1000 // 1h ago
      await withState({ lastCheckedAt: recent, lastSeenLatest: CURRENT_VERSION })

      globalThis.fetch = makeFetchOk('0.1.38-wcap.99')
      makeSpawnSuccess()

      const { maybeBackgroundUpdate } = await import('./update-check')
      maybeBackgroundUpdate('https://npm.example.com/')
      await awaitNextTick()

      expect(globalThis.fetch).not.toHaveBeenCalled()
      expect(mockSpawn).not.toHaveBeenCalled()
    })

    it('runs again after the throttle window elapses', async () => {
      const stale = Date.now() - 25 * 60 * 60 * 1000 // 25h ago
      await withState({ lastCheckedAt: stale })

      globalThis.fetch = makeFetchOk('0.1.38-wcap.99')
      makeSpawnSuccess()

      const { maybeBackgroundUpdate } = await import('./update-check')
      maybeBackgroundUpdate('https://npm.example.com/')
      await awaitNextTick()

      expect(globalThis.fetch).toHaveBeenCalledTimes(1)
      expect(mockSpawn).toHaveBeenCalledTimes(1)
    })

    it('persists the throttle timestamp even on registry failure', async () => {
      globalThis.fetch = makeFetchFail()

      const { maybeBackgroundUpdate } = await import('./update-check')
      maybeBackgroundUpdate('https://npm.example.com/')
      await awaitNextTick()

      const stateRaw = await fs.readFile(path.join(tmpConfigDir, 'last-update-check.json'), 'utf8')
      const state = JSON.parse(stateRaw)
      expect(typeof state.lastCheckedAt).toBe('number')
      expect(Math.abs(state.lastCheckedAt - Date.now())).toBeLessThan(5_000)
    })
  })
})
