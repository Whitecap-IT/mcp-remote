import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import fs from 'fs/promises'
import path from 'path'
import os from 'os'
import { writeJsonFile, getConfigFilePath } from './mcp-auth-config'

// utils is imported transitively for log/version constants
vi.mock('./utils', () => ({
  getServerUrlHash: () => 'test-hash',
  log: vi.fn(),
  debugLog: vi.fn(),
  DEBUG: false,
  MCP_REMOTE_VERSION: '1.0.0',
}))

describe('writeJsonFile — race resistance (C1)', () => {
  let tmpDir: string
  let originalConfigDir: string | undefined

  beforeEach(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'mcp-remote-test-'))
    originalConfigDir = process.env.MCP_REMOTE_CONFIG_DIR
    process.env.MCP_REMOTE_CONFIG_DIR = tmpDir
  })

  afterEach(async () => {
    process.env.MCP_REMOTE_CONFIG_DIR = originalConfigDir
    await fs.rm(tmpDir, { recursive: true, force: true })
  })

  it('two concurrent writes from the same process both complete cleanly', async () => {
    // Pre-fix this raced: both callers computed `${pid}.${Date.now()}.tmp` in
    // the same millisecond → same temp path → rename() race → one threw
    // ENOENT/EPERM → saveTokens bubbled the error up → SDK started fresh
    // OAuth → repeat → "SSO storm". Post-fix the temp suffix is UUID-based
    // so the writes are independent.
    const hash = 'race-hash'
    const a = writeJsonFile(hash, 'tokens.json', { who: 'A', n: 1 })
    const b = writeJsonFile(hash, 'tokens.json', { who: 'B', n: 2 })

    await expect(Promise.all([a, b])).resolves.toBeDefined()

    // The final state on disk is one of the two (whichever rename landed
    // second). Either is valid; the only thing that matters is no throw.
    const content = JSON.parse(await fs.readFile(getConfigFilePath(hash, 'tokens.json'), 'utf-8'))
    expect(['A', 'B']).toContain(content.who)
  })

  it('no stale .tmp files are left behind on a successful write burst', async () => {
    const hash = 'cleanup-hash'
    await Promise.all([
      writeJsonFile(hash, 'tokens.json', { i: 1 }),
      writeJsonFile(hash, 'tokens.json', { i: 2 }),
      writeJsonFile(hash, 'tokens.json', { i: 3 }),
      writeJsonFile(hash, 'tokens.json', { i: 4 }),
    ])

    const files = await fs.readdir(tmpDir)
    const tmpLeftovers = files.filter((f) => f.endsWith('.tmp'))
    expect(tmpLeftovers).toEqual([])
  })

  it('tmp file name is unique across rapid sequential calls', async () => {
    // Spy on fs.rename to capture the actual temp paths used.
    const renameSpy = vi.spyOn(fs, 'rename')

    const hash = 'unique-hash'
    await writeJsonFile(hash, 'tokens.json', { v: 1 })
    await writeJsonFile(hash, 'tokens.json', { v: 2 })
    await writeJsonFile(hash, 'tokens.json', { v: 3 })

    const tempPaths = renameSpy.mock.calls.map((c) => c[0] as string)
    expect(new Set(tempPaths).size).toBe(tempPaths.length)

    renameSpy.mockRestore()
  })
})
