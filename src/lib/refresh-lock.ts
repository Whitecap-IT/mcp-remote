import fs from 'fs/promises'
import lockfile from 'proper-lockfile'
import { ensureConfigDir, getConfigFilePath } from './mcp-auth-config'
import { debugLog } from './utils'

const REFRESH_LOCK_STALE_MS = 30_000

export async function withRefreshLock<T>(serverUrlHash: string, fn: () => Promise<T>): Promise<T> {
  await ensureConfigDir()
  const lockTarget = getConfigFilePath(serverUrlHash, 'tokens.refresh.lock')

  const handle = await fs.open(lockTarget, 'a', 0o600)
  await handle.close()

  let release: (() => Promise<void>) | null = null
  try {
    release = await lockfile.lock(lockTarget, {
      retries: { retries: 30, factor: 1.2, minTimeout: 100, maxTimeout: 1000 },
      stale: REFRESH_LOCK_STALE_MS,
      realpath: false,
    })
    debugLog('Acquired cross-process refresh lock')
    return await fn()
  } finally {
    if (release) {
      await release().catch((error) => debugLog('Failed to release refresh lock', error))
      debugLog('Released cross-process refresh lock')
    }
  }
}
