import path from 'path'
import os from 'os'
import fs from 'fs/promises'
import { randomUUID } from 'crypto'
import lockfile from 'proper-lockfile'
import { log, MCP_REMOTE_VERSION } from './utils'

/**
 * MCP Remote Authentication Configuration
 *
 * This module handles the storage and retrieval of authentication-related data for MCP Remote.
 *
 * Configuration directory structure:
 * - The config directory is determined by MCP_REMOTE_CONFIG_DIR env var or defaults to ~/.mcp-auth
 * - Each file is prefixed with a hash of the server URL to separate configurations for different servers
 *
 * Files stored in the config directory:
 * - {server_hash}_client_info.json: Contains OAuth client registration information
 *   - Format: OAuthClientInformation object with client_id and other registration details
 * - {server_hash}_tokens.json: Contains OAuth access and refresh tokens
 *   - Format: OAuthTokens object with access_token, refresh_token, and expiration information
 * - {server_hash}_code_verifier.txt: Contains the PKCE code verifier for the current OAuth flow
 *   - Format: Plain text string used for PKCE verification
 *
 * All JSON files are stored with 2-space indentation for readability.
 */

/**
 * Lockfile data structure
 */
export interface LockfileData {
  pid: number
  port: number
  timestamp: number
}

/**
 * Creates a lockfile for the given server
 * @param serverUrlHash The hash of the server URL
 * @param pid The process ID
 * @param port The port the server is running on
 */
export async function createLockfile(serverUrlHash: string, pid: number, port: number): Promise<void> {
  const lockData: LockfileData = {
    pid,
    port,
    timestamp: Date.now(),
  }
  await writeJsonFile(serverUrlHash, 'lock.json', lockData)
}

/**
 * Checks if a lockfile exists for the given server
 * @param serverUrlHash The hash of the server URL
 * @returns The lockfile data or null if it doesn't exist
 */
export async function checkLockfile(serverUrlHash: string): Promise<LockfileData | null> {
  try {
    const lockfile = await readJsonFile<LockfileData>(serverUrlHash, 'lock.json', {
      async parseAsync(data: any) {
        if (typeof data !== 'object' || data === null) return null
        if (typeof data.pid !== 'number' || typeof data.port !== 'number' || typeof data.timestamp !== 'number') {
          return null
        }
        return data as LockfileData
      },
    })
    return lockfile || null
  } catch {
    return null
  }
}

/**
 * Deletes the lockfile for the given server
 * @param serverUrlHash The hash of the server URL
 */
export async function deleteLockfile(serverUrlHash: string): Promise<void> {
  await deleteConfigFile(serverUrlHash, 'lock.json')
}

/**
 * Gets the configuration directory path
 * @returns The path to the configuration directory
 */
export function getConfigDir(): string {
  const baseConfigDir = process.env.MCP_REMOTE_CONFIG_DIR || path.join(os.homedir(), '.mcp-auth')
  // Add a version subdirectory so we don't need to worry about backwards/forwards compatibility yet
  return path.join(baseConfigDir, `mcp-remote-${MCP_REMOTE_VERSION}`)
}

/**
 * Ensures the configuration directory exists
 */
export async function ensureConfigDir(): Promise<void> {
  try {
    const configDir = getConfigDir()
    await fs.mkdir(configDir, { recursive: true })
  } catch (error) {
    log('Error creating config directory:', error)
    throw error
  }
}

/**
 * Gets the file path for a config file
 * @param serverUrlHash The hash of the server URL
 * @param filename The name of the file
 * @returns The absolute file path
 */
export function getConfigFilePath(serverUrlHash: string, filename: string): string {
  const configDir = getConfigDir()
  return path.join(configDir, `${serverUrlHash}_${filename}`)
}

/**
 * Deletes a config file if it exists
 * @param serverUrlHash The hash of the server URL
 * @param filename The name of the file to delete
 */
export async function deleteConfigFile(serverUrlHash: string, filename: string): Promise<void> {
  try {
    const filePath = getConfigFilePath(serverUrlHash, filename)
    await fs.unlink(filePath)
  } catch (error) {
    // Ignore if file doesn't exist
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
      log(`Error deleting ${filename}:`, error)
    }
  }
}

/**
 * Reads a JSON file and parses it with the provided schema
 * @param serverUrlHash The hash of the server URL
 * @param filename The name of the file to read
 * @param schema The schema to validate against
 * @returns The parsed file content or undefined if the file doesn't exist
 */
export async function readJsonFile<T>(serverUrlHash: string, filename: string, schema: any): Promise<T | undefined> {
  try {
    await ensureConfigDir()

    const filePath = getConfigFilePath(serverUrlHash, filename)
    const content = await fs.readFile(filePath, 'utf-8')
    const result = await schema.parseAsync(JSON.parse(content))
    // console.log({ filename: result })
    return result
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      // console.log(`File ${filename} does not exist`)
      return undefined
    }
    log(`Error reading ${filename}:`, error)
    return undefined
  }
}

/**
 * Acquires a cross-process advisory lock on a config file (or its parent
 * config dir, if the target doesn't exist yet). Used by writeJsonFile to
 * serialize concurrent writers on Windows, where `fs.rename` can fail
 * with EPERM when another process holds an open handle on the target.
 *
 * Returns an `unlock` function. Callers must invoke it in a `finally`
 * block; if the call throws (lock unavailable), no unlock is necessary.
 */
async function acquireConfigLock(filePath: string): Promise<() => Promise<void>> {
  // `proper-lockfile` creates a sibling directory `<filePath>.lock`. If
  // the target file doesn't exist yet (first write), lock the parent
  // config dir instead so we still serialize across writers.
  let lockTarget = filePath
  try {
    await fs.access(filePath)
  } catch {
    // Target doesn't exist; fall back to the parent dir, which is
    // guaranteed to exist because ensureConfigDir() ran before this.
    lockTarget = path.dirname(filePath)
  }
  return lockfile.lock(lockTarget, {
    retries: { retries: 10, factor: 1.5, minTimeout: 50, maxTimeout: 1000 },
    stale: 30_000,
    realpath: false,
  })
}

/**
 * Writes a JSON object to a file atomically using temp file + rename pattern.
 * This prevents race conditions where multiple processes might read partially-written files.
 * The rename operation is atomic on POSIX systems.
 * @param serverUrlHash The hash of the server URL
 * @param filename The name of the file to write
 * @param data The data to write
 */
export async function writeJsonFile(serverUrlHash: string, filename: string, data: any): Promise<void> {
  try {
    await ensureConfigDir()
    const filePath = getConfigFilePath(serverUrlHash, filename)

    // Cross-process advisory lock. On Windows, two mcp-remote subprocesses
    // (which Claude Desktop sometimes spawns) racing each other's
    // fs.rename can produce EPERM. The lock serializes them so each gets
    // a clean atomic write. The lock is short-lived (single write op).
    let unlock: (() => Promise<void>) | null = null
    try {
      unlock = await acquireConfigLock(filePath)
    } catch (lockErr) {
      // If we can't get the lock in time, fall through and try the write
      // anyway. The UUID temp suffix still prevents intra-process races;
      // we'd just be at the mercy of the rename for cross-process. C2's
      // non-fatal save catches any leftover failure.
      log(`Could not acquire lock for ${filename}; proceeding without it:`, lockErr)
    }

    try {
      // Use atomic write pattern: write to a unique temp file, then rename.
      // The suffix uses crypto.randomUUID() rather than `${pid}.${Date.now()}`
      // because two callers in the same Node process can hit this function
      // within the same millisecond (concurrent OAuth flows after an SSE
      // reconnect), and `pid+Date.now()` collides.
      const tempPath = `${filePath}.${randomUUID()}.tmp`

      try {
        // Write to temporary file first
        await fs.writeFile(tempPath, JSON.stringify(data, null, 2), { encoding: 'utf-8', mode: 0o600 })

        // Atomic rename (on POSIX systems; on Windows, may fail with EPERM
        // under contention if a peer holds a handle — the surrounding
        // lock and the saveTokens non-fatal-catch both mitigate that).
        await fs.rename(tempPath, filePath)
      } catch (writeError) {
        // Clean up temp file if it exists
        try {
          await fs.unlink(tempPath)
        } catch {
          // Ignore cleanup errors
        }
        throw writeError
      }
    } finally {
      if (unlock) {
        await unlock().catch(() => {
          // proper-lockfile throws if the lock was compromised; we don't
          // care at this point because we're done writing.
        })
      }
    }
  } catch (error) {
    log(`Error writing ${filename}:`, error)
    throw error
  }
}

/**
 * Reads a text file
 * @param serverUrlHash The hash of the server URL
 * @param filename The name of the file to read
 * @param errorMessage Optional custom error message
 * @returns The file content as a string
 */
export async function readTextFile(serverUrlHash: string, filename: string, errorMessage?: string): Promise<string> {
  try {
    await ensureConfigDir()
    const filePath = getConfigFilePath(serverUrlHash, filename)
    return await fs.readFile(filePath, 'utf-8')
  } catch (error) {
    throw new Error(errorMessage || `Error reading ${filename}`)
  }
}

/**
 * Writes a text string to a file
 * @param serverUrlHash The hash of the server URL
 * @param filename The name of the file to write
 * @param text The text to write
 */
export async function writeTextFile(serverUrlHash: string, filename: string, text: string): Promise<void> {
  try {
    await ensureConfigDir()
    const filePath = getConfigFilePath(serverUrlHash, filename)
    await fs.writeFile(filePath, text, { encoding: 'utf-8', mode: 0o600 })
  } catch (error) {
    log(`Error writing ${filename}:`, error)
    throw error
  }
}
