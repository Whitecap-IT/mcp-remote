import { Transport } from '@modelcontextprotocol/sdk/shared/transport.js'
import { log, debugLog } from './utils'
import { isAuthFailureError } from './auth-errors'

export type ReconnectionState = 'connected' | 'reconnecting' | 'waiting' | 'auth-failed'

export interface ReconnectionConfig {
  initialDelayMs: number
  maxDelayMs: number
  backoffFactor: number
  maxRetriesBeforeWaiting: number
  waitingRetryIntervalMs: number
  maxMessageAgeMs: number
  // After this many consecutive auth-related reconnect failures, give up
  // and transition to the terminal `auth-failed` state. This prevents a
  // silent infinite loop when an admin has truly revoked the user (the
  // refresh_token is invalid, the access_token won't refresh, and we'd
  // otherwise keep retrying every 5 min forever without ever surfacing
  // a clear message). Set to 0 to retry indefinitely.
  maxAuthFailuresBeforeGiveUp: number
}

export const DEFAULT_RECONNECTION_CONFIG: ReconnectionConfig = {
  initialDelayMs: 2000,
  maxDelayMs: 60000,
  backoffFactor: 2,
  maxRetriesBeforeWaiting: 10,
  waitingRetryIntervalMs: 5 * 60 * 1000,
  maxMessageAgeMs: 30 * 1000,
  maxAuthFailuresBeforeGiveUp: 5,
}

type JSONRPCMessage = any

interface QueuedMessage {
  message: JSONRPCMessage
  resolve: () => void
  reject: (error: Error) => void
  queuedAt: number
}

export class ReconnectionManager {
  private state: ReconnectionState = 'connected'
  private config: ReconnectionConfig
  private reconnectFn: () => Promise<Transport>
  private onTransportReplaced: (transport: Transport) => void
  private onMessagePurged?: (message: JSONRPCMessage) => void
  private messageQueue: QueuedMessage[] = []
  private capturedInitMessage: JSONRPCMessage | null = null
  private pendingInitId: string | null = null
  private retryCount = 0
  private consecutiveAuthFailures = 0
  private reconnecting = false
  private transportSwappedListeners: Array<(transport: Transport) => void> = []

  constructor(opts: {
    config?: Partial<ReconnectionConfig>
    reconnectFn: () => Promise<Transport>
    onTransportReplaced: (transport: Transport) => void
    onMessagePurged?: (message: JSONRPCMessage) => void
  }) {
    this.config = { ...DEFAULT_RECONNECTION_CONFIG, ...opts.config }
    this.reconnectFn = opts.reconnectFn
    this.onTransportReplaced = opts.onTransportReplaced
    this.onMessagePurged = opts.onMessagePurged
  }

  getState(): ReconnectionState {
    return this.state
  }

  captureInitialize(message: JSONRPCMessage) {
    this.capturedInitMessage = { ...message }
    debugLog('Captured initialize message for reconnection replay')
  }

  isReconnecting(): boolean {
    return this.state !== 'connected'
  }

  isSyntheticInitResponse(message: JSONRPCMessage): boolean {
    if (this.pendingInitId && message.id === this.pendingInitId) {
      debugLog('Suppressing synthetic init response from being forwarded to client', { id: message.id })
      this.pendingInitId = null
      return true
    }
    return false
  }

  onTransportSwapped(listener: (transport: Transport) => void): void {
    this.transportSwappedListeners.push(listener)
  }

  queueMessage(message: JSONRPCMessage): Promise<void> {
    return new Promise((resolve, reject) => {
      this.messageQueue.push({ message, resolve, reject, queuedAt: Date.now() })
      debugLog('Queued message during reconnection', { method: message.method, id: message.id })
    })
  }

  async triggerReconnection(reason: string): Promise<void> {
    if (this.reconnecting) {
      debugLog('Reconnection already in progress, skipping duplicate trigger')
      return
    }

    this.reconnecting = true
    this.state = 'reconnecting'
    this.retryCount = 0
    log(`Server connection lost (${reason}). Starting reconnection...`)

    try {
      await this.reconnectLoop()
    } catch (error) {
      log(`Unexpected error in reconnection loop: ${error instanceof Error ? error.message : String(error)}`)
      this.reconnecting = false
      this.state = 'waiting'
    }
  }

  private async reconnectLoop(): Promise<void> {
    while (true) {
      this.retryCount++

      let delay: number
      if (this.retryCount <= this.config.maxRetriesBeforeWaiting) {
        delay = Math.min(this.config.initialDelayMs * Math.pow(this.config.backoffFactor, this.retryCount - 1), this.config.maxDelayMs)
        log(`Reconnection attempt ${this.retryCount}/${this.config.maxRetriesBeforeWaiting} in ${delay}ms...`)
      } else {
        if (this.state !== 'waiting') {
          this.state = 'waiting'
          log(`Entering waiting state. Will retry every ${this.config.waitingRetryIntervalMs / 1000}s until server returns.`)
          this.purgeStaleMessages()
        }
        delay = this.config.waitingRetryIntervalMs
        log(`Waiting-state retry #${this.retryCount - this.config.maxRetriesBeforeWaiting} in ${delay / 1000}s...`)
      }

      await this.sleep(delay)

      try {
        const newTransport = await this.reconnectFn()
        log('New transport connected. Re-initializing session...')

        if (this.capturedInitMessage) {
          const initId = `reconnect-init-${Date.now()}`
          this.pendingInitId = initId
          const syntheticInit = {
            ...this.capturedInitMessage,
            id: initId,
          }
          await newTransport.send(syntheticInit)
          debugLog('Sent synthetic initialize on new transport')
        }

        this.state = 'connected'
        this.reconnecting = false
        this.retryCount = 0
        this.consecutiveAuthFailures = 0
        for (const listener of this.transportSwappedListeners) {
          listener(newTransport)
        }
        this.onTransportReplaced(newTransport)
        log('Reconnection successful. Draining queued messages...')
        this.purgeStaleMessages()
        await this.drainQueue(newTransport)
        return
      } catch (error) {
        log(`Reconnection attempt ${this.retryCount} failed: ${error instanceof Error ? error.message : String(error)}`)
        debugLog('Reconnection attempt failed', {
          attempt: this.retryCount,
          error: error instanceof Error ? error.stack : String(error),
        })

        // Track auth-specific failures separately. A 401/403/invalid_grant
        // means the credentials are bad — retrying with the same bad
        // credentials forever just churns silently. After
        // maxAuthFailuresBeforeGiveUp consecutive auth errors, surface a
        // clear terminal message and stop retrying.
        if (isAuthFailureError(error)) {
          this.consecutiveAuthFailures++
          debugLog('Auth-related reconnection failure', {
            consecutiveAuthFailures: this.consecutiveAuthFailures,
            limit: this.config.maxAuthFailuresBeforeGiveUp,
          })
          if (this.config.maxAuthFailuresBeforeGiveUp > 0 && this.consecutiveAuthFailures >= this.config.maxAuthFailuresBeforeGiveUp) {
            this.state = 'auth-failed'
            this.reconnecting = false
            log(
              `Authentication has permanently failed after ${this.consecutiveAuthFailures} attempts. ` +
                `Your access has likely been revoked, or your refresh token expired. ` +
                `To recover: quit Claude Desktop, delete %USERPROFILE%\\.mcp-auth\\ (on Windows) or ~/.mcp-auth/ (on macOS/Linux), and restart Claude Desktop to re-authenticate.`,
            )
            this.purgeStaleMessages()
            return
          }
        } else {
          // Reset on non-auth failure so a single auth blip doesn't poison
          // the counter when intermixed with network blips.
          this.consecutiveAuthFailures = 0
        }
      }
    }
  }

  private purgeStaleMessages(): void {
    const cutoff = Date.now() - this.config.maxMessageAgeMs
    const stale: QueuedMessage[] = []
    const fresh: QueuedMessage[] = []

    for (const item of this.messageQueue) {
      if (item.queuedAt < cutoff) {
        stale.push(item)
      } else {
        fresh.push(item)
      }
    }

    this.messageQueue.length = 0
    this.messageQueue.push(...fresh)

    for (const item of stale) {
      item.resolve()
      if (this.onMessagePurged) {
        this.onMessagePurged(item.message)
      }
    }

    if (stale.length > 0) {
      log(`Purged ${stale.length} stale message(s) from queue`)
    }
  }

  private async drainQueue(transport: Transport): Promise<void> {
    const pending = this.messageQueue.splice(0)
    for (const item of pending) {
      try {
        await transport.send(item.message)
        item.resolve()
        debugLog('Drained queued message', { method: item.message.method, id: item.message.id })
      } catch (error) {
        item.reject(error instanceof Error ? error : new Error(String(error)))
      }
    }
    log(`Drained ${pending.length} queued message(s)`)
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms))
  }
}
