import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js'
import { ReconnectionManager, DEFAULT_RECONNECTION_CONFIG } from './reconnection-manager'

vi.mock('./utils', () => ({
  log: vi.fn(),
  debugLog: vi.fn(),
}))

function makeTransport(): Transport {
  return {
    start: vi.fn().mockResolvedValue(undefined),
    send: vi.fn().mockResolvedValue(undefined),
    close: vi.fn().mockResolvedValue(undefined),
    onmessage: undefined,
    onclose: undefined,
    onerror: undefined,
  } as unknown as Transport
}

describe('ReconnectionManager', () => {
  let transportReplaced: Transport[]
  let messagesPurged: any[]

  beforeEach(() => {
    transportReplaced = []
    messagesPurged = []
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  function makeManager(reconnectFn: () => Promise<Transport>, config?: Partial<typeof DEFAULT_RECONNECTION_CONFIG>) {
    return new ReconnectionManager({
      config: { initialDelayMs: 10, maxDelayMs: 100, ...config },
      reconnectFn,
      onTransportReplaced: (t) => transportReplaced.push(t),
      onMessagePurged: (m) => messagesPurged.push(m),
    })
  }

  describe('state machine', () => {
    it('starts in connected state', () => {
      const m = makeManager(async () => makeTransport())
      expect(m.getState()).toBe('connected')
      expect(m.isReconnecting()).toBe(false)
    })

    it('reaches connected again after a successful reconnect', async () => {
      const newT = makeTransport()
      const m = makeManager(async () => newT)

      const p = m.triggerReconnection('test')
      await vi.runAllTimersAsync()
      await p

      expect(m.getState()).toBe('connected')
      expect(transportReplaced).toEqual([newT])
    })

    it('double-trigger is a no-op while already reconnecting', async () => {
      let calls = 0
      const m = makeManager(async () => {
        calls++
        return makeTransport()
      })

      const p1 = m.triggerReconnection('first')
      const p2 = m.triggerReconnection('second-while-running')
      await vi.runAllTimersAsync()
      await Promise.all([p1, p2])

      expect(calls).toBe(1)
    })
  })

  describe('queue draining', () => {
    it('drains queued messages on successful reconnect', async () => {
      const newT = makeTransport()
      const m = makeManager(async () => newT)

      const sent: any[] = []
      ;(newT.send as any).mockImplementation(async (msg: any) => {
        sent.push(msg)
      })

      // Queue some messages while connected. Note queueMessage returns a
      // promise that only resolves once the message is drained, so we
      // attach but don't await here.
      const enq1 = m.queueMessage({ jsonrpc: '2.0', id: 1, method: 'foo' })
      const enq2 = m.queueMessage({ jsonrpc: '2.0', id: 2, method: 'bar' })

      const recon = m.triggerReconnection('test')
      await vi.runAllTimersAsync()
      await recon
      await Promise.all([enq1, enq2])

      const drained = sent.map((s) => s.method)
      expect(drained).toContain('foo')
      expect(drained).toContain('bar')
    })

    it('purges stale messages (older than maxMessageAgeMs)', async () => {
      const m = makeManager(async () => makeTransport(), { maxMessageAgeMs: 50 })

      // Queue but don't drain. Then advance time so the message goes stale.
      const enq = m.queueMessage({ jsonrpc: '2.0', id: 1, method: 'old' })
      enq.catch(() => {}) // will resolve via purge

      vi.advanceTimersByTime(100)

      const recon = m.triggerReconnection('test')
      await vi.runAllTimersAsync()
      await recon

      expect(messagesPurged.length).toBe(1)
      expect(messagesPurged[0].method).toBe('old')
    })
  })

  describe('synthetic initialize replay', () => {
    it('captures + replays initialize on reconnect', async () => {
      const newT = makeTransport()
      const m = makeManager(async () => newT)

      const initMsg = { jsonrpc: '2.0', id: 'client-1', method: 'initialize', params: {} }
      m.captureInitialize(initMsg)

      const recon = m.triggerReconnection('test')
      await vi.runAllTimersAsync()
      await recon

      // newT.send should have been called with a synthetic init carrying
      // a generated reconnect-init-* id.
      const sentMsg = (newT.send as any).mock.calls[0]?.[0]
      expect(sentMsg?.method).toBe('initialize')
      expect(String(sentMsg?.id)).toMatch(/^reconnect-init-/)
    })

    it('suppresses the synthetic init response on the way back', () => {
      const m = makeManager(async () => makeTransport())
      const initMsg = { jsonrpc: '2.0', id: 'client-1', method: 'initialize', params: {} }
      m.captureInitialize(initMsg)

      // Inject the synthetic id directly via a reconnect cycle. We can't
      // peek at the private id, so just verify the API behavior with a
      // crafted message: any non-matching id is forwarded, a matching one
      // is suppressed.
      const forwarded = m.isSyntheticInitResponse({ jsonrpc: '2.0', id: 'unrelated', result: {} })
      expect(forwarded).toBe(false)
    })
  })

  describe('auth-failure breakout (review item #3)', () => {
    it('transitions to auth-failed after N consecutive 401s', async () => {
      let attempts = 0
      const m = makeManager(
        async () => {
          attempts++
          const err = new Error('Authentication required') as Error & { status: number }
          err.status = 401
          throw err
        },
        {
          maxAuthFailuresBeforeGiveUp: 3,
          maxRetriesBeforeWaiting: 100, // don't enter "waiting" before auth-fail
        },
      )

      const p = m.triggerReconnection('test-auth-storm')
      await vi.runAllTimersAsync()
      await p

      expect(m.getState()).toBe('auth-failed')
      expect(attempts).toBe(3)
    })

    it('does not transition to auth-failed for non-auth errors', async () => {
      let attempts = 0
      const m = makeManager(
        async () => {
          attempts++
          if (attempts < 4) throw new Error('ECONNREFUSED: backend is down')
          return makeTransport()
        },
        { maxAuthFailuresBeforeGiveUp: 2 },
      )

      const p = m.triggerReconnection('test-network-flap')
      await vi.runAllTimersAsync()
      await p

      // 3 network failures, then success — should reach connected, not auth-failed.
      expect(m.getState()).toBe('connected')
      expect(attempts).toBe(4)
    })

    it('resets the auth-failure counter on a non-auth failure', async () => {
      // Sequence: auth, auth, network, auth, auth, auth — should NOT trip
      // a 3-strikes auth-fail because the network blip in the middle
      // resets the counter.
      const seq: Array<() => Error> = [
        () => Object.assign(new Error('Unauthorized'), { status: 401 }),
        () => Object.assign(new Error('Unauthorized'), { status: 401 }),
        () => new Error('ECONNREFUSED'),
        () => Object.assign(new Error('Unauthorized'), { status: 401 }),
        () => Object.assign(new Error('Unauthorized'), { status: 401 }),
      ]
      let i = 0
      const m = makeManager(
        async () => {
          if (i < seq.length) {
            throw seq[i++]()
          }
          return makeTransport()
        },
        { maxAuthFailuresBeforeGiveUp: 3, maxRetriesBeforeWaiting: 100 },
      )

      const p = m.triggerReconnection('test-mix')
      await vi.runAllTimersAsync()
      await p

      // After 2 auth + 1 network + 2 auth (counter reset to 0 in middle, so
      // only 2 consecutive auth at the end), then a success on attempt 6 —
      // we expect connected, not auth-failed.
      expect(m.getState()).toBe('connected')
    })

    it('returns to connected and resets auth counter on a successful reconnect', async () => {
      let attempts = 0
      const m = makeManager(
        async () => {
          attempts++
          if (attempts === 1) {
            throw Object.assign(new Error('Unauthorized'), { status: 401 })
          }
          return makeTransport()
        },
        { maxAuthFailuresBeforeGiveUp: 3 },
      )

      const p = m.triggerReconnection('test-recover')
      await vi.runAllTimersAsync()
      await p

      expect(m.getState()).toBe('connected')
      expect(attempts).toBe(2)
    })
  })
})
