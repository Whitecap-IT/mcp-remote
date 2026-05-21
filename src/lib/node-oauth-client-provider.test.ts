import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { NodeOAuthClientProvider } from './node-oauth-client-provider'
import * as mcpAuthConfig from './mcp-auth-config'
import type { OAuthProviderOptions } from './types'
import type { AuthorizationServerMetadata } from './authorization-server-metadata'

vi.mock('./mcp-auth-config')
vi.mock('./authorization-server-metadata', () => ({
  fetchAuthorizationServerMetadata: vi.fn().mockResolvedValue(undefined),
}))
vi.mock('./utils', () => ({
  getServerUrlHash: () => 'test-hash',
  log: vi.fn(),
  debugLog: vi.fn(),
  DEBUG: false,
  MCP_REMOTE_VERSION: '1.0.0',
}))
vi.mock('open', () => ({ default: vi.fn() }))

describe('NodeOAuthClientProvider - OAuth Scope Handling', () => {
  let provider: NodeOAuthClientProvider
  let mockReadJsonFile: any
  let mockWriteJsonFile: any
  let mockDeleteConfigFile: any
  let mockWriteTextFile: any

  const defaultOptions: OAuthProviderOptions = {
    serverUrl: 'https://example.com',
    callbackPort: 8080,
    host: 'localhost',
    serverUrlHash: 'test-hash',
  }

  beforeEach(() => {
    mockReadJsonFile = vi.mocked(mcpAuthConfig.readJsonFile)
    mockWriteJsonFile = vi.mocked(mcpAuthConfig.writeJsonFile)
    mockDeleteConfigFile = vi.mocked(mcpAuthConfig.deleteConfigFile)
    mockWriteTextFile = vi.mocked(mcpAuthConfig.writeTextFile)

    mockReadJsonFile.mockResolvedValue(undefined)
    mockWriteJsonFile.mockResolvedValue(undefined)
    mockDeleteConfigFile.mockResolvedValue(undefined)
    mockWriteTextFile.mockResolvedValue(undefined)
  })

  afterEach(() => {
    vi.clearAllMocks()
    vi.unstubAllGlobals()
  })

  describe('scope priority', () => {
    it('should prioritize custom scope from staticOAuthClientMetadata', () => {
      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'custom read write',
        } as any,
      })

      const metadata = provider.clientMetadata
      expect(metadata.scope).toBe('custom read write')
    })

    it('should use scope from registration response', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      const clientInfo = {
        client_id: 'test-client',
        redirect_uris: ['http://localhost:8080/oauth/callback'],
        scope: 'openid email profile read:user',
      }

      await provider.saveClientInformation(clientInfo)
      await provider.clientInformation()

      const metadata = provider.clientMetadata
      expect(metadata.scope).toBe('openid email profile read:user')
    })

    it('should fallback to default scopes when none provided', () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      const metadata = provider.clientMetadata
      expect(metadata.scope).toBe('openid email profile')
    })
  })

  describe('authorization URL', () => {
    it('should include scope parameter in authorization URL', async () => {
      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'github read:user',
        } as any,
      })

      const authUrl = new URL('https://auth.example.com/authorize')
      await provider.redirectToAuthorization(authUrl)

      expect(authUrl.searchParams.get('scope')).toBe('github read:user')
    })

    it('should include default scope in authorization URL when none specified', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      const authUrl = new URL('https://auth.example.com/authorize')
      await provider.redirectToAuthorization(authUrl)

      expect(authUrl.searchParams.get('scope')).toBe('openid email profile')
    })
  })

  describe('backward compatibility', () => {
    it('should preserve existing custom scope behavior', () => {
      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'user:email repo',
          client_name: 'My Custom Client',
        } as any,
      })

      const metadata = provider.clientMetadata

      expect(metadata).toMatchObject({
        scope: 'user:email repo',
        client_name: 'My Custom Client',
        redirect_uris: ['http://localhost:8080/oauth/callback'],
        token_endpoint_auth_method: 'none',
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        software_id: '2e6dc280-f3c3-4e01-99a7-8181dbd1d23d',
        software_version: '1.0.0',
      })
    })
  })

  describe('credential invalidation', () => {
    it('should reset to default scopes after client invalidation', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      const clientInfo = {
        client_id: 'test-client',
        redirect_uris: ['http://localhost:8080/oauth/callback'],
        scope: 'extracted custom scopes',
      }

      mockReadJsonFile.mockResolvedValueOnce(clientInfo)
      await provider.clientInformation()
      expect(provider.clientMetadata.scope).toBe('extracted custom scopes')

      await provider.invalidateCredentials('client')

      expect(provider.clientMetadata.scope).toBe('openid email profile')
      expect(mockDeleteConfigFile).toHaveBeenCalledWith('test-hash', 'client_info.json')
    })

    it('should not delete client info when invalidating only tokens', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      await provider.invalidateCredentials('tokens')

      expect(mockDeleteConfigFile).toHaveBeenCalledWith('test-hash', 'tokens.json')
      expect(mockDeleteConfigFile).not.toHaveBeenCalledWith('test-hash', 'client_info.json')
    })
  })

  describe('scopes_supported parsing', () => {
    it('should use custom scopes without filtering', () => {
      const metadata: AuthorizationServerMetadata = {
        issuer: 'https://example.com',
        scopes_supported: ['openid', 'email', 'profile'],
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'openid email profile custom:read custom:write',
        } as any,
        authorizationServerMetadata: metadata,
      })

      const clientMetadata = provider.clientMetadata
      // Should use all requested scopes without filtering
      expect(clientMetadata.scope).toBe('openid email profile custom:read custom:write')
    })

    it('should use requested scopes regardless of scopes_supported', () => {
      const metadata: AuthorizationServerMetadata = {
        issuer: 'https://example.com',
        scopes_supported: ['some', 'other', 'scopes'],
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'custom:read custom:write',
        } as any,
        authorizationServerMetadata: metadata,
      })

      const clientMetadata = provider.clientMetadata
      // Should use requested scopes even if not in scopes_supported
      expect(clientMetadata.scope).toBe('custom:read custom:write')
    })

    it('should use scopes when scopes_supported is missing', () => {
      const metadata: AuthorizationServerMetadata = {
        issuer: 'https://example.com',
        // No scopes_supported
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'custom:read custom:write special:scope',
        } as any,
        authorizationServerMetadata: metadata,
      })

      const clientMetadata = provider.clientMetadata
      expect(clientMetadata.scope).toBe('custom:read custom:write special:scope')
    })

    it('should use scopes when scopes_supported is empty', () => {
      const metadata: AuthorizationServerMetadata = {
        issuer: 'https://example.com',
        scopes_supported: [],
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'custom:read custom:write',
        } as any,
        authorizationServerMetadata: metadata,
      })

      const clientMetadata = provider.clientMetadata
      expect(clientMetadata.scope).toBe('custom:read custom:write')
    })

    it('should use scopes when no metadata is provided', () => {
      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'custom:read custom:write',
        } as any,
      })

      const clientMetadata = provider.clientMetadata
      expect(clientMetadata.scope).toBe('custom:read custom:write')
    })

    it('should use scopes from client registration response', async () => {
      const metadata: AuthorizationServerMetadata = {
        issuer: 'https://example.com',
        scopes_supported: ['openid', 'email'],
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        authorizationServerMetadata: metadata,
      })

      const clientInfo = {
        client_id: 'test-client',
        redirect_uris: ['http://localhost:8080/oauth/callback'],
        scope: 'openid email profile custom:read',
      }

      await provider.saveClientInformation(clientInfo)
      await provider.clientInformation()

      const clientMetadata = provider.clientMetadata
      // Should use all scopes from registration response
      expect(clientMetadata.scope).toBe('openid email profile custom:read')
    })

    it('should use scopes_supported when no user or client scopes provided', () => {
      const metadata: AuthorizationServerMetadata = {
        issuer: 'https://example.com',
        scopes_supported: ['openid', 'email'],
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        authorizationServerMetadata: metadata,
      })

      const clientMetadata = provider.clientMetadata
      // Should use scopes_supported when nothing else is provided
      expect(clientMetadata.scope).toBe('openid email')
    })

    it('should treat empty scope string as no scope and use default', () => {
      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: '',
        } as any,
      })

      const clientMetadata = provider.clientMetadata
      // Empty scope should fallback to default
      expect(clientMetadata.scope).toBe('openid email profile')
    })
  })

  describe('storm resistance (C1/C2/C5)', () => {
    it('returns the same state while an OAuth attempt is active, rotates after saveTokens', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      // Parallel reconnect paths both reach state() before the attempt
      // completes - they MUST get the same value (single-flight gate),
      // otherwise the verifier-overwrite race causes "Code not valid".
      const firstState = provider.state()
      const secondState = provider.state()
      expect(secondState).toBe(firstState)
      expect(provider.currentState()).toBe(firstState)

      // saveTokens completes the attempt; the gate is released.
      await provider.saveTokens({
        access_token: 'at',
        token_type: 'Bearer',
        refresh_token: 'rt',
        expires_in: 3600,
      })

      const thirdState = provider.state()
      expect(thirdState).not.toBe(firstState)
    })

    it('saveTokens does not throw when disk write fails', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)
      mockWriteJsonFile.mockRejectedValueOnce(new Error('EPERM: rename failed'))

      // Should resolve successfully — the in-memory tokens are valid even
      // if persistence failed. Pre-fix this would throw and trigger the
      // SDK's fresh-OAuth cascade.
      await expect(
        provider.saveTokens({
          access_token: 'at-1',
          token_type: 'Bearer',
          refresh_token: 'rt-1',
          expires_in: 7200,
        }),
      ).resolves.toBeUndefined()
    })

    it('tokens() returns the in-memory copy if it is fresher than disk', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      // Disk has an old token; simulate the case where the most recent
      // saveTokens persisted to memory but failed to flush to disk.
      const oldExpiresAt = Date.now() - 60_000 // already expired
      const newExpiresAt = Date.now() + 7_200_000 // 2h from now
      mockReadJsonFile.mockResolvedValue({
        access_token: 'old',
        token_type: 'Bearer',
        refresh_token: 'rt-old',
        expires_in: 7200,
        expires_at: oldExpiresAt,
      })

      // Make disk write fail so the in-memory cache is the only fresh copy.
      mockWriteJsonFile.mockRejectedValueOnce(new Error('EPERM'))
      await provider.saveTokens({
        access_token: 'new',
        token_type: 'Bearer',
        refresh_token: 'rt-new',
        expires_in: 7200,
      })

      const got = await provider.tokens()
      expect(got?.access_token).toBe('new')
    })

    it('tokens() clears cached tokens when proactive refresh gets invalid_grant', async () => {
      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientInfo: {
          client_id: 'mcp-platform-prod',
          redirect_uris: ['http://localhost:8080/oauth/callback'],
        } as any,
        authorizationServerMetadata: {
          issuer: 'https://idp.example.com',
          authorization_endpoint: 'https://idp.example.com/auth',
          token_endpoint: 'https://idp.example.com/token',
          response_types_supported: ['code'],
        } as any,
      })

      mockReadJsonFile.mockResolvedValue({
        access_token: 'expired-access-token',
        token_type: 'Bearer',
        refresh_token: 'stale-refresh-token',
        expires_in: 3600,
        expires_at: Date.now() - 1_000,
      })

      vi.stubGlobal(
        'fetch',
        vi.fn().mockResolvedValue(
          new Response(
            JSON.stringify({
              error: 'invalid_grant',
              error_description: "Session doesn't have required client",
            }),
            { status: 400 },
          ),
        ),
      )

      const got = await provider.tokens()

      expect(got).toBeUndefined()
      expect(mockDeleteConfigFile).toHaveBeenCalledWith('test-hash', 'tokens.json')
    })

    it('redirectToAuthorization suppresses a duplicate attempt whose code_challenge does not match the active verifier', async () => {
      const openMod = await import('open')
      const openMock = vi.mocked(openMod.default)
      openMock.mockClear()

      provider = new NodeOAuthClientProvider(defaultOptions)

      // Simulate the SDK's normal flow for attempt A: state -> verifier.
      provider.state()
      await provider.saveCodeVerifier('verifier-A-1234567890abcdef')

      // Two URLs arrive at redirectToAuthorization. The first carries the
      // legitimate challenge derived from verifier-A; the second comes from
      // a parallel SDK path that computed a different challenge before the
      // gate's first-writer-wins serialized it.
      const { createHash } = await import('node:crypto')
      const challengeA = createHash('sha256').update('verifier-A-1234567890abcdef').digest('base64url')
      const challengeB = createHash('sha256').update('verifier-B-fedcba0987654321').digest('base64url')

      const urlA = new URL('https://idp.example.com/auth')
      urlA.searchParams.set('code_challenge', challengeA)
      const urlB = new URL('https://idp.example.com/auth')
      urlB.searchParams.set('code_challenge', challengeB)

      await provider.redirectToAuthorization(urlA)
      await provider.redirectToAuthorization(urlB)
      await provider.redirectToAuthorization(urlB)

      // Only the URL matching the active verifier's challenge opens a tab.
      expect(openMock).toHaveBeenCalledTimes(1)
    })

    it('saveCodeVerifier is first-writer-wins within an active attempt', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)
      provider.state()

      const verifierA = 'verifier-A-1234567890abcdef'
      const verifierB = 'verifier-B-fedcba0987654321'

      await provider.saveCodeVerifier(verifierA)
      await provider.saveCodeVerifier(verifierB)

      // Only the first writer's verifier reaches disk.
      const calls = mockWriteTextFile.mock.calls.filter((c: unknown[]) => c[1] === 'code_verifier.txt')
      expect(calls).toHaveLength(1)
      expect(calls[0][2]).toBe(verifierA)
    })

    it('gate stays held between callback and saveTokens to prevent verifier overwrite', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      // Simulate the SDK's normal flow up to receiving the auth code:
      // state -> save verifier -> open tab -> (user completes) -> callback
      // fires -> finishAuth runs. The gate must NOT release on callback
      // receipt because the token exchange still needs to read the verifier.
      const firstState = provider.state()
      await provider.saveCodeVerifier('verifier-A-1234567890abcdef')

      // Pretend the callback has fired and the application is now in the
      // window between callback receipt and saveTokens. A racing reconnect
      // path arrives and calls state() + saveCodeVerifier(). It MUST NOT
      // be allowed to rotate state or overwrite the verifier.
      const racingState = provider.state()
      expect(racingState).toBe(firstState)

      await provider.saveCodeVerifier('verifier-B-fedcba0987654321')
      const calls = mockWriteTextFile.mock.calls.filter((c: unknown[]) => c[1] === 'code_verifier.txt')
      expect(calls).toHaveLength(1)
      expect(calls[0][2]).toBe('verifier-A-1234567890abcdef')

      // Token exchange succeeds; saveTokens releases the gate.
      await provider.saveTokens({
        access_token: 'at',
        token_type: 'Bearer',
        refresh_token: 'rt',
        expires_in: 3600,
      })

      // After release, the next attempt rotates.
      const nextState = provider.state()
      expect(nextState).not.toBe(firstState)
    })

    it('TTL expiry releases the gate so a new attempt can start', async () => {
      vi.useFakeTimers()
      try {
        provider = new NodeOAuthClientProvider(defaultOptions)
        const firstState = provider.state()

        // Advance past the 5-minute TTL without ever calling saveTokens.
        vi.advanceTimersByTime(5 * 60 * 1000 + 1)

        const secondState = provider.state()
        expect(secondState).not.toBe(firstState)
      } finally {
        vi.useRealTimers()
      }
    })

    it('invalid_grant backoff suppresses new browser opens during the window', async () => {
      const openMod = await import('open')
      const openMock = vi.mocked(openMod.default)
      openMock.mockClear()

      provider = new NodeOAuthClientProvider(defaultOptions)
      provider.state()
      await provider.saveCodeVerifier('verifier-X-1234567890abcdef')

      const { createHash } = await import('node:crypto')
      const challenge = createHash('sha256').update('verifier-X-1234567890abcdef').digest('base64url')

      // Simulate the proxy recording an invalid_grant after a failed token
      // exchange. The next redirectToAuthorization must be suppressed.
      provider.recordInvalidGrant()

      const url = new URL('https://idp.example.com/auth')
      url.searchParams.set('code_challenge', challenge)
      await provider.redirectToAuthorization(url)

      expect(openMock).toHaveBeenCalledTimes(0)
    })

    it('redirectToAuthorization suppresses entirely if tokens were saved recently', async () => {
      const openMod = await import('open')
      const openMock = vi.mocked(openMod.default)
      openMock.mockClear()

      provider = new NodeOAuthClientProvider(defaultOptions)
      const url = new URL('https://idp.example.com/auth?x=1')

      // Simulate a successful token refresh that just landed. The SDK now
      // reaches the auth path due to a transient error (e.g. a 401 from
      // an upstream that lost in-memory session state). We must not open
      // a browser — our tokens are valid.
      await provider.saveTokens({
        access_token: 'at-fresh',
        token_type: 'Bearer',
        refresh_token: 'rt-fresh',
        expires_in: 7200,
      })

      await provider.redirectToAuthorization(url)
      await provider.redirectToAuthorization(url)

      // Zero browser tabs — the "tokens just saved" guard catches everything.
      expect(openMock).toHaveBeenCalledTimes(0)
    })
  })
})
