import open from 'open'
import { OAuthClientProvider } from '@modelcontextprotocol/sdk/client/auth.js'
import {
  OAuthClientInformationFull,
  OAuthClientInformationFullSchema,
  OAuthTokens,
  OAuthTokensSchema,
} from '@modelcontextprotocol/sdk/shared/auth.js'
import type { OAuthProviderOptions, StaticOAuthClientMetadata } from './types'
import { readJsonFile, writeJsonFile, readTextFile, writeTextFile, deleteConfigFile } from './mcp-auth-config'
import { StaticOAuthClientInformationFull } from './types'
import { log, debugLog, MCP_REMOTE_VERSION } from './utils'
import { sanitizeUrl } from 'strict-url-sanitise'
import { randomUUID } from 'node:crypto'
import { fetchAuthorizationServerMetadata, type AuthorizationServerMetadata } from './authorization-server-metadata'
import type { ProtectedResourceMetadata } from './protected-resource-metadata'

/**
 * Implements the OAuthClientProvider interface for Node.js environments.
 * Handles OAuth flow and token storage for MCP clients.
 */
export class NodeOAuthClientProvider implements OAuthClientProvider {
  private serverUrlHash: string
  private callbackPath: string
  private clientName: string
  private clientUri: string
  private softwareId: string
  private softwareVersion: string
  private staticOAuthClientMetadata: StaticOAuthClientMetadata
  private staticOAuthClientInfo: StaticOAuthClientInformationFull
  private authorizeResource: string | undefined
  private _state: string
  private _clientInfo: OAuthClientInformationFull | undefined
  private authorizationServerMetadata: AuthorizationServerMetadata | undefined
  private protectedResourceMetadata: ProtectedResourceMetadata | undefined
  private wwwAuthenticateScope: string | undefined

  // Single in-flight refresh attempt across concurrent tokens() callers, so a
  // burst of MCP requests near the access_token's expiry doesn't fire N parallel
  // refresh exchanges (which would race + waste OAuth server load + can cause
  // refresh-token-rotation problems with strict providers).
  private refreshPromise: Promise<OAuthTokens | undefined> | null = null

  // Refresh the access_token when it has this many ms left. 60 seconds gives
  // plenty of buffer to round-trip the refresh exchange before the SDK uses it.
  private static readonly REFRESH_BUFFER_MS = 60_000

  /**
   * Creates a new NodeOAuthClientProvider
   * @param options Configuration options for the provider
   */
  constructor(readonly options: OAuthProviderOptions) {
    this.serverUrlHash = options.serverUrlHash
    this.callbackPath = options.callbackPath || '/oauth/callback'
    this.clientName = options.clientName || 'MCP CLI Client'
    this.clientUri = options.clientUri || 'https://github.com/modelcontextprotocol/mcp-cli'
    this.softwareId = options.softwareId || '2e6dc280-f3c3-4e01-99a7-8181dbd1d23d'
    this.softwareVersion = options.softwareVersion || MCP_REMOTE_VERSION
    this.staticOAuthClientMetadata = options.staticOAuthClientMetadata
    this.staticOAuthClientInfo = options.staticOAuthClientInfo
    this.authorizeResource = options.authorizeResource
    this._state = randomUUID()
    this._clientInfo = undefined
    this.authorizationServerMetadata = options.authorizationServerMetadata
    this.protectedResourceMetadata = options.protectedResourceMetadata
    this.wwwAuthenticateScope = options.wwwAuthenticateScope
  }

  get redirectUrl(): string {
    return `http://${this.options.host}:${this.options.callbackPort}${this.callbackPath}`
  }

  get clientMetadata() {
    const effectiveScope = this.getEffectiveScope()
    return {
      redirect_uris: [this.redirectUrl],
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      client_name: this.clientName,
      client_uri: this.clientUri,
      software_id: this.softwareId,
      software_version: this.softwareVersion,
      ...this.staticOAuthClientMetadata,
      scope: effectiveScope,
    }
  }

  state(): string {
    return this._state
  }

  /**
   * Gets the authorization server metadata, fetching it if not already available
   * @returns The authorization server metadata, or undefined if unavailable
   */
  async getAuthorizationServerMetadata(): Promise<AuthorizationServerMetadata | undefined> {
    // Already have metadata? Return it
    debugLog(`authorizationServerMetadata: ${JSON.stringify(this.authorizationServerMetadata)}`)
    if (this.authorizationServerMetadata) {
      return this.authorizationServerMetadata
    }

    // Fetch metadata and cache in memory for this session
    try {
      this.authorizationServerMetadata = await fetchAuthorizationServerMetadata(this.options.serverUrl)
      if (this.authorizationServerMetadata?.scopes_supported) {
        debugLog('Authorization server supports scopes', {
          scopes_supported: this.authorizationServerMetadata.scopes_supported,
        })
      }
      return this.authorizationServerMetadata
    } catch (error) {
      debugLog('Failed to fetch authorization server metadata', error)
      return undefined
    }
  }

  private getEffectiveScope(): string {
    // Priority 1: User-provided scope from staticOAuthClientMetadata (highest priority)
    if (this.staticOAuthClientMetadata?.scope && this.staticOAuthClientMetadata.scope.trim().length > 0) {
      debugLog('Using scope from staticOAuthClientMetadata', { scope: this.staticOAuthClientMetadata.scope })
      return this.staticOAuthClientMetadata.scope
    }

    // Priority 2: Scope from WWW-Authenticate header (per MCP spec)
    if (this.wwwAuthenticateScope && this.wwwAuthenticateScope.trim().length > 0) {
      debugLog('Using scope from WWW-Authenticate header', { scope: this.wwwAuthenticateScope })
      return this.wwwAuthenticateScope
    }

    // Priority 3: Scopes from Protected Resource Metadata (RFC 9728)
    if (this.protectedResourceMetadata?.scopes_supported?.length) {
      const scope = this.protectedResourceMetadata.scopes_supported.join(' ')
      debugLog('Using scopes from Protected Resource Metadata', {
        scopes_supported: this.protectedResourceMetadata.scopes_supported,
        scope,
      })
      return scope
    }

    // Priority 4: Scope from client registration response
    if (this._clientInfo?.scope && this._clientInfo.scope.trim().length > 0) {
      debugLog('Using scope from client registration response', { scope: this._clientInfo.scope })
      return this._clientInfo.scope
    }

    // Priority 5: Use authorization server's supported scopes if available
    if (this.authorizationServerMetadata?.scopes_supported?.length) {
      const scope = this.authorizationServerMetadata.scopes_supported.join(' ')
      debugLog('Using scopes from Authorization Server Metadata', {
        scopes_supported: this.authorizationServerMetadata.scopes_supported,
        scope,
      })
      return scope
    }

    // Priority 6: Fallback to hardcoded default
    debugLog('Using fallback default scope')
    return 'openid email profile'
  }

  /**
   * Gets the client information if it exists
   * @returns The client information or undefined
   */
  async clientInformation(): Promise<OAuthClientInformationFull | undefined> {
    debugLog('Reading client info')
    if (this.staticOAuthClientInfo) {
      debugLog('Returning static client info')
      this._clientInfo = this.staticOAuthClientInfo
      return this.staticOAuthClientInfo
    }
    const clientInfo = await readJsonFile<OAuthClientInformationFull>(
      this.serverUrlHash,
      'client_info.json',
      OAuthClientInformationFullSchema,
    )

    if (clientInfo) {
      this._clientInfo = clientInfo
    }

    debugLog('Client info result:', clientInfo ? 'Found' : 'Not found')
    return clientInfo
  }

  /**
   * Saves client information
   * @param clientInformation The client information to save
   */
  async saveClientInformation(clientInformation: OAuthClientInformationFull): Promise<void> {
    debugLog('Saving client info', { client_id: clientInformation.client_id })
    this._clientInfo = clientInformation
    await writeJsonFile(this.serverUrlHash, 'client_info.json', clientInformation)
  }

  /**
   * Performs a single OAuth refresh_token exchange against the authorization
   * server's token endpoint. Used by `tokens()` for proactive refresh.
   *
   * Returns the new OAuthTokens on success, or undefined if the refresh cannot
   * be attempted (no metadata, no client info, no token endpoint). On HTTP
   * failure (4xx/5xx) this throws so the caller can decide whether to fall
   * back to the stale tokens (5xx, transient) or surface the error (4xx,
   * usually invalid_grant requiring fresh user auth).
   */
  private async performTokenRefresh(refreshToken: string): Promise<OAuthTokens | undefined> {
    const meta = await this.getAuthorizationServerMetadata()
    if (!meta?.token_endpoint) {
      debugLog('Cannot refresh: authorization server metadata has no token_endpoint')
      return undefined
    }

    const clientInfo = await this.clientInformation()
    if (!clientInfo) {
      debugLog('Cannot refresh: client information not yet registered')
      return undefined
    }

    const body = new URLSearchParams()
    body.set('grant_type', 'refresh_token')
    body.set('refresh_token', refreshToken)
    body.set('client_id', clientInfo.client_id)
    if (clientInfo.client_secret) {
      body.set('client_secret', clientInfo.client_secret)
    }

    debugLog('Performing proactive token refresh', { tokenEndpoint: meta.token_endpoint })
    const response = await fetch(meta.token_endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    })

    if (!response.ok) {
      const text = await response.text().catch(() => '')
      // Tag 4xx vs 5xx so the caller can decide how to react.
      const err = new Error(`Token refresh failed: HTTP ${response.status} ${text}`) as Error & {
        status: number
        body: string
      }
      err.status = response.status
      err.body = text
      throw err
    }

    const newTokens = (await response.json()) as OAuthTokens
    log('Access token refreshed proactively (no 401 round-trip needed)')
    return newTokens
  }

  /**
   * Gets the OAuth tokens if they exist.
   *
   * Proactive refresh: when the cached access_token is expired or within
   * REFRESH_BUFFER_MS of expiring AND a refresh_token is present, this method
   * silently performs the refresh exchange before returning. The freshly
   * minted tokens are persisted via saveTokens() and returned in place of the
   * stale ones. Concurrent callers share a single in-flight refresh promise.
   *
   * If the proactive refresh fails (network error, transient 5xx, or 4xx
   * invalid_grant), the original (stale) tokens are returned and the SDK's
   * existing 401-driven re-auth flow takes over. This is intentional: a
   * proactive failure should never make things worse than the previous
   * reactive-only behavior.
   *
   * @returns The OAuth tokens or undefined
   */
  async tokens(): Promise<OAuthTokens | undefined> {
    debugLog('Reading OAuth tokens')
    debugLog('Token request stack trace:', new Error().stack)

    // Read tokens with extended schema that includes expires_at
    const tokens = await readJsonFile<OAuthTokens & { expires_at?: number }>(this.serverUrlHash, 'tokens.json', OAuthTokensSchema)

    if (!tokens) {
      debugLog('Token result: Not found')
      return tokens
    }

    // Calculate actual time left using expires_at if available (preferred),
    // otherwise fall back to expires_in (less accurate - doesn't account for time since save)
    let timeLeftSeconds: number
    let timeLeftMs: number
    let hasAuthoritativeExpiry: boolean

    if (typeof tokens.expires_at === 'number' && tokens.expires_at > 0) {
      timeLeftMs = tokens.expires_at - Date.now()
      timeLeftSeconds = Math.floor(timeLeftMs / 1000)
      hasAuthoritativeExpiry = true
      debugLog('Using expires_at for expiration check', {
        expiresAt: new Date(tokens.expires_at).toISOString(),
        timeLeftSeconds,
      })
    } else {
      // Fall back to expires_in (legacy behavior - may be inaccurate)
      timeLeftSeconds = tokens.expires_in || 0
      timeLeftMs = timeLeftSeconds * 1000
      hasAuthoritativeExpiry = false
      debugLog('⚠️ Using legacy expires_in (may be inaccurate)', {
        expiresIn: tokens.expires_in,
      })
    }

    const isExpired = timeLeftSeconds <= 0

    // Alert if expires_in is invalid
    if (typeof tokens.expires_in !== 'number' || tokens.expires_in < 0) {
      debugLog('⚠️ WARNING: Invalid expires_in detected while reading tokens ⚠️', {
        expiresIn: tokens.expires_in,
        tokenObject: JSON.stringify(tokens),
        stack: new Error('Invalid expires_in value').stack,
      })
    }

    debugLog('Token result:', {
      found: true,
      hasAccessToken: !!tokens.access_token,
      hasRefreshToken: !!tokens.refresh_token,
      expiresIn: `${timeLeftSeconds} seconds`,
      isExpired,
      expiresInValue: tokens.expires_in,
      expiresAtValue: tokens.expires_at,
    })

    // Proactive refresh: only attempt when we trust the expiry (authoritative
    // expires_at) and have a refresh_token. We refresh when the token is
    // already expired OR will expire within REFRESH_BUFFER_MS.
    const shouldProactivelyRefresh =
      hasAuthoritativeExpiry &&
      !!tokens.refresh_token &&
      timeLeftMs < NodeOAuthClientProvider.REFRESH_BUFFER_MS

    if (!shouldProactivelyRefresh) {
      return tokens
    }

    // Coalesce concurrent refresh attempts so multiple in-flight tokens()
    // callers share a single network round-trip.
    if (!this.refreshPromise) {
      const refreshTokenValue = tokens.refresh_token!
      this.refreshPromise = (async () => {
        try {
          const newTokens = await this.performTokenRefresh(refreshTokenValue)
          if (newTokens) {
            await this.saveTokens(newTokens)
          }
          return newTokens
        } finally {
          // Allow subsequent near-expiry windows to trigger a fresh refresh.
          this.refreshPromise = null
        }
      })()
    }

    try {
      const refreshed = await this.refreshPromise
      if (refreshed) {
        // saveTokens() writes both expires_in and a freshly computed expires_at.
        // Re-read so the caller sees the persisted form (with expires_at) rather
        // than the raw token-endpoint response (which only has expires_in).
        const persisted = await readJsonFile<OAuthTokens & { expires_at?: number }>(
          this.serverUrlHash,
          'tokens.json',
          OAuthTokensSchema,
        )
        return persisted ?? refreshed
      }
      // Refresh skipped (no metadata / no client info) - return stale tokens.
      return tokens
    } catch (err) {
      // Refresh failed. Fall back to returning the stale tokens so the SDK's
      // existing 401 -> re-auth path can run. This preserves the prior
      // (reactive-only) behavior as a safety net.
      const status = (err as Error & { status?: number }).status
      log(
        `Proactive token refresh failed (status=${status ?? 'n/a'}); falling back to existing tokens. SDK will trigger re-auth on next 401.`,
      )
      debugLog('Proactive refresh error', err)
      return tokens
    }
  }

  /**
   * Saves OAuth tokens
   * @param tokens The tokens to save
   */
  async saveTokens(tokens: OAuthTokens): Promise<void> {
    const timeLeft = tokens.expires_in || 0

    // Alert if expires_in is invalid
    if (typeof tokens.expires_in !== 'number' || tokens.expires_in < 0) {
      debugLog('⚠️ WARNING: Invalid expires_in detected in tokens ⚠️', {
        expiresIn: tokens.expires_in,
        tokenObject: JSON.stringify(tokens),
        stack: new Error('Invalid expires_in value').stack,
      })
    }

    // Calculate and store absolute expiration timestamp for accurate expiration checks later
    // This prevents the issue where expires_in becomes stale when read from disk
    const expiresAt = typeof tokens.expires_in === 'number' && tokens.expires_in > 0 ? Date.now() + tokens.expires_in * 1000 : undefined

    debugLog('Saving tokens', {
      hasAccessToken: !!tokens.access_token,
      hasRefreshToken: !!tokens.refresh_token,
      expiresIn: `${timeLeft} seconds`,
      expiresInValue: tokens.expires_in,
      expiresAt: expiresAt ? new Date(expiresAt).toISOString() : undefined,
    })

    // Store tokens with additional expires_at field for accurate expiration tracking
    const tokensWithExpiry = {
      ...tokens,
      ...(expiresAt ? { expires_at: expiresAt } : {}),
    }

    await writeJsonFile(this.serverUrlHash, 'tokens.json', tokensWithExpiry)
  }

  /**
   * Redirects the user to the authorization URL
   * @param authorizationUrl The URL to redirect to
   */
  async redirectToAuthorization(authorizationUrl: URL): Promise<void> {
    // Optionally fetch metadata for debugging/informational purposes (non-blocking)
    this.getAuthorizationServerMetadata().catch(() => {
      // Ignore errors, metadata is optional
    })

    if (this.authorizeResource) {
      authorizationUrl.searchParams.set('resource', this.authorizeResource)
    }

    const effectiveScope = this.getEffectiveScope()
    authorizationUrl.searchParams.set('scope', effectiveScope)
    debugLog('Added scope parameter to authorization URL', { scopes: effectiveScope })

    log(`\nPlease authorize this client by visiting:\n${authorizationUrl.toString()}\n`)

    debugLog('Redirecting to authorization URL', authorizationUrl.toString())

    try {
      await open(sanitizeUrl(authorizationUrl.toString()))
      log('Browser opened automatically.')
    } catch (error) {
      log('Could not open browser automatically. Please copy and paste the URL above into your browser.')
      debugLog('Failed to open browser', error)
    }
  }

  /**
   * Saves the PKCE code verifier
   * @param codeVerifier The code verifier to save
   */
  async saveCodeVerifier(codeVerifier: string): Promise<void> {
    debugLog('Saving code verifier')
    await writeTextFile(this.serverUrlHash, 'code_verifier.txt', codeVerifier)
  }

  /**
   * Gets the PKCE code verifier
   * @returns The code verifier
   */
  async codeVerifier(): Promise<string> {
    debugLog('Reading code verifier')
    const verifier = await readTextFile(this.serverUrlHash, 'code_verifier.txt', 'No code verifier saved for session')
    debugLog('Code verifier found:', !!verifier)
    return verifier
  }

  /**
   * Invalidates the specified credentials
   * @param scope The scope of credentials to invalidate
   */
  async invalidateCredentials(scope: 'all' | 'client' | 'tokens' | 'verifier'): Promise<void> {
    debugLog(`Invalidating credentials: ${scope}`)

    switch (scope) {
      case 'all':
        await Promise.all([
          deleteConfigFile(this.serverUrlHash, 'client_info.json'),
          deleteConfigFile(this.serverUrlHash, 'tokens.json'),
          deleteConfigFile(this.serverUrlHash, 'code_verifier.txt'),
        ])
        this._clientInfo = undefined
        debugLog('All credentials invalidated')
        break

      case 'client':
        await deleteConfigFile(this.serverUrlHash, 'client_info.json')
        this._clientInfo = undefined
        debugLog('Client information invalidated')
        break

      case 'tokens':
        await deleteConfigFile(this.serverUrlHash, 'tokens.json')
        debugLog('OAuth tokens invalidated')
        break

      case 'verifier':
        await deleteConfigFile(this.serverUrlHash, 'code_verifier.txt')
        debugLog('Code verifier invalidated')
        break

      default:
        throw new Error(`Unknown credential scope: ${scope}`)
    }
  }
}
