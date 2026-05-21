import open from 'open'
import { z } from 'zod'
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
import { createHash, randomUUID } from 'node:crypto'
import { fetchAuthorizationServerMetadata, type AuthorizationServerMetadata } from './authorization-server-metadata'
import type { ProtectedResourceMetadata } from './protected-resource-metadata'
import { isInvalidGrantError } from './auth-errors'

// Extend the SDK's OAuthTokensSchema with `expires_at` — the absolute
// expiration timestamp that saveTokens() writes. The SDK's schema uses
// `.strip()` so any unknown keys are silently dropped on read; without
// this extension, tokens() falls through to the legacy `expires_in`
// branch even though we persisted `expires_at`. That bug made the
// proactive-refresh path effectively unreachable across process restarts.
const StoredOAuthTokensSchema = OAuthTokensSchema.extend({
  expires_at: z.number().optional(),
})
type StoredOAuthTokens = z.infer<typeof StoredOAuthTokensSchema>

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

  // Hot cache of the most recently issued tokens. Used as a fallback when
  // disk persistence fails (Windows file locks, antivirus, cross-process
  // races) so we can keep operating with valid in-memory tokens instead of
  // throwing back to the SDK and triggering a fresh OAuth flow. Includes the
  // computed expires_at so tokens() can decide whether to refresh.
  private inMemoryTokens: StoredOAuthTokens | null = null

  // Single-flight authorization gate. The MCP SDK's auth path is:
  //
  //   state() -> generate verifier+challenge -> saveCodeVerifier() ->
  //   redirectToAuthorization() -> callback receives code ->
  //   finishAuth(code) -> saveTokens()
  //
  // When the SDK's own SSE-reconnect loop AND our ReconnectionManager both
  // hit auth at roughly the same moment, two parallel passes through this
  // chain race each other. The visible symptom is many browser tabs opening.
  // The subtler bug is verifier corruption: pass A computes verifier-A and
  // writes it to disk, then pass B overwrites with verifier-B, then pass A's
  // browser tab returns a code that was minted for challenge-A, but the
  // verifier on disk is now verifier-B. Token exchange returns
  // "Code not valid".
  //
  // Fix: a single in-flight attempt across the whole chain. The gate is
  // established at the FIRST mutation point (state()) and released only
  // AFTER saveTokens() has persisted new tokens. During the window between,
  // duplicate callers get the active attempt's state echoed back, cannot
  // overwrite the verifier, and cannot trigger new browser tabs.
  private static readonly ACTIVE_AUTH_TTL_MS = 5 * 60 * 1000
  private activeAuthAttempt: {
    state: string
    codeVerifier: string | null
    codeChallenge: string | null
    startedAt: number
  } | null = null

  // Backoff window after an invalid_grant terminal rejection. While set,
  // redirectToAuthorization() and tokens() refuse to start a new attempt -
  // gives the user breathing room and prevents the proxy from churning
  // through OAuth round trips against an IdP that is currently saying "no".
  private invalidGrantBackoffUntil = 0
  private consecutiveInvalidGrants = 0
  private static readonly INVALID_GRANT_BACKOFF_BASE_MS = 2_000
  private static readonly INVALID_GRANT_BACKOFF_CAP_MS = 60_000
  private static readonly INVALID_GRANT_TERMINAL_THRESHOLD = 3

  // Timestamp of the most recent successful saveTokens() call. If we just
  // got fresh tokens (either via OAuth flow or refresh_token exchange), any
  // subsequent "must authenticate" signal in the next AUTH_RECENT_WINDOW_MS
  // is treated as a transient bug rather than a real auth failure. The SDK
  // sometimes calls into the auth path on transient errors (e.g. a 401 from
  // an upstream that just lost in-memory session state) — suppressing a
  // browser tab in that window prevents the visible storm. The user's
  // tokens are valid; the SDK can retry with the existing Bearer header.
  private static readonly AUTH_RECENT_WINDOW_MS = 60_000
  private lastSuccessfulSaveAt = 0

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

  // First call into the OAuth flow during an auth attempt. The single-flight
  // gate lives here because state() is the EARLIEST mutation point: rotating
  // state without coordinating saveCodeVerifier() leaves a window where two
  // racing reconnect paths can swap each other's PKCE material and produce
  // "Code not valid" even with only one tab open. Behavior:
  //
  //   - No active attempt (or active attempt past its TTL): start a new
  //     attempt with a fresh state.
  //   - Active attempt: return the same state. The caller participates in
  //     the in-flight attempt instead of starting its own.
  //
  // currentState() exposes the active state without rotating; used by the
  // callback server to validate `state=` on the OAuth redirect.
  state(): string {
    this.purgeExpiredAttempt()
    if (!this.activeAuthAttempt) {
      this.activeAuthAttempt = {
        state: randomUUID(),
        codeVerifier: null,
        codeChallenge: null,
        startedAt: Date.now(),
      }
      this._state = this.activeAuthAttempt.state
      debugLog('OAuth attempt started', { state: this._state })
    } else {
      debugLog('OAuth attempt already active; reusing state', {
        state: this.activeAuthAttempt.state,
        ageMs: Date.now() - this.activeAuthAttempt.startedAt,
      })
    }
    return this._state
  }

  currentState(): string {
    return this._state
  }

  private purgeExpiredAttempt(): void {
    if (!this.activeAuthAttempt) return
    const age = Date.now() - this.activeAuthAttempt.startedAt
    if (age > NodeOAuthClientProvider.ACTIVE_AUTH_TTL_MS) {
      debugLog('Active OAuth attempt expired; releasing gate', { ageMs: age })
      this.activeAuthAttempt = null
    }
  }

  private releaseAuthAttempt(reason: string): void {
    if (!this.activeAuthAttempt) return
    debugLog('Releasing OAuth attempt', { state: this.activeAuthAttempt.state, reason })
    this.activeAuthAttempt = null
  }

  private static pkceChallengeForVerifier(verifier: string): string {
    return createHash('sha256').update(verifier).digest('base64url')
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
   *
   * Special-case: providers like Keycloak rotate the refresh_token on every
   * use AND reject the previous one. If two mcp-remote processes start at
   * the same moment (which Claude Desktop sometimes does), both read the
   * same refresh_token from disk, both POST /token, and the second sees
   * `invalid_grant`. Before bubbling that up (which would trigger a fresh
   * OAuth flow in the SDK), we re-read tokens.json — the first process has
   * almost certainly just persisted the rotated refresh_token — and retry
   * once with the fresh value. If THAT also fails, the refresh token is
   * genuinely invalid and we surface the error.
   */
  private async performTokenRefresh(refreshToken: string): Promise<OAuthTokens | undefined> {
    return this.doTokenRefresh(refreshToken, /*allowReread=*/ true)
  }

  private async doTokenRefresh(refreshToken: string, allowReread: boolean): Promise<OAuthTokens | undefined> {
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
      const isInvalidGrant = response.status === 400 && text.includes('invalid_grant')

      if (isInvalidGrant && allowReread) {
        // Another mcp-remote process probably just rotated the refresh
        // token out from under us. Re-read what they persisted and try
        // once more before surfacing this as an auth failure.
        log('Refresh got invalid_grant; checking if another process rotated the token...')
        const fresh = await readJsonFile<StoredOAuthTokens>(this.serverUrlHash, 'tokens.json', StoredOAuthTokensSchema)
        if (fresh?.refresh_token && fresh.refresh_token !== refreshToken) {
          debugLog('Disk has a newer refresh_token; retrying once with it')
          return this.doTokenRefresh(fresh.refresh_token, /*allowReread=*/ false)
        }
        debugLog('Disk refresh_token unchanged; invalid_grant is real')
      }

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
    let tokens = await readJsonFile<StoredOAuthTokens>(this.serverUrlHash, 'tokens.json', StoredOAuthTokensSchema)

    // If the on-disk tokens are stale (older expires_at) but we have fresher
    // tokens in memory from a save that didn't persist to disk, prefer the
    // in-memory copy. This keeps things working when disk persistence is
    // intermittent (Windows concurrent processes, AV scanners, etc.).
    if (this.inMemoryTokens) {
      const diskExpiresAt = tokens?.expires_at ?? 0
      const memExpiresAt = this.inMemoryTokens.expires_at ?? 0
      if (!tokens || memExpiresAt > diskExpiresAt) {
        debugLog('Using in-memory tokens (fresher than disk or disk missing)', {
          diskExpiresAt,
          memExpiresAt,
        })
        tokens = this.inMemoryTokens
      }
    }

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
      hasAuthoritativeExpiry && !!tokens.refresh_token && timeLeftMs < NodeOAuthClientProvider.REFRESH_BUFFER_MS

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
        const persisted = await readJsonFile<StoredOAuthTokens>(this.serverUrlHash, 'tokens.json', StoredOAuthTokensSchema)
        return persisted ?? refreshed
      }
      // Refresh skipped (no metadata / no client info) - return stale tokens.
      return tokens
    } catch (err) {
      if (isInvalidGrantError(err)) {
        log('Refresh token was rejected by the authorization server. Clearing cached tokens and starting fresh auth.')
        await this.invalidateCredentials('tokens')
        return undefined
      }

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

    // Cache the tokens in memory unconditionally — they're valid right now
    // regardless of whether the disk write succeeds. Subsequent reads via
    // tokens() can fall back to this cache if readJsonFile returns stale or
    // ENOENT'd state.
    this.inMemoryTokens = tokensWithExpiry

    // Record that we just acquired fresh tokens. Used by
    // redirectToAuthorization to suppress browser tabs that the SDK opens
    // due to transient auth-related errors right after a refresh.
    this.lastSuccessfulSaveAt = Date.now()

    // Persist to disk, but do NOT throw if persistence fails. A failed write
    // is annoying (the next mcp-remote process won't see these tokens until
    // a successful save) but it is NOT an auth failure — the tokens are
    // perfectly usable in this process. If we throw here, the SDK treats
    // saveTokens-rejection as an auth flow failure and triggers a fresh
    // OAuth round (browser tab, PKCE, the works). On Windows with concurrent
    // mcp-remote subprocesses (which Claude Desktop spawns), this would
    // cascade into dozens of browser tabs — the "SSO storm" failure mode.
    try {
      await writeJsonFile(this.serverUrlHash, 'tokens.json', tokensWithExpiry)
    } catch (err) {
      log(
        `Persisting tokens to disk failed; keeping them in memory for this process. The next mcp-remote subprocess will trigger a fresh refresh. Cause:`,
        err,
      )
    }

    // The single-flight gate is released ONLY here, after the token
    // exchange has completed and new tokens are persisted. Releasing
    // earlier (e.g. on callback receipt) reopens the race: a parallel
    // reconnect path could rotate state() and overwrite the verifier
    // between callback and finishAuth, making the auth_code unredeemable.
    this.releaseAuthAttempt('saveTokens-success')
    this.consecutiveInvalidGrants = 0
    this.invalidGrantBackoffUntil = 0
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

    // Guard 1: recently saved tokens. If we just persisted fresh tokens
    // within AUTH_RECENT_WINDOW_MS, the SDK reaching this code path is
    // almost certainly a false alarm; our tokens are valid and the SDK can
    // retry the request with its existing Bearer header.
    const sinceSave = Date.now() - this.lastSuccessfulSaveAt
    if (this.lastSuccessfulSaveAt > 0 && sinceSave < NodeOAuthClientProvider.AUTH_RECENT_WINDOW_MS) {
      log(
        `Browser open suppressed: tokens were saved ${sinceSave}ms ago (within ` +
          `${NodeOAuthClientProvider.AUTH_RECENT_WINDOW_MS}ms window). Existing tokens are valid; ` +
          `the SDK reached the auth path due to a transient error. Not opening a tab.`,
      )
      return
    }

    // Guard 2: invalid_grant backoff. After a token-exchange failure we
    // refuse new OAuth round trips for an exponential window so we are not
    // spamming an IdP that just said "no".
    const backoffRemaining = this.invalidGrantBackoffUntil - Date.now()
    if (backoffRemaining > 0) {
      log(
        `Browser open suppressed: invalid_grant backoff in effect (${Math.ceil(backoffRemaining / 1000)}s remaining). ` +
          `Wait, then retry from Claude Desktop.`,
      )
      return
    }

    // Guard 3: PKCE challenge match. The single-flight gate guarantees
    // only one verifier is associated with the active attempt. If the URL
    // the SDK handed us was built with a DIFFERENT challenge, it came from
    // a duplicate auth pass that lost the race in saveCodeVerifier(). It is
    // unredeemable - the auth_code its tab would mint cannot be exchanged
    // against the verifier we have stored. Suppress quietly.
    this.purgeExpiredAttempt()
    const attempt = this.activeAuthAttempt
    const urlChallenge = authorizationUrl.searchParams.get('code_challenge')
    if (attempt && attempt.codeChallenge && urlChallenge && urlChallenge !== attempt.codeChallenge) {
      debugLog('Suppressing redirectToAuthorization for stale challenge', {
        state: attempt.state,
        urlState: authorizationUrl.searchParams.get('state'),
      })
      log('Auth tab already pending for this server; this duplicate attempt is suppressed.')
      return
    }

    try {
      await open(sanitizeUrl(authorizationUrl.toString()))
      log('Browser opened automatically.')
    } catch (error) {
      log('Could not open browser automatically. Please copy and paste the URL above into your browser.')
      debugLog('Failed to open browser', error)
    }
  }

  /**
   * Called by the proxy when the token-exchange step (finishAuth) returns
   * invalid_grant. We extend the backoff window, count toward the terminal
   * threshold, and on the Nth strike, do a full credential wipe and release
   * the gate so the next user action can start clean.
   */
  recordInvalidGrant(): void {
    this.consecutiveInvalidGrants += 1
    const exp = Math.min(
      NodeOAuthClientProvider.INVALID_GRANT_BACKOFF_BASE_MS * 2 ** (this.consecutiveInvalidGrants - 1),
      NodeOAuthClientProvider.INVALID_GRANT_BACKOFF_CAP_MS,
    )
    this.invalidGrantBackoffUntil = Date.now() + exp
    debugLog('invalid_grant backoff scheduled', {
      consecutive: this.consecutiveInvalidGrants,
      backoffMs: exp,
    })
    if (this.consecutiveInvalidGrants >= NodeOAuthClientProvider.INVALID_GRANT_TERMINAL_THRESHOLD) {
      log('Persistent invalid_grant errors detected. Wiping cached tokens and PKCE state.')
      this.invalidateCredentials('tokens').catch((err) => debugLog('terminal invalidate failed', err))
      this.invalidateCredentials('verifier').catch((err) => debugLog('terminal invalidate failed', err))
      this.releaseAuthAttempt('invalid_grant-terminal')
    }
  }

  /**
   * Saves the PKCE code verifier. First-writer-wins while an attempt is
   * active: if state() has already started an attempt and a verifier was
   * stored for it, subsequent saveCodeVerifier() calls within the same
   * attempt are no-ops. This prevents a parallel reconnect path from
   * overwriting verifier-A with verifier-B and then making the auth_code
   * minted for challenge-A unredeemable.
   * @param codeVerifier The code verifier to save
   */
  async saveCodeVerifier(codeVerifier: string): Promise<void> {
    this.purgeExpiredAttempt()
    const attempt = this.activeAuthAttempt
    if (attempt && attempt.codeVerifier && attempt.codeVerifier !== codeVerifier) {
      debugLog('Ignoring duplicate saveCodeVerifier for active attempt', {
        state: attempt.state,
      })
      return
    }
    if (attempt) {
      attempt.codeVerifier = codeVerifier
      attempt.codeChallenge = NodeOAuthClientProvider.pkceChallengeForVerifier(codeVerifier)
    }
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
        this.inMemoryTokens = null
        this.refreshPromise = null
        this.lastSuccessfulSaveAt = 0
        this.releaseAuthAttempt('invalidate-all')
        debugLog('All credentials invalidated')
        break

      case 'client':
        await deleteConfigFile(this.serverUrlHash, 'client_info.json')
        this._clientInfo = undefined
        debugLog('Client information invalidated')
        break

      case 'tokens':
        await deleteConfigFile(this.serverUrlHash, 'tokens.json')
        this.inMemoryTokens = null
        this.refreshPromise = null
        this.lastSuccessfulSaveAt = 0
        debugLog('OAuth tokens invalidated')
        break

      case 'verifier':
        await deleteConfigFile(this.serverUrlHash, 'code_verifier.txt')
        // Releasing the gate here lets a fresh attempt start. We intentionally
        // do NOT release on 'tokens'-only invalidation because a token wipe
        // can happen mid-attempt (e.g. proactive refresh failure) and we
        // want the in-flight authorization to still complete.
        this.releaseAuthAttempt('invalidate-verifier')
        debugLog('Code verifier invalidated')
        break

      default:
        throw new Error(`Unknown credential scope: ${scope}`)
    }
  }
}
