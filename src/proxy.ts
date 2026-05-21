#!/usr/bin/env node

/**
 * MCP Proxy with OAuth support
 * A bidirectional proxy between a local STDIO MCP server and a remote SSE server with OAuth authentication.
 *
 * Run with: npx tsx proxy.ts https://example.remote/server [callback-port]
 *
 * If callback-port is not specified, an available port will be automatically selected.
 */

import { EventEmitter } from 'events'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { StreamableHTTPError } from '@modelcontextprotocol/sdk/client/streamableHttp.js'
import {
  connectToRemoteServer,
  log,
  debugLog,
  mcpProxy,
  parseCommandLineArgs,
  setupSignalHandlers,
  TransportStrategy,
  discoverOAuthServerInfo,
} from './lib/utils'
import { StaticOAuthClientInformationFull, StaticOAuthClientMetadata } from './lib/types'
import { NodeOAuthClientProvider } from './lib/node-oauth-client-provider'
import { createLazyAuthCoordinator } from './lib/coordination'
import { ReconnectionManager } from './lib/reconnection-manager'
import { maybeBackgroundUpdate } from './lib/update-check'

const DEFAULT_UPDATE_REGISTRY = 'https://npm.shakudo.wcap.ca/'

/**
 * Main function to run the proxy
 */
async function runProxy(
  serverUrl: string,
  callbackPort: number,
  headers: Record<string, string>,
  transportStrategy: TransportStrategy = 'http-first',
  host: string,
  staticOAuthClientMetadata: StaticOAuthClientMetadata,
  staticOAuthClientInfo: StaticOAuthClientInformationFull,
  authorizeResource: string,
  ignoredTools: string[],
  authTimeoutMs: number,
  serverUrlHash: string,
) {
  // Set up event emitter for auth flow
  const events = new EventEmitter()

  // Discover OAuth server info via Protected Resource Metadata (RFC 9728)
  // This probes the MCP server for WWW-Authenticate header and fetches PRM
  log('Discovering OAuth server configuration...')
  const discoveryResult = await discoverOAuthServerInfo(serverUrl, headers)

  if (discoveryResult.protectedResourceMetadata) {
    log(`Discovered authorization server: ${discoveryResult.authorizationServerUrl}`)
    if (discoveryResult.protectedResourceMetadata.scopes_supported) {
      debugLog('Protected Resource Metadata scopes', {
        scopes_supported: discoveryResult.protectedResourceMetadata.scopes_supported,
      })
    }
  } else {
    debugLog('No Protected Resource Metadata found, using server URL as authorization server')
  }

  // Create the OAuth client provider with discovered server info
  const authProvider = new NodeOAuthClientProvider({
    serverUrl: discoveryResult.authorizationServerUrl,
    callbackPort,
    host,
    clientName: 'MCP CLI Proxy',
    staticOAuthClientMetadata,
    staticOAuthClientInfo,
    authorizeResource,
    serverUrlHash,
    authorizationServerMetadata: discoveryResult.authorizationServerMetadata,
    protectedResourceMetadata: discoveryResult.protectedResourceMetadata,
    wwwAuthenticateScope: discoveryResult.wwwAuthenticateScope,
  })

  // Create a lazy auth coordinator after the provider exists so the callback
  // server can reject stale browser tabs whose OAuth state no longer matches
  // the current PKCE attempt.
  const authCoordinator = createLazyAuthCoordinator(serverUrlHash, callbackPort, events, authTimeoutMs, () => authProvider.currentState())

  // Create the STDIO transport for local connections
  const localTransport = new StdioServerTransport()

  // Keep track of the server instance for cleanup
  let server: any = null

  // Define an auth initializer function
  const authInitializer = async () => {
    const authState = await authCoordinator.initializeAuth()

    // Store server in outer scope for cleanup
    server = authState.server

    // If auth was completed by another instance, just log that we'll use the auth from disk
    if (authState.skipBrowserAuth) {
      log('Authentication was completed by another instance - will use tokens from disk')
      // TODO: remove, the callback is happening before the tokens are exchanged
      //  so we're slightly too early
      await new Promise((res) => setTimeout(res, 1_000))
    }

    return {
      waitForAuthCode: authState.waitForAuthCode,
      skipBrowserAuth: authState.skipBrowserAuth,
      resetAuth: authCoordinator.resetAuth,
    }
  }

  try {
    // Connect to remote server with lazy authentication.
    // Retry transient errors (500/502/503/504/network) so that startup
    // survives backend pods still booting.
    let remoteTransport = await (async () => {
      const maxStartupRetries = 10
      const retryDelayMs = 3000
      for (let attempt = 1; ; attempt++) {
        try {
          return await connectToRemoteServer(null, serverUrl, authProvider, headers, authInitializer, transportStrategy)
        } catch (err: any) {
          const code = err instanceof StreamableHTTPError ? err.code : undefined
          const isTransient =
            (typeof code === 'number' && code >= 500) ||
            err.message?.includes('ECONNREFUSED') ||
            err.message?.includes('fetch failed') ||
            err.message?.includes('Connection refused')

          if (!isTransient || attempt >= maxStartupRetries) throw err
          log(`Initial connection attempt ${attempt} failed (${String(code ?? err.message)}), retrying in ${retryDelayMs / 1000}s...`)
          await new Promise((r) => setTimeout(r, retryDelayMs))
        }
      }
    })()

    // Set up reconnection manager for seamless server restarts.
    // Retries indefinitely — survives hours-long outages (e.g. weekend maintenance).
    const reconnectionManager = new ReconnectionManager({
      config: {
        maxMessageAgeMs: 4 * 60 * 1000,
      },
      reconnectFn: async () => {
        log('Reconnecting to remote server...')
        return connectToRemoteServer(null, serverUrl, authProvider, headers, authInitializer, transportStrategy)
      },
      onTransportReplaced: (newTransport) => {
        remoteTransport = newTransport
        log('Server transport replaced successfully')
      },
      onMessagePurged: (message, reason) => {
        if (message.id) {
          log(`Sending error response for purged request ${message.id} (${message.method})`)
          localTransport
            .send({
              jsonrpc: '2.0',
              id: message.id,
              error: {
                code: -32603,
                message: reason || 'Server temporarily unavailable, please retry',
              },
            })
            .catch((err: Error) => log('Failed to send purge error response:', err.message))
        }
      },
    })

    // Set up bidirectional proxy between local and remote transports
    mcpProxy({
      transportToClient: localTransport,
      transportToServer: remoteTransport,
      ignoredTools,
      reconnectionManager,
      onAuthFailure: async () => {
        await authProvider.invalidateCredentials('tokens')
        await authCoordinator.resetAuth()
      },
    })

    // Start the local STDIO server
    await localTransport.start()
    log('Local STDIO server running')
    log(`Proxy established successfully between local STDIO and remote ${remoteTransport.constructor.name}`)
    log('Press Ctrl+C to exit')

    // Fire-and-forget background update check. Never throws; if the npm
    // registry is unreachable, the proxy keeps running on the currently
    // installed global binary. Disable with MCP_REMOTE_DISABLE_UPDATE_CHECK=1.
    try {
      const registry = process.env.MCP_REMOTE_UPDATE_REGISTRY || DEFAULT_UPDATE_REGISTRY
      maybeBackgroundUpdate(registry)
    } catch (err) {
      debugLog('update-check: invocation threw (treated as no-op)', err)
    }

    // Setup cleanup handler
    const cleanup = async () => {
      await remoteTransport.close()
      await localTransport.close()
      // Only close the server if it was initialized
      if (server) {
        server.close()
      }
    }
    setupSignalHandlers(cleanup)
  } catch (error) {
    log('Fatal error:', error)
    if (error instanceof Error && error.message.includes('self-signed certificate in certificate chain')) {
      log(`You may be behind a VPN!

If you are behind a VPN, you can try setting the NODE_EXTRA_CA_CERTS environment variable to point
to the CA certificate file. If using claude_desktop_config.json, this might look like:

{
  "mcpServers": {
    "\${mcpServerName}": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://remote.mcp.server/sse"
      ],
      "env": {
        "NODE_EXTRA_CA_CERTS": "\${your CA certificate file path}.pem"
      }
    }
  }
}
        `)
    }
    // Only close the server if it was initialized
    if (server) {
      server.close()
    }
    process.exit(1)
  }
}

// Parse command-line arguments and run the proxy
parseCommandLineArgs(process.argv.slice(2), 'Usage: npx tsx proxy.ts <https://server-url> [callback-port] [--debug]')
  .then(
    ({
      serverUrl,
      callbackPort,
      headers,
      transportStrategy,
      host,
      debug,
      staticOAuthClientMetadata,
      staticOAuthClientInfo,
      authorizeResource,
      ignoredTools,
      authTimeoutMs,
      serverUrlHash,
    }) => {
      return runProxy(
        serverUrl,
        callbackPort,
        headers,
        transportStrategy,
        host,
        staticOAuthClientMetadata,
        staticOAuthClientInfo,
        authorizeResource,
        ignoredTools,
        authTimeoutMs,
        serverUrlHash,
      )
    },
  )
  .catch((error) => {
    log('Fatal error:', error)
    process.exit(1)
  })
