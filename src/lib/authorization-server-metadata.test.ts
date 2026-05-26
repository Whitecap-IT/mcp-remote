import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { fetchAuthorizationServerMetadata, getMetadataUrl, getMetadataUrls } from './authorization-server-metadata'

describe('authorization-server-metadata', () => {
  describe('getMetadataUrl', () => {
    it('should construct correct well-known URL', () => {
      const url = getMetadataUrl('https://example.com/mcp')
      expect(url).toBe('https://example.com/.well-known/oauth-authorization-server')
    })

    it('should handle URLs with different paths', () => {
      const url = getMetadataUrl('https://api.example.com/v1/mcp/server')
      expect(url).toBe('https://api.example.com/.well-known/oauth-authorization-server')
    })

    it('should handle URLs with ports', () => {
      const url = getMetadataUrl('https://localhost:8080/mcp')
      expect(url).toBe('https://localhost:8080/.well-known/oauth-authorization-server')
    })
  })

  describe('getMetadataUrls', () => {
    it('should include Keycloak realm-local OIDC discovery URL', () => {
      const urls = getMetadataUrls('https://shakudo.wcap.ca/auth/realms/Hyperplane')

      expect(urls).toContain('https://shakudo.wcap.ca/auth/realms/Hyperplane/.well-known/openid-configuration')
      expect(urls).toContain('https://shakudo.wcap.ca/.well-known/oauth-authorization-server/auth/realms/Hyperplane')
    })
  })

  describe('fetchAuthorizationServerMetadata', () => {
    let originalFetch: typeof global.fetch

    beforeEach(() => {
      originalFetch = global.fetch
    })

    afterEach(() => {
      global.fetch = originalFetch
    })

    it('should fetch and parse metadata successfully', async () => {
      const mockMetadata = {
        issuer: 'https://example.com',
        authorization_endpoint: 'https://example.com/oauth/authorize',
        token_endpoint: 'https://example.com/oauth/token',
        scopes_supported: ['openid', 'email', 'profile', 'custom:read'],
        response_types_supported: ['code'],
      }

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => mockMetadata,
      })

      const metadata = await fetchAuthorizationServerMetadata('https://example.com')

      expect(metadata).toEqual(mockMetadata)
      expect(global.fetch).toHaveBeenCalledWith(
        'https://example.com/.well-known/oauth-authorization-server',
        expect.objectContaining({
          headers: {
            Accept: 'application/json',
          },
        }),
      )
    })

    it('should fall back to realm-local OIDC metadata when OAuth metadata is not found', async () => {
      const mockMetadata = {
        issuer: 'https://idp.example.com/auth/realms/Hyperplane',
        authorization_endpoint: 'https://idp.example.com/auth/realms/Hyperplane/protocol/openid-connect/auth',
        token_endpoint: 'https://idp.example.com/auth/realms/Hyperplane/protocol/openid-connect/token',
      }

      global.fetch = vi
        .fn()
        .mockResolvedValueOnce({
          ok: false,
          status: 404,
          statusText: 'Not Found',
        })
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => mockMetadata,
        })

      const metadata = await fetchAuthorizationServerMetadata('https://idp.example.com/auth/realms/Hyperplane')

      expect(metadata).toEqual(mockMetadata)
      expect(global.fetch).toHaveBeenNthCalledWith(
        1,
        'https://idp.example.com/.well-known/oauth-authorization-server/auth/realms/Hyperplane',
        expect.any(Object),
      )
      expect(global.fetch).toHaveBeenNthCalledWith(
        2,
        'https://idp.example.com/auth/realms/Hyperplane/.well-known/openid-configuration',
        expect.any(Object),
      )
    })

    it('should return undefined on 404', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 404,
        statusText: 'Not Found',
      })

      const metadata = await fetchAuthorizationServerMetadata('https://example.com/mcp')

      expect(metadata).toBeUndefined()
    })

    it('should return undefined on other HTTP errors', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
      })

      const metadata = await fetchAuthorizationServerMetadata('https://example.com/mcp')

      expect(metadata).toBeUndefined()
    })

    it('should return undefined on network errors', async () => {
      global.fetch = vi.fn().mockRejectedValue(new Error('Network error'))

      const metadata = await fetchAuthorizationServerMetadata('https://example.com/mcp')

      expect(metadata).toBeUndefined()
    })

    it('should handle timeout errors', async () => {
      global.fetch = vi.fn().mockRejectedValue(new Error('Timeout'))

      const metadata = await fetchAuthorizationServerMetadata('https://example.com/mcp')

      expect(metadata).toBeUndefined()
    })

    it('should handle metadata without scopes_supported', async () => {
      const mockMetadata = {
        issuer: 'https://example.com',
        authorization_endpoint: 'https://example.com/oauth/authorize',
        token_endpoint: 'https://example.com/oauth/token',
        // No scopes_supported
      }

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => mockMetadata,
      })

      const metadata = await fetchAuthorizationServerMetadata('https://example.com/mcp')

      expect(metadata).toEqual(mockMetadata)
      expect(metadata?.scopes_supported).toBeUndefined()
    })

    it('should handle metadata with empty scopes_supported', async () => {
      const mockMetadata = {
        issuer: 'https://example.com',
        scopes_supported: [],
      }

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => mockMetadata,
      })

      const metadata = await fetchAuthorizationServerMetadata('https://example.com/mcp')

      expect(metadata).toEqual(mockMetadata)
      expect(metadata?.scopes_supported).toEqual([])
    })
  })
})
