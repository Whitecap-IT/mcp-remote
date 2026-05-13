# Whitecap MCP Setup Guide — Windows

Connect Claude Desktop to Whitecap's internal databases (whprod, whstage, whgis) via the MCP platform.

## Prerequisites

- **Claude Desktop** installed on your Windows machine
- **Node.js** (v18 or later) installed — [download here](https://nodejs.org/)
- **Keycloak access** — your Whitecap account must have the appropriate MCP roles assigned by an admin (e.g. `mcp-ro-all` for access to all databases)

To verify Node.js is installed, open **Command Prompt** and run:

```cmd
node --version
```

## Step 1: Install the MCP Remote Proxy

Open **Command Prompt** and run:

```cmd
npm install -g @wcap/mcp-remote --registry https://npm.shakudo.wcap.ca/
```

To verify:

```cmd
npm list -g @wcap/mcp-remote
```

## Step 2: Configure Claude Desktop

1. Open Claude Desktop
2. Click the **hamburger menu** (top-left) > **Settings** > **Developer** > **Edit Config**
3. This opens `claude_desktop_config.json` in your text editor
4. Replace the contents with:

```json
{
  "mcpServers": {
    "wcap-mcp-prod": {
      "command": "mcp-remote",
      "args": [
        "https://mcp.shakudo.wcap.ca/mcp",
        "9697",
        "--transport",
        "http-only",
        "--static-oauth-client-info",
        "{\"client_id\":\"mcp-platform-prod\"}"
      ]
    }
  }
}
```

> **Note:** If you already have other MCP servers configured, add the `wcap-mcp-prod` entry inside the existing `mcpServers` object rather than replacing the whole file.

5. Save the file and **restart Claude Desktop** (fully quit and reopen, not just close the window)

## Step 3: Authenticate

On first connection, Claude Desktop will:

1. Open your default browser to the Whitecap Keycloak login page
2. Log in with your Whitecap credentials
3. After successful login, the browser will show a confirmation page — you can close it
4. Claude Desktop will now show the MCP tools as available

Authentication persists across sessions. You should not need to log in again unless your session expires or is revoked.

## Step 4: Verify

In Claude Desktop, you should see the MCP server status showing as connected. Try asking Claude:

> "Run a query on whstage: SELECT current_database()"

Claude should return the database name, confirming the connection works.

## Updating to a New Version

When a new version is released, open **Command Prompt** and run:

```cmd
rmdir /s /q "%LOCALAPPDATA%\npm-cache" && npm install -g @wcap/mcp-remote --registry https://npm.shakudo.wcap.ca/
```

Then restart Claude Desktop.

## Troubleshooting

### MCP server shows as "Dropped" or "Disconnected"

The proxy auto-reconnects when the server restarts. Wait 1-2 minutes — it should recover on its own. If it doesn't, restart Claude Desktop.

### Authentication fails or loops

Clear the cached auth tokens and restart:

1. Open **File Explorer** and navigate to `%USERPROFILE%\.mcp-auth\`
2. Delete all files in that folder
3. Restart Claude Desktop — it will prompt you to log in again

### Lots of Keycloak login tabs opening at once ("SSO storm")

If this happens, **first quit Claude Desktop fully** (system tray → Quit). It usually settles within a minute.

This issue was a known bug in versions ≤ `0.1.38-wcap.10`. Upgrade to the latest version:

```cmd
npm install -g @wcap/mcp-remote --registry https://npm.shakudo.wcap.ca/
```

Then restart Claude Desktop. The new version has four layers of defense against the storm:

- Race-safe token file writes (no more concurrent-write collisions)
- Token-save failures no longer trigger fresh logins
- Cross-process refresh-token rotation handling
- A 30-second cooldown plus a "tokens just refreshed" suppression on browser opens

If you still see the storm after upgrading, attach `%APPDATA%\Claude\logs\mcp-server-wcap-mcp-prod.log` to a support ticket — that file shows exactly what mcp-remote tried.

### "server closed the connection unexpectedly" errors

This is a transient backend database error. Retry the query — the second attempt should succeed. If it persists, contact the MCP platform admin.

### Check which version is installed

```cmd
npm list -g @wcap/mcp-remote
```

### Check logs

Claude Desktop MCP logs are at:

```
%APPDATA%\Claude\logs\mcp-server-wcap-mcp-prod.log
```

Open this file to see connection status, reconnection attempts, and error details.

## Available Databases

| Database | Description | Tool prefix |
|----------|-------------|-------------|
| whprod | Production warehouse | `whprod-ro_` |
| whstage | Staging warehouse | `whstage-ro_` |
| whgis | GIS database | `whgis-ro_` |

All access is **read-only**. You can run SELECT queries but cannot modify data.

## Access Roles

Your access depends on which Keycloak roles are assigned to your account:

| Role | Access |
|------|--------|
| `mcp-ro-all` | All three databases (most common) |
| `mcp-ro-whprod` | whprod only |
| `mcp-ro-whstage` | whstage only |
| `mcp-ro-whgis` | whgis only |

If you get authorization errors for a specific database, contact your admin to verify your role assignment.

## Support

For issues with the MCP platform, contact the SRE team or file a ticket referencing "MCP Platform - prod".
