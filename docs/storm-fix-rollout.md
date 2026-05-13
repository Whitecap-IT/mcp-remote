# MCP Storm Fix — Company-Wide Rollout

## What this fixes

Some users reported Claude Desktop suddenly opening **dozens of Keycloak login tabs in a few seconds**, with no obvious trigger. This was a bug in `@wcap/mcp-remote` versions up to and including `0.1.38-wcap.10`. The fix is in `0.1.38-wcap.12`.

## What users need to do

Open **Command Prompt** (Windows) and run:

```cmd
npm install -g @wcap/mcp-remote --registry https://npm.shakudo.wcap.ca/
```

Then quit Claude Desktop fully (system tray → Quit) and start it again. That's it.

To verify the upgrade landed:

```cmd
npm list -g @wcap/mcp-remote
```

Expected output:

```
+-- @wcap/mcp-remote@0.1.38-wcap.12
```

## What if a user still sees the storm after upgrading

The storm should be impossible on `0.1.38-wcap.12`. If it still happens:

1. Confirm the version: `npm list -g @wcap/mcp-remote` — must be `0.1.38-wcap.12` or higher.
2. Confirm Claude Desktop was fully restarted (not just window-closed).
3. Capture the log: `%APPDATA%\Claude\logs\mcp-server-wcap-mcp-prod.log` — share with #mcp-platform.

## What's actually in this version

Four independent defenses, layered:

| Defense | What it does |
|---|---|
| Race-safe token-file writes | `writeJsonFile` uses a UUID-suffixed temp file. Two concurrent writes inside one process no longer collide and fail. |
| Non-fatal save failures | If the disk write does fail (Windows antivirus, file locks, etc.), the tokens stay valid in memory and the auth flow doesn't restart. |
| Cross-process refresh-token rotation handling | If another mcp-remote process consumed the refresh_token before us, we re-read the token file and retry once with the freshly-rotated value. |
| Browser-open guards | After a successful token save, browser tabs are suppressed for 60s. Beyond that, a 30s cooldown prevents repeat opens. |

All four are independent — if any one of them slips through, the next layer catches it.

## Why this happened in the first place

Upstream, the MCP server-push channel (long-lived GET `/mcp`) is being closed every 5 minutes by some idle-timeout in the Istio/agentgateway path. mcp-remote handles that drop correctly with its `ReconnectionManager` — but earlier versions had a subtle race in token persistence that turned a single SSE drop into a token-write storm into an auth-flow restart into 41 browser tabs.

The 5-min server-side cutoff is being chased separately. Even after that's fixed, the client-side defenses in `0.1.38-wcap.12` will remain useful for other failure modes (laptop sleep, network blip, Claude Desktop restart on Monday morning).

## For ops: what to monitor

- Any user reports of "lots of Keycloak tabs opening at once" — should be zero on `0.1.38-wcap.12`.
- Stale `.tmp` files in `~/.mcp-auth/mcp-remote-*/` directories — should be zero (the new writer cleans up after itself on failure).
- Loki query for AG access logs: `count_over_time({namespace="mcp-platform-prod", app="agentgateway"} |~ "duration=30[0-9]{4}ms" [1h])` — the 5-min cutoffs the storm was reacting to. Tracking this confirms the upstream issue is still active or fixed.
