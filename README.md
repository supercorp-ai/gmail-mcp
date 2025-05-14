`@supercorp/gmail-mcp` is a Gmail MCP server.

## Installation & Usage

Run via `npx` using only the required flags:

```bash
npx @supercorp/gmail-mcp \
  --googleClientId <string> \
  --googleClientSecret <string> \
  --googleRedirectUri <string>
```

All other options can be adjusted in the table below.

## CLI Arguments

| Flag                      | Type                     | Default            | Description                                                                                                           |
|---------------------------|--------------------------|--------------------|-----------------------------------------------------------------------------------------------------------------------|
| `--googleClientId`        | _string_ _(required)_    | N/A                | Your Google OAuth client ID.                                                                                          |
| `--googleClientSecret`    | _string_ _(required)_    | N/A                | Your Google OAuth client secret.                                                                                      |
| `--googleRedirectUri`     | _string_ _(required)_    | N/A                | OAuth 2.0 redirect URI registered in Google Cloud Console.                                                            |
| `--port`                  | _number_                 | `8000`             | TCP port for HTTP/SSE mode.                                                                                           |
| `--transport`             | `sse` or `stdio`         | `sse`              | MCP transport:<br>• `sse`: HTTP server + Server-Sent Events<br>• `stdio`: JSON-RPC over stdin/stdout                  |
| `--storage`               | see below                | `memory-single`   | Persistence backend for OAuth tokens:<br>• `memory-single`: in-memory single-user (no header key)<br>• `memory`: multi-user in-memory<br>• `upstash-redis-rest`: durable via Upstash Redis REST API |
| `--storageHeaderKey`      | _string_ _(conditional)_  | _none_             | HTTP header name (or Redis key prefix) to identify users when using `memory` or `upstash-redis-rest`.                  |
| `--upstashRedisRestUrl`   | _string_ _(conditional)_  | _none_             | Upstash Redis REST URL (required if `--storage=upstash-redis-rest`).                                                  |
| `--upstashRedisRestToken` | _string_ _(conditional)_  | _none_             | Upstash Redis REST token (required if `--storage=upstash-redis-rest`).                                                |
| `--sendOnly`              | _boolean_                | `false`            | If set, only the `gmail.send` tool is exposed (no read/draft capabilities).                                           |
| `--googleState`           | _string_ _(optional)_     | _none_             | Optional OAuth state parameter forwarded to Google.                                                                   |

### Storage Backends

- **memory-single**: in-memory single-user (quick demos; data lost on restart)
- **memory**: in-memory multi-user (requires `--storageHeaderKey`)
- **upstash-redis-rest**: persistent via Upstash Redis REST (requires `--storageHeaderKey`, `--upstashRedisRestUrl`, `--upstashRedisRestToken`)

### Transports

- **stdio**
  JSON-RPC over stdin/stdout.
- **sse**
  HTTP server + Server-Sent Events:
  - Subscribe: `GET http://localhost:<port>/`
  - Send:      `POST http://localhost:<port>/message?sessionId=<session-id>`

## Exposed MCP Methods

| Tool                 | Description                                                                                                         |
|----------------------|---------------------------------------------------------------------------------------------------------------------|
| `auth_url`           | Returns a Gmail OAuth consent URL.                                                                                  |
| `exchange_auth_code` | Exchanges the OAuth code for a refresh token and stores it.                                                          |
| `list_emails`        | Lists Gmail messages (`maxResults`, `labelIds`, `query`, `pageToken`, `unreadOnly`).                                |
| `read_email`         | Retrieves a full message by ID, converts HTML bodies into Markdown.                                                  |
| `list_drafts`        | Lists Gmail drafts (`maxResults`, `query`).                                                                         |
| `read_draft`         | Reads a single draft by ID (in full).                                                                               |
| `draft_email`        | Creates a new draft (`sender`, `to`, `cc?`, `bcc?`, `subject`, `body`, `isHtml?`).                                   |
| `update_draft`       | Updates an existing draft by ID.                                                                                     |
| `delete_draft`       | Deletes a draft by ID.                                                                                               |
| `send_email`         | Sends an email (new or via an existing draft if `draftId` is provided). In send-only mode, this is the only tool.  |
