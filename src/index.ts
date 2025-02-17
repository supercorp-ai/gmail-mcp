#!/usr/bin/env node

import yargs from 'yargs'
import { hideBin } from 'yargs/helpers'
import express, { Request, Response } from 'express'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { z } from 'zod'
import { google, gmail_v1 } from 'googleapis'
import { OAuth2Client } from 'google-auth-library'
import { createMimeMessage } from 'mimetext' // You can install a helper, or build raw base64 yourself

/* ------------------------------------------------------------------
 * Logging
 * ------------------------------------------------------------------ */
const log = (...args: any[]) => console.log('[gmail-mcp]', ...args)
const logErr = (...args: any[]) => console.error('[gmail-mcp]', ...args)

/* ------------------------------------------------------------------
 * OAuth Setup
 * ------------------------------------------------------------------ */
const CLIENT_ID = process.env.GOOGLE_CLIENT_ID || ''
const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || ''
const REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI || ''
const REFRESH_TOKEN = process.env.GOOGLE_REFRESH_TOKEN || ''
const STATE = process.env.GOOGLE_STATE || ''

const oauth2Client = new OAuth2Client(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI)
if (REFRESH_TOKEN) {
  oauth2Client.setCredentials({ refresh_token: REFRESH_TOKEN })
  log('Using refresh token from env.')
} else {
  log('No refresh token in env. Provide at runtime or exchange_auth_code.')
}

const gmail = google.gmail({ version: 'v1', auth: oauth2Client })

/* ------------------------------------------------------------------
 * MCP-friendly JSON response (always "type": "text")
 * ------------------------------------------------------------------ */
function toTextJson(data: unknown) {
  return {
    content: [
      {
        type: 'text' as const,
        text: JSON.stringify(data, null, 2)
      }
    ]
  }
}

/* ------------------------------------------------------------------
 * decodeBase64Url + collectParts for "readEmail"
 * ------------------------------------------------------------------ */
function decodeBase64Url(encoded: string): string {
  const base64 = encoded.replace(/-/g, '+').replace(/_/g, '/')
  return Buffer.from(base64, 'base64').toString('utf8')
}

function collectParts(payload?: gmail_v1.Schema$MessagePart): { mimeType?: string; text: string }[] {
  if (!payload) return []
  const results: { mimeType?: string; text: string }[] = []

  // If part has data, decode if text
  if (payload.body?.data && (payload.mimeType?.startsWith('text/') || payload.mimeType === 'text/html')) {
    results.push({
      mimeType: payload.mimeType,
      text: decodeBase64Url(payload.body.data)
    })
  }

  // Recurse sub-parts
  if (payload.parts) {
    for (const part of payload.parts) {
      results.push(...collectParts(part))
    }
  }
  return results
}

/* ------------------------------------------------------------------
 * (1) getAuthUrl / (2) exchangeAuthCode
 * ------------------------------------------------------------------ */
function getAuthUrl(): string {
  const SCOPES = [
    'https://www.googleapis.com/auth/gmail.send',
    'https://www.googleapis.com/auth/gmail.readonly'
  ]
  return oauth2Client.generateAuthUrl({
    access_type: 'offline',
    prompt: 'consent',
    scope: SCOPES,
    state: STATE,
  })
}
async function exchangeAuthCode(code: string): Promise<string> {
  log(`Exchanging auth code: ${code}`)
  const { tokens } = await oauth2Client.getToken(code.trim())
  if (!tokens.refresh_token) {
    throw new Error('No refresh token returned by Google.')
  }
  oauth2Client.setCredentials(tokens)
  log('Exchange successful, refresh token obtained.')
  return tokens.refresh_token
}

/* ------------------------------------------------------------------
 * (3) listEmails (with snippet, pageToken for pagination)
 * ------------------------------------------------------------------ */
interface ListEmailsArgs {
  maxResults?: number
  labelIds?: string[]
  query?: string
  pageToken?: string
  unreadOnly?: boolean
}
async function listEmails(args: ListEmailsArgs) {
  const { maxResults = 10, labelIds, query, pageToken, unreadOnly = false } = args
  const q = [query, unreadOnly ? 'is:unread' : null].filter(Boolean).join(' ')

  const resp = await gmail.users.messages.list({
    userId: 'me',
    maxResults,
    labelIds,
    pageToken,
    ...(q && { q })
  })

  // If you want the snippet, we can do a quick
  // "get()" for each message. This is more expensive,
  // but let's do it for demonstration:
  if (resp.data.messages) {
    const enriched = []
    for (const m of resp.data.messages) {
      // Retrieve minimal info to get snippet
      const detail = await gmail.users.messages.get({
        userId: 'me',
        id: m.id!,
        format: 'metadata', // or 'snippet'
        metadataHeaders: ['Subject', 'From', 'To']
      })
      enriched.push({
        id: detail.data.id,
        threadId: detail.data.threadId,
        snippet: detail.data.snippet,
        headers: detail.data.payload?.headers
      })
    }
    return toTextJson({
      nextPageToken: resp.data.nextPageToken,
      resultSizeEstimate: resp.data.resultSizeEstimate,
      messages: enriched
    })
  }

  // fallback
  return toTextJson(resp.data)
}

/* ------------------------------------------------------------------
 * (4) readEmail: full message + decode
 * ------------------------------------------------------------------ */
async function readEmail(messageId: string) {
  const resp = await gmail.users.messages.get({
    userId: 'me',
    id: messageId,
    format: 'full'
  })

  if (resp.data.payload) {
    const decoded = collectParts(resp.data.payload)
    ;(resp.data as any).decodedParts = decoded
  }
  return toTextJson(resp.data)
}

/* ------------------------------------------------------------------
 * Draft tools
 * (a) listDrafts
 * (b) readDraft
 * (c) draftEmail (create)
 * (d) updateDraft
 * (e) deleteDraft
 * ------------------------------------------------------------------ */
// (a) listDrafts
interface ListDraftsArgs {
  maxResults?: number
  query?: string
}
async function listDrafts({ maxResults = 10, query }: ListDraftsArgs) {
  const q = query ?? ''
  const resp = await gmail.users.drafts.list({
    userId: 'me',
    maxResults,
    q
  })
  return toTextJson(resp.data)
}

// (b) readDraft
async function readDraft(draftId: string) {
  const resp = await gmail.users.drafts.get({
    userId: 'me',
    id: draftId,
    format: 'full'
  })
  // We can decode the message inside if needed:
  if (resp.data.message?.payload) {
    const decoded = collectParts(resp.data.message.payload)
    ;(resp.data as any).decodedParts = decoded
  }
  return toTextJson(resp.data)
}

// Utility: build raw base64 encoded email
function buildMimeMessage({
  to,
  cc,
  bcc,
  subject,
  body,
  isHtml
}: {
  to: string[]
  cc?: string[]
  bcc?: string[]
  subject: string
  body: string
  isHtml?: boolean
}): string {
  const msg = createMimeMessage()
  msg.setSender('me <me@gmail.com>') // "From" can be changed
  msg.setTo(to)
  if (cc) msg.setCc(cc)
  if (bcc) msg.setBcc(bcc)
  msg.setSubject(subject)

  if (isHtml) {
    msg.addMessage({
      contentType: 'text/html',
      data: body
    })
  } else {
    msg.addMessage({
      contentType: 'text/plain',
      data: body
    })
  }
  // createMimeMessage returns text => must base64url
  const raw = msg.asEncoded() // standard base64
  // But Gmail wants base64-URL
  return raw.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

// (c) draftEmail (create draft)
interface DraftEmailArgs {
  to: string[]
  cc?: string[]
  bcc?: string[]
  subject: string
  body: string
  isHtml?: boolean
}
async function draftEmail(args: DraftEmailArgs) {
  const raw = buildMimeMessage(args)
  const resp = await gmail.users.drafts.create({
    userId: 'me',
    requestBody: {
      message: {
        raw
      }
    }
  })
  return toTextJson(resp.data)
}

// (d) updateDraft
interface UpdateDraftArgs extends DraftEmailArgs {
  draftId: string
}
async function updateDraft(args: UpdateDraftArgs) {
  const { draftId, ...rest } = args
  const raw = buildMimeMessage(rest)
  const resp = await gmail.users.drafts.update({
    userId: 'me',
    id: draftId,
    requestBody: {
      message: {
        raw
      }
    }
  })
  return toTextJson(resp.data)
}

// (e) deleteDraft
async function deleteDraft(draftId: string) {
  await gmail.users.drafts.delete({
    userId: 'me',
    id: draftId
  })
  return toTextJson({ success: true, deletedDraftId: draftId })
}

/* ------------------------------------------------------------------
 * sendEmail: either send from scratch or pass a draftId
 * ------------------------------------------------------------------ */
interface SendEmailArgs extends DraftEmailArgs {
  draftId?: string
}
async function sendEmail(args: SendEmailArgs) {
  const { draftId, ...rest } = args

  // If they gave a draftId, let's "send draft"
  if (draftId) {
    const resp = await gmail.users.drafts.send({
      userId: 'me',
      requestBody: {
        id: draftId
      }
    })
    return toTextJson(resp.data)
  }

  // Otherwise, build + send new message
  const raw = buildMimeMessage(rest)
  const resp = await gmail.users.messages.send({
    userId: 'me',
    requestBody: {
      raw
    }
  })
  return toTextJson(resp.data)
}

/* ------------------------------------------------------------------
 * Create MCP Server with all tools
 * ------------------------------------------------------------------ */
function createServerWithTools(): McpServer {
  const server = new McpServer({
    name: 'Gmail MCP Server',
    version: '1.0.0'
  })

  // (1) auth_url
  server.tool(
    'auth_url',
    'Return an OAuth URL for the user to visit',
    {},
    async () => {
      try {
        return toTextJson({ authUrl: getAuthUrl() })
      } catch (err: any) {
        return toTextJson({ error: String(err.message) })
      }
    }
  )

  // (2) exchange_auth_code
  server.tool(
    'exchange_auth_code',
    'Exchange an auth code for refresh token',
    { code: z.string() },
    async ({ code }) => {
      try {
        const token = await exchangeAuthCode(code)
        return toTextJson({ refreshToken: token })
      } catch (err: any) {
        return toTextJson({ error: String(err.message) })
      }
    }
  )

  // (3) list_emails
  server.tool(
    'list_emails',
    'List Gmail messages with snippet, etc. (supports pagination)',
    {
      maxResults: z.number().optional(),
      labelIds: z.array(z.string()).optional(),
      query: z.string().optional(),
      pageToken: z.string().optional(),
      unreadOnly: z.boolean().optional()
    },
    async (args) => {
      try {
        return await listEmails(args)
      } catch (err: any) {
        return toTextJson({ error: String(err.message) })
      }
    }
  )

  // (4) read_email
  server.tool(
    'read_email',
    'Fetch a single message in full, decode text parts.',
    { messageId: z.string() },
    async ({ messageId }) => {
      try {
        return await readEmail(messageId)
      } catch (err: any) {
        return toTextJson({ error: String(err.message) })
      }
    }
  )

  // listDrafts
  server.tool(
    'list_drafts',
    'List Gmail drafts (basic info).',
    {
      maxResults: z.number().optional(),
      query: z.string().optional()
    },
    async (args) => {
      try {
        return await listDrafts(args)
      } catch (err: any) {
        return toTextJson({ error: String(err.message) })
      }
    }
  )

  // readDraft
  server.tool(
    'read_draft',
    'Fetch a single draft in full, decode text parts.',
    { draftId: z.string() },
    async ({ draftId }) => {
      try {
        return await readDraft(draftId)
      } catch (err: any) {
        return toTextJson({ error: String(err.message) })
      }
    }
  )

  // draftEmail
  server.tool(
    'draft_email',
    'Create a new draft message',
    {
      to: z.array(z.string()),
      subject: z.string(),
      body: z.string(),
      cc: z.array(z.string()).optional(),
      bcc: z.array(z.string()).optional(),
      isHtml: z.boolean().optional()
    },
    async (args) => {
      try {
        return await draftEmail(args)
      } catch (err: any) {
        return toTextJson({ error: String(err.message) })
      }
    }
  )

  // updateDraft
  server.tool(
    'update_draft',
    'Update an existing draft message',
    {
      draftId: z.string(),
      to: z.array(z.string()),
      subject: z.string(),
      body: z.string(),
      cc: z.array(z.string()).optional(),
      bcc: z.array(z.string()).optional(),
      isHtml: z.boolean().optional()
    },
    async (args) => {
      try {
        return await updateDraft(args)
      } catch (err: any) {
        return toTextJson({ error: String(err.message) })
      }
    }
  )

  // deleteDraft
  server.tool(
    'delete_draft',
    'Delete an existing draft by ID',
    { draftId: z.string() },
    async ({ draftId }) => {
      try {
        return await deleteDraft(draftId)
      } catch (err: any) {
        return toTextJson({ error: String(err.message) })
      }
    }
  )

  // sendEmail
  server.tool(
    'send_email',
    'Send an email (new or existing draft).',
    {
      to: z.array(z.string()),
      subject: z.string(),
      body: z.string(),
      cc: z.array(z.string()).optional(),
      bcc: z.array(z.string()).optional(),
      isHtml: z.boolean().optional(),
      draftId: z.string().optional()
    },
    async (args) => {
      try {
        return await sendEmail(args)
      } catch (err: any) {
        return toTextJson({ error: String(err.message) })
      }
    }
  )

  return server
}

/* ------------------------------------------------------------------
 * SSE vs. stdio
 * ------------------------------------------------------------------ */
interface ServerSession {
  server: McpServer
  transport: SSEServerTransport
}

let machineId: string | null = null

function parseFlyReplaySrc(headerValue: string): Record<string, string> {
  const regex = /(.*?)=(.*?)($|;)/g
  const matches = headerValue.matchAll(regex)
  const result: Record<string, string> = {}
  for (const match of matches) {
    if (match.length >= 3) {
      const key = match[1].trim()
      const value = match[2].trim()
      result[key] = value
    }
  }
  return result
}

function saveMachineId(req: Request) {
  if (machineId) return
  const headerKey = 'fly-replay-src'
  const raw = req.headers[headerKey.toLowerCase()]
  if (!raw || typeof raw !== 'string') return

  try {
    const parsed = parseFlyReplaySrc(raw)
    if (parsed.state) {
      const decoded = decodeURIComponent(parsed.state)
      const obj = JSON.parse(decoded) as { machineId?: string }
      if (obj.machineId) {
        machineId = obj.machineId
      }
    }
  } catch {
    // ignore
  }
}

function main() {
  const argv = yargs(hideBin(process.argv))
    .option('port', { type: 'number', default: 8000 })
    .option('transport', { type: 'string', choices: ['sse', 'stdio'], default: 'sse' })
    .help()
    .parseSync()

  if (argv.transport === 'stdio') {
    const server = createServerWithTools()
    const transport = new StdioServerTransport()
    void server.connect(transport)
    log('Listening on stdio')
    return
  }

  const port = argv.port
  const app = express()
  let sessions: ServerSession[] = []

  // parse JSON only on /message
  app.use((req, res, next) => {
    if (req.path === '/message') return next()
    express.json()(req, res, next)
  })

  app.get('/', async (req: Request, res: Response) => {
    saveMachineId(req)

    const transport = new SSEServerTransport('/message', res)
    const server = createServerWithTools()
    await server.connect(transport)

    sessions.push({ server, transport })
    const sessionId = transport.sessionId
    log(`[${sessionId}] New SSE connection established`)

    transport.onclose = () => {
      log(`[${sessionId}] SSE connection closed`)
      sessions = sessions.filter(s => s.transport !== transport)
    }
    transport.onerror = (err: Error) => {
      logErr(`[${sessionId}] SSE error:`, err)
      sessions = sessions.filter(s => s.transport !== transport)
    }
    req.on('close', () => {
      log(`[${sessionId}] Client disconnected`)
      sessions = sessions.filter(s => s.transport !== transport)
    })
  })

  app.post('/message', async (req: Request, res: Response) => {
    const sessionId = req.query.sessionId as string
    if (!sessionId) {
      res.status(400).send({ error: 'Missing sessionId' })
      return
    }
    const target = sessions.find(s => s.transport.sessionId === sessionId)
    if (!target) {
      res.status(404).send({ error: 'No active session' })
      return
    }
    try {
      await target.transport.handlePostMessage(req, res)
    } catch (err) {
      logErr(`[${sessionId}] Error handling /message:`, err)
      res.status(500).send({ error: 'Internal error' })
    }
  })

  app.listen(port, () => {
    log(`Listening on port ${port} (SSE)`)
  })
}

main()
