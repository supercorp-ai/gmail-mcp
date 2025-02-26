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
import { createMimeMessage } from 'mimetext'
import { unified } from 'unified'
import rehypeParse from 'rehype-parse'
import rehypeRemark from 'rehype-remark'
import remarkGfm from 'remark-gfm'
import remarkStringify from 'remark-stringify'
import { visit, SKIP } from 'unist-util-visit'

// --------------------------------------------------------------------
// 1) Parse CLI options
// --------------------------------------------------------------------
const argv = yargs(hideBin(process.argv))
  .option('port', { type: 'number', default: 8000 })
  .option('transport', { type: 'string', choices: ['sse', 'stdio'], default: 'sse' })
  .option('send-only', {
    type: 'boolean',
    default: false,
    describe: 'Only use https://www.googleapis.com/auth/gmail.send scope and expose only send_email'
  })
  .help()
  .parseSync()

const log = (...args: any[]) => console.log('[gmail-mcp]', ...args)
const logErr = (...args: any[]) => console.error('[gmail-mcp]', ...args)

const sendOnly = argv['send-only']

// --------------------------------------------------------------------
// 2) Determine scopes
// --------------------------------------------------------------------
const SCOPES = sendOnly
  ? [ 'https://www.googleapis.com/auth/gmail.send' ]
  : [
      'https://www.googleapis.com/auth/gmail.send',
      'https://www.googleapis.com/auth/gmail.readonly',
      'https://www.googleapis.com/auth/gmail.compose',
      'https://www.googleapis.com/auth/gmail.modify'
    ]

// --------------------------------------------------------------------
// 3) Setup OAuth and Gmail
// --------------------------------------------------------------------
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

// --------------------------------------------------------------------
// 4) Helpers (HTML-to-Markdown, building raw messages, etc.)
// --------------------------------------------------------------------
function dropUnsupportedNodes() {
  const whitelist = new Set([
    'html', 'head', 'body',
    'p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'em', 'strong', 'a', 'blockquote',
    'ul', 'ol', 'li',
    'table', 'thead', 'tbody', 'tr', 'th', 'td',
    'pre', 'code',
    'img', 'br', 'hr',
    'div', 'span'
  ])
  return (tree: any) => {
    visit(tree, 'element', (node, index, parent) => {
      if (node?.tagName && !whitelist.has(node.tagName)) {
        parent?.children?.splice(index, 1)
        return SKIP
      }
    })
  }
}

function convertHtmlToMarkdown(html: string): string {
  const file = unified()
    .use(rehypeParse, { fragment: true })
    .use(dropUnsupportedNodes)
    .use(rehypeRemark)
    .use(remarkGfm)
    .use(remarkStringify)
    .processSync(html)
  return String(file)
}

function cleanMarkdown(markdown: string): string {
  let cleaned = markdown.replace(/<!--[\s\S]*?-->/g, '')
  cleaned = cleaned.replace(/\n{3,}/g, '\n\n')
  return cleaned.trim()
}

function decodeBase64Url(encoded: string): string {
  const base64 = encoded.replace(/-/g, '+').replace(/_/g, '/')
  return Buffer.from(base64, 'base64').toString('utf8')
}

/**
 * Grab a particular header's value, ignoring case for the name.
 */
function getHeaderValue(
  headers: gmail_v1.Schema$MessagePartHeader[] | undefined,
  headerName: string
): string {
  if (!headers) return ''
  const found = headers.find(h => h.name?.toLowerCase() === headerName.toLowerCase())
  return found?.value || ''
}

let cachedDefaultSender: string | null = null
async function getDefaultSender(): Promise<string> {
  if (cachedDefaultSender) return cachedDefaultSender
  const profile = await gmail.users.getProfile({ userId: 'me' })
  if (!profile.data.emailAddress) throw new Error('No default sender found in profile.')
  cachedDefaultSender = profile.data.emailAddress
  return cachedDefaultSender
}

async function buildMimeMessage({
  sender,
  to,
  cc,
  bcc,
  subject,
  body,
  isHtml
}: {
  sender?: string
  to: string[]
  cc?: string[]
  bcc?: string[]
  subject: string
  body: string
  isHtml?: boolean
}): Promise<string> {
  const actualSender = sender || await getDefaultSender()
  const msg = createMimeMessage()
  msg.setSender(actualSender)
  msg.setTo(to)
  if (cc) msg.setCc(cc)
  if (bcc) msg.setBcc(bcc)
  msg.setSubject(subject)
  msg.addMessage({
    contentType: isHtml ? 'text/html' : 'text/plain',
    data: body
  })
  // Gmail raw format must be Base64URL. Mimetext uses standard base64 => convert
  const raw = msg.asEncoded()
  return raw
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
}

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

// --------------------------------------------------------------------
// 5) All methods that might be used (list, read, draft, send, etc.)
// --------------------------------------------------------------------

// -- Only used if not sendOnly --
async function listEmails(args: {
  maxResults?: number
  labelIds?: string[]
  query?: string
  pageToken?: string
  unreadOnly?: boolean
}) {
  const { maxResults = 10, labelIds, query, pageToken, unreadOnly = false } = args
  const q = [query, unreadOnly ? 'is:unread' : null].filter(Boolean).join(' ')
  const resp = await gmail.users.messages.list({
    userId: 'me',
    maxResults,
    labelIds,
    pageToken,
    ...(q && { q })
  })

  if (!resp.data.messages) {
    return toTextJson(resp.data)
  }

  // Optionally get partial metadata about each message (Subject, From, To, snippet)
  const enriched = []
  for (const m of resp.data.messages) {
    const detail = await gmail.users.messages.get({
      userId: 'me',
      id: m.id!,
      format: 'metadata',
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

async function readEmail(messageId: string) {
  const resp = await gmail.users.messages.get({
    userId: 'me',
    id: messageId,
    format: 'full'
  })
  if (!resp.data.payload) {
    return toTextJson({ error: 'No payload' })
  }

  const headers = resp.data.payload.headers
  const subject = getHeaderValue(headers, 'subject')
  const from    = getHeaderValue(headers, 'from')
  const to      = getHeaderValue(headers, 'to')

  // We can gather any text parts
  const parts: { mimeType?: string; text: string }[] = []
  function traverse(p?: gmail_v1.Schema$MessagePart) {
    if (!p) return
    if (p.body?.data && p.mimeType?.startsWith('text/')) {
      parts.push({ mimeType: p.mimeType, text: decodeBase64Url(p.body.data) })
    }
    p.parts?.forEach(traverse)
  }
  traverse(resp.data.payload)

  const html = parts.find(p => p.mimeType === 'text/html')?.text
  const body = html
    ? cleanMarkdown(convertHtmlToMarkdown(html))
    : (parts.find(p => p.mimeType === 'text/plain')?.text ?? '')

  return toTextJson({ messageId, subject, from, to, body })
}

async function listDrafts({ maxResults = 10, query = '' }: { maxResults?: number; query?: string }) {
  const resp = await gmail.users.drafts.list({
    userId: 'me',
    maxResults,
    q: query
  })
  return toTextJson(resp.data)
}

async function readDraft(draftId: string) {
  // We can reuse readEmail to parse the payload, but first get the draft
  const resp = await gmail.users.drafts.get({
    userId: 'me',
    id: draftId,
    format: 'full'
  })
  if (!resp.data.message?.id) {
    return toTextJson({ error: 'No message in draft' })
  }
  // Now fetch the message details with readEmail
  return readEmail(resp.data.message.id)
}

async function draftEmail(args: {
  sender?: string
  to: string[]
  cc?: string[]
  bcc?: string[]
  subject: string
  body: string
  isHtml?: boolean
}) {
  const raw = await buildMimeMessage(args)
  const resp = await gmail.users.drafts.create({
    userId: 'me',
    requestBody: { message: { raw } }
  })
  return toTextJson(resp.data)
}

async function updateDraft(args: {
  draftId: string
  sender?: string
  to: string[]
  cc?: string[]
  bcc?: string[]
  subject: string
  body: string
  isHtml?: boolean
}) {
  const { draftId, ...rest } = args
  const raw = await buildMimeMessage(rest)
  const resp = await gmail.users.drafts.update({
    userId: 'me',
    id: draftId,
    requestBody: { message: { raw } }
  })
  return toTextJson(resp.data)
}

async function deleteDraft(draftId: string) {
  await gmail.users.drafts.delete({ userId: 'me', id: draftId })
  return toTextJson({ success: true, deletedDraftId: draftId })
}

/**
 * If a `draftId` is provided, it sends that existing draft.
 * Otherwise, it builds a new raw message and sends that directly.
 */
async function sendEmailFull(args: {
  sender?: string
  to: string[]
  cc?: string[]
  bcc?: string[]
  subject: string
  body: string
  isHtml?: boolean
  draftId?: string
}) {
  if (args.draftId) {
    // Send existing draft
    const resp = await gmail.users.drafts.send({
      userId: 'me',
      requestBody: { id: args.draftId }
    })
    return toTextJson(resp.data)
  }
  // Build a brand-new message
  const raw = await buildMimeMessage(args)
  const resp = await gmail.users.messages.send({
    userId: 'me',
    requestBody: { raw }
  })
  return toTextJson(resp.data)
}

/**
 * In "send-only" mode (gmail.send scope), we can't deal with drafts.
 * So this always builds a fresh message.
 */
async function sendEmailOnly(args: {
  sender?: string
  to: string[]
  cc?: string[]
  bcc?: string[]
  subject: string
  body: string
  isHtml?: boolean
}) {
  const raw = await buildMimeMessage(args)
  const resp = await gmail.users.messages.send({
    userId: 'me',
    requestBody: { raw }
  })
  return toTextJson(resp.data)
}

// --------------------------------------------------------------------
// 6) OAuth Tools
// --------------------------------------------------------------------
function getAuthUrl(): string {
  return oauth2Client.generateAuthUrl({
    access_type: 'offline',
    prompt: 'consent',
    scope: SCOPES,
    state: STATE
  })
}

async function exchangeAuthCode(code: string): Promise<string> {
  log(`Exchanging code: ${code}`)
  const { tokens } = await oauth2Client.getToken(code.trim())
  if (!tokens.refresh_token) {
    throw new Error('No refresh token returned by Google.')
  }
  oauth2Client.setCredentials(tokens)
  return tokens.refresh_token
}

// --------------------------------------------------------------------
// 7) Create the MCP server, conditionally registering tools
// --------------------------------------------------------------------
function createMcpServer(sendOnly: boolean): McpServer {
  const server = new McpServer({
    name: sendOnly ? 'Gmail MCP Server (Send-Only)' : 'Gmail MCP Server',
    version: '1.0.0'
  })

  // Always at least `send_email` in some form:
  if (sendOnly) {
    server.tool(
      'send_email',
      'Send an email using only the gmail.send scope (no draftId).',
      {
        sender: z.string().optional(),
        to: z.array(z.string()),
        cc: z.array(z.string()).optional(),
        bcc: z.array(z.string()).optional(),
        subject: z.string(),
        body: z.string(),
        isHtml: z.boolean().optional()
      },
      async (args) => {
        try {
          return await sendEmailOnly(args)
        } catch (err: any) {
          return toTextJson({ error: String(err.message) })
        }
      }
    )
    return server
  }

  // If NOT sendOnly, register everything
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

  server.tool(
    'exchange_auth_code',
    'Exchange an auth code for a refresh token',
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

  server.tool(
    'list_emails',
    'List Gmail messages with snippet (supports pagination, etc.)',
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

  server.tool(
    'read_email',
    'Fetch a single message in full, convert HTML to Markdown, etc.',
    { messageId: z.string() },
    async ({ messageId }) => {
      try {
        return await readEmail(messageId)
      } catch (err: any) {
        return toTextJson({ error: String(err.message) })
      }
    }
  )

  server.tool(
    'list_drafts',
    'List Gmail drafts.',
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

  server.tool(
    'read_draft',
    'Fetch a single draft in full.',
    { draftId: z.string() },
    async ({ draftId }) => {
      try {
        return await readDraft(draftId)
      } catch (err: any) {
        return toTextJson({ error: String(err.message) })
      }
    }
  )

  server.tool(
    'draft_email',
    'Create a new draft',
    {
      sender: z.string().optional(),
      to: z.array(z.string()),
      cc: z.array(z.string()).optional(),
      bcc: z.array(z.string()).optional(),
      subject: z.string(),
      body: z.string(),
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

  server.tool(
    'update_draft',
    'Update an existing draft',
    {
      draftId: z.string(),
      sender: z.string().optional(),
      to: z.array(z.string()).optional(),
      cc: z.array(z.string()).optional(),
      bcc: z.array(z.string()).optional(),
      subject: z.string(),
      body: z.string(),
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

  server.tool(
    'delete_draft',
    'Delete a draft',
    { draftId: z.string() },
    async ({ draftId }) => {
      try {
        return await deleteDraft(draftId)
      } catch (err: any) {
        return toTextJson({ error: String(err.message) })
      }
    }
  )

  server.tool(
    'send_email',
    'Send an email (new or existing draft).',
    {
      sender: z.string().optional(),
      to: z.array(z.string()),
      cc: z.array(z.string()).optional(),
      bcc: z.array(z.string()).optional(),
      subject: z.string(),
      body: z.string(),
      isHtml: z.boolean().optional(),
      draftId: z.string().optional()
    },
    async (args) => {
      try {
        return await sendEmailFull(args)
      } catch (err: any) {
        return toTextJson({ error: String(err.message) })
      }
    }
  )

  return server
}

// --------------------------------------------------------------------
// 8) Minimal Fly.io "replay" handling (optional).
// --------------------------------------------------------------------
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
let machineId: string | null = null
function saveMachineId(req: Request) {
  if (machineId) return
  const headerKey = 'fly-replay-src'
  const raw = req.headers[headerKey.toLowerCase()]
  if (!raw || typeof raw !== 'string') return
  try {
    const parsed = parseFlyReplaySrc(raw)
    if (parsed.state) {
      const decoded = decodeURIComponent(parsed.state)
      const obj = JSON.parse(decoded)
      if (obj.machineId) machineId = obj.machineId
    }
  } catch {
    // ignore
  }
}

// --------------------------------------------------------------------
// 9) Main: Start either SSE or stdio server
// --------------------------------------------------------------------
function main() {
  const server = createMcpServer(sendOnly)

  if (argv.transport === 'stdio') {
    // STDIO transport
    const transport = new StdioServerTransport()
    void server.connect(transport)
    log('Listening on stdio')
    return
  }

  // Otherwise SSE server
  const port = argv.port
  const app = express()
  let sessions: { server: McpServer; transport: SSEServerTransport }[] = []

  // We'll only parse JSON for requests other than /message
  app.use((req, res, next) => {
    if (req.path === '/message') return next()
    express.json()(req, res, next)
  })

  // SSE connect
  app.get('/', async (req: Request, res: Response) => {
    saveMachineId(req)
    const transport = new SSEServerTransport('/message', res)
    const mcpInstance = createMcpServer(sendOnly)
    await mcpInstance.connect(transport)
    sessions.push({ server: mcpInstance, transport })

    const sessionId = transport.sessionId
    log(`[${sessionId}] SSE connection established`)

    transport.onclose = () => {
      log(`[${sessionId}] SSE closed`)
      sessions = sessions.filter(s => s.transport !== transport)
    }
    transport.onerror = (err: Error) => {
      logErr(`[${sessionId}] SSE error:`, err)
      sessions = sessions.filter(s => s.transport !== transport)
    }
    req.on('close', () => {
      log(`[${sessionId}] SSE client disconnected`)
      sessions = sessions.filter(s => s.transport !== transport)
    })
  })

  // SSE incoming messages
  app.post('/message', async (req: Request, res: Response) => {
    const sessionId = req.query.sessionId as string
    if (!sessionId) {
      logErr('Missing sessionId')
      res.status(400).send({ error: 'Missing sessionId' })
      return
    }
    const target = sessions.find(s => s.transport.sessionId === sessionId)
    if (!target) {
      logErr(`No active session for sessionId=${sessionId}`)
      res.status(404).send({ error: 'No active session' })
      return
    }
    try {
      await target.transport.handlePostMessage(req, res)
    } catch (err: any) {
      logErr(`[${sessionId}] Error handling /message:`, err)
      res.status(500).send({ error: 'Internal error' })
    }
  })

  app.listen(port, () => {
    log(`Listening on port ${port} (${argv.transport})${sendOnly ? ' [SEND-ONLY MODE]' : ''}`)
  })
}

main()
