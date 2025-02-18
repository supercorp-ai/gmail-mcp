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

// -------------------------------
// Logging
// -------------------------------
const log = (...args: any[]) => console.log('[gmail-mcp]', ...args)
const logErr = (...args: any[]) => console.error('[gmail-mcp]', ...args)

// -------------------------------
// OAuth Setup
// -------------------------------
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

// -------------------------------
// HTML to Markdown conversion using Unified
// -------------------------------

// Custom plugin to drop unsupported nodes
const dropUnsupportedNodes = () => {
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
      if (node && node.tagName && !whitelist.has(node.tagName)) {
        if (parent && Array.isArray(parent.children)) {
          parent.children.splice(index, 1)
          return SKIP
        }
      }
    })
  }
}

const convertHtmlToMarkdown = (html: string) => {
  const file = unified()
    .use(rehypeParse, { fragment: true })
    .use(dropUnsupportedNodes)
    .use(rehypeRemark)
    .use(remarkGfm)
    .use(remarkStringify)
    .processSync(html)
  return String(file)
}

// -------------------------------
// Additional cleanup: remove HTML comments and collapse excessive newlines
// -------------------------------
const cleanMarkdown = (markdown: string): string => {
  let cleaned = markdown.replace(/<!--[\s\S]*?-->/g, '')
  cleaned = cleaned.replace(/\n{3,}/g, '\n\n')
  return cleaned.trim()
}

// -------------------------------
// Helpers to extract only important info from messages/drafts
// -------------------------------
const getHeaderValue = (headers: any[], name: string) =>
  headers.find(h => h.name.toLowerCase() === name.toLowerCase())?.value || ''

const decodeBase64Url = (encoded: string): string => {
  const base64 = encoded.replace(/-/g, '+').replace(/_/g, '/')
  return Buffer.from(base64, 'base64').toString('utf8')
}

const collectParts = (payload?: gmail_v1.Schema$MessagePart): { mimeType?: string; text: string }[] => {
  if (!payload) return []
  let results: { mimeType?: string; text: string }[] = []
  if (payload.body?.data && (payload.mimeType?.startsWith('text/') || payload.mimeType === 'text/html')) {
    results.push({
      mimeType: payload.mimeType,
      text: decodeBase64Url(payload.body.data)
    })
  }
  if (payload.parts) {
    for (const part of payload.parts) {
      results.push(...collectParts(part))
    }
  }
  return results
}

const extractImportantInfo = (message: gmail_v1.Schema$Message) => {
  const headers = message.payload?.headers || []
  const subject = getHeaderValue(headers, 'Subject')
  const from = getHeaderValue(headers, 'From')
  const to = getHeaderValue(headers, 'To')
  const cc = getHeaderValue(headers, 'Cc')
  const bcc = getHeaderValue(headers, 'Bcc')
  const parts = collectParts(message.payload)
  const htmlPart = parts.find(p => p.mimeType && p.mimeType.startsWith('text/html'))
  let body = htmlPart ? convertHtmlToMarkdown(htmlPart.text) : ''
  if (body) {
    body = cleanMarkdown(body)
  } else {
    const textPart = parts.find(p => p.mimeType && p.mimeType.startsWith('text/'))
    body = textPart ? cleanMarkdown(textPart.text) : ''
  }
  return {
    messageId: message.id,
    threadId: message.threadId,
    subject,
    from,
    to,
    cc,
    bcc,
    body
  }
}

// -------------------------------
// MCP-friendly JSON response
// -------------------------------
const toTextJson = (data: unknown) => ({
  content: [
    {
      type: 'text' as const,
      text: JSON.stringify(data, null, 2)
    }
  ]
})

// -------------------------------
// (1) getAuthUrl / (2) exchangeAuthCode
// -------------------------------
const getAuthUrl = (): string => {
  const SCOPES = [
    'https://www.googleapis.com/auth/gmail.send',
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/gmail.compose',
    'https://www.googleapis.com/auth/gmail.modify'
  ]
  return oauth2Client.generateAuthUrl({
    access_type: 'offline',
    prompt: 'consent',
    scope: SCOPES,
    state: STATE,
  })
}

const exchangeAuthCode = async (code: string): Promise<string> => {
  log(`Exchanging auth code: ${code}`)
  const { tokens } = await oauth2Client.getToken(code.trim())
  if (!tokens.refresh_token) {
    throw new Error('No refresh token returned by Google.')
  }
  oauth2Client.setCredentials(tokens)
  log('Exchange successful, refresh token obtained.')
  return tokens.refresh_token
}

// -------------------------------
// (3) listEmails (with snippet, pageToken for pagination)
// -------------------------------
interface ListEmailsArgs {
  maxResults?: number
  labelIds?: string[]
  query?: string
  pageToken?: string
  unreadOnly?: boolean
}

const listEmails = async (args: ListEmailsArgs) => {
  const { maxResults = 10, labelIds, query, pageToken, unreadOnly = false } = args
  const q = [query, unreadOnly ? 'is:unread' : null].filter(Boolean).join(' ')
  const resp = await gmail.users.messages.list({
    userId: 'me',
    maxResults,
    labelIds,
    pageToken,
    ...(q && { q })
  })
  if (resp.data.messages) {
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
  return toTextJson(resp.data)
}

// -------------------------------
// (4) readEmail: full message + decode and simplify key fields
// -------------------------------
const readEmail = async (messageId: string) => {
  const resp = await gmail.users.messages.get({
    userId: 'me',
    id: messageId,
    format: 'full'
  })
  const result = resp.data.payload ? extractImportantInfo(resp.data) : { error: 'No payload found' }
  return toTextJson(result)
}

// -------------------------------
// Draft tools: listDrafts, readDraft, draftEmail, updateDraft, deleteDraft
// -------------------------------
interface ListDraftsArgs {
  maxResults?: number
  query?: string
}

const listDrafts = async ({ maxResults = 10, query }: ListDraftsArgs) => {
  const q = query ?? ''
  const resp = await gmail.users.drafts.list({
    userId: 'me',
    maxResults,
    q
  })
  return toTextJson(resp.data)
}

const readDraft = async (draftId: string) => {
  const resp = await gmail.users.drafts.get({
    userId: 'me',
    id: draftId,
    format: 'full'
  })
  const result = resp.data.message?.payload ? extractImportantInfo(resp.data.message) : { error: 'No payload found' }
  return toTextJson(result)
}

// -------------------------------
// Retrieve the default sender from the authenticated user's profile
// -------------------------------
let cachedDefaultSender: string | null = null
const getDefaultSender = async (): Promise<string> => {
  if (cachedDefaultSender) return cachedDefaultSender
  const profile = await gmail.users.getProfile({ userId: 'me' })
  if (!profile.data.emailAddress) throw new Error('Could not retrieve default sender from profile.')
  cachedDefaultSender = profile.data.emailAddress
  return cachedDefaultSender
}

// -------------------------------
// Utility: build raw base64 encoded email with required sender
// -------------------------------
// buildMimeMessage is now asynchronous because it may need to fetch the default sender
const buildMimeMessage = async ({
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
}): Promise<string> => {
  const actualSender = sender || await getDefaultSender()
  if (!actualSender) throw new Error('The "From" header is required.')
  const msg = createMimeMessage()
  msg.setSender(actualSender)
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
  const raw = msg.asEncoded()
  return raw.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

interface DraftEmailArgs {
  sender?: string
  to: string[]
  cc?: string[]
  bcc?: string[]
  subject: string
  body: string
  isHtml?: boolean
}

const draftEmail = async (args: DraftEmailArgs) => {
  const raw = await buildMimeMessage(args)
  const resp = await gmail.users.drafts.create({
    userId: 'me',
    requestBody: {
      message: { raw }
    }
  })
  return toTextJson(resp.data)
}

interface UpdateDraftArgs extends DraftEmailArgs {
  draftId: string
}

const updateDraft = async (args: UpdateDraftArgs) => {
  const { draftId, ...rest } = args
  const raw = await buildMimeMessage(rest)
  const resp = await gmail.users.drafts.update({
    userId: 'me',
    id: draftId,
    requestBody: {
      message: { raw }
    }
  })
  return toTextJson(resp.data)
}

const deleteDraft = async (draftId: string) => {
  await gmail.users.drafts.delete({
    userId: 'me',
    id: draftId
  })
  return toTextJson({ success: true, deletedDraftId: draftId })
}

interface SendEmailArgs extends DraftEmailArgs {
  draftId?: string
}

const sendEmail = async (args: SendEmailArgs) => {
  const { draftId, ...rest } = args
  if (draftId) {
    const resp = await gmail.users.drafts.send({
      userId: 'me',
      requestBody: { id: draftId }
    })
    return toTextJson(resp.data)
  }
  const raw = await buildMimeMessage(rest)
  const resp = await gmail.users.messages.send({
    userId: 'me',
    requestBody: { raw }
  })
  return toTextJson(resp.data)
}

// -------------------------------
// Create MCP Server with all tools
// -------------------------------
const createServerWithTools = (): McpServer => {
  const server = new McpServer({
    name: 'Gmail MCP Server',
    version: '1.0.0'
  })

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

  server.tool(
    'read_email',
    'Fetch a single message in full, decode and simplify key fields.',
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

  server.tool(
    'read_draft',
    'Fetch a single draft in full, decode and simplify key fields.',
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
    'Create a new draft message',
    {
      sender: z.string(),
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

  server.tool(
    'update_draft',
    'Update an existing draft message',
    {
      draftId: z.string(),
      sender: z.string(),
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

  server.tool(
    'send_email',
    'Send an email (new or existing draft).',
    {
      sender: z.string(),
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

// -------------------------------
// Helpers for fly replay headers and machine ID
// -------------------------------
const parseFlyReplaySrc = (headerValue: string): Record<string, string> => {
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

const saveMachineId = (req: Request) => {
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

// -------------------------------
// Server setup: SSE vs stdio
// -------------------------------
interface ServerSession {
  server: McpServer
  transport: SSEServerTransport
}

const main = () => {
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
