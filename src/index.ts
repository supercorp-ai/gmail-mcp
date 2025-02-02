import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js'
import { z } from 'zod'
import { google } from 'googleapis'
import { OAuth2Client } from 'google-auth-library'
import express from 'express'
import yargs from 'yargs'
import { hideBin } from 'yargs/helpers'

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET
const REDIRECT_URI = process.env.REDIRECT_URI

// initialize OAuth2 client (redirect URI required by Google)
const oAuth2Client = new OAuth2Client(
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  REDIRECT_URI
)

// initialize Gmail API client
const gmail = google.gmail({ version: 'v1', auth: oAuth2Client })

// helper: encode an email in base64url format
const encodeEmail = (raw: string): string =>
  Buffer.from(raw)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')

// helper: list latest emails
const readEmails = async (maxResults: number = 10) => {
  console.log(`Reading up to ${maxResults} emails`)
  const res = await gmail.users.messages.list({ userId: 'me', maxResults })
  const messages = res.data.messages || []
  const detailedMessages = await Promise.all(
    messages.map(async msg => {
      const mRes = await gmail.users.messages.get({ userId: 'me', id: msg.id! })
      return mRes.data
    })
  )
  console.log(`Read ${detailedMessages.length} emails`)
  return detailedMessages
}

// helper: search emails by query string
const searchEmails = async (query: string) => {
  console.log(`Searching emails with query: ${query}`)
  const res = await gmail.users.messages.list({ userId: 'me', q: query })
  const messages = res.data.messages || []
  const detailedMessages = await Promise.all(
    messages.map(async msg => {
      const mRes = await gmail.users.messages.get({ userId: 'me', id: msg.id! })
      return mRes.data
    })
  )
  console.log(`Found ${detailedMessages.length} emails for query: ${query}`)
  return detailedMessages
}

// helper: send an email by constructing a raw RFC 2822 message
const sendEmail = async (to: string, subject: string, body: string) => {
  console.log(`Sending email to ${to} with subject: ${subject}`)
  const rawMessage = [
    `To: ${to}`,
    'Content-Type: text/plain; charset=utf-8',
    'MIME-Version: 1.0',
    `Subject: ${subject}`,
    '',
    body
  ].join('\n')
  const raw = encodeEmail(rawMessage)
  const res = await gmail.users.messages.send({
    userId: 'me',
    requestBody: { raw }
  })
  console.log(`Email sent, response: ${JSON.stringify(res.data)}`)
  return res.data
}

// auth tool: returns the authorization URL for the user to visit
const getAuthUrl = (): string =>
  oAuth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: [
      'https://www.googleapis.com/auth/gmail.send',
      'https://www.googleapis.com/auth/gmail.readonly'
    ]
  })

// auth tool: exchanges an auth code for tokens and returns the refresh token
const exchangeAuthCode = async (code: string) => {
  console.log(`Exchanging auth code: ${code}`)
  const { tokens } = await oAuth2Client.getToken(code.trim())
  if (tokens.refresh_token) {
    oAuth2Client.setCredentials(tokens)
    console.log('Exchange successful, refresh token obtained')
    return tokens.refresh_token
  }
  else {
    console.error('No refresh token returned during auth code exchange')
    throw new Error('No refresh token returned')
  }
}

const server = new McpServer({ name: '@supercorp/mcp-server-gmail', version: '1.0.0' })

// expose auth tools as MCP tools
server.tool(
  'getAuthUrl',
  {},
  async (_args, _extra) => {
    const url = getAuthUrl()
    console.log(`Tool getAuthUrl called, returning URL: ${url}`)
    return {
      content: [{ type: 'text', text: url }]
    }
  }
)

server.tool(
  'exchangeAuthCode',
  { code: z.string() },
  async ({ code }, _extra) => {
    const refreshToken = await exchangeAuthCode(code)
    console.log(`Tool exchangeAuthCode called, returning refresh token`)
    return {
      content: [{ type: 'text', text: `Refresh Token: ${refreshToken}` }]
    }
  }
)

// expose Gmail tools
server.tool(
  'readEmails',
  { maxResults: z.number().optional() },
  async ({ maxResults }, _extra) => {
    const emails = await readEmails(maxResults ?? 10)
    return {
      content: [{ type: 'text', text: JSON.stringify(emails, null, 2) }]
    }
  }
)

server.tool(
  'searchEmails',
  { query: z.string() },
  async ({ query }, _extra) => {
    const emails = await searchEmails(query)
    return {
      content: [{ type: 'text', text: JSON.stringify(emails, null, 2) }]
    }
  }
)

server.tool(
  'sendEmail',
  { to: z.string(), subject: z.string(), body: z.string() },
  async ({ to, subject, body }, _extra) => {
    const result = await sendEmail(to, subject, body)
    return {
      content: [{ type: 'text', text: JSON.stringify(result, null, 2) }]
    }
  }
)

// parse CLI arguments using yargs (default port 4010, transport default stdio)
const argv = yargs(hideBin(process.argv))
  .option('transport', {
    alias: 't',
    type: 'string',
    choices: ['stdio', 'sse'],
    description: 'Transport type (stdio or sse)',
    default: 'stdio'
  })
  .option('port', {
    alias: 'p',
    type: 'number',
    description: 'Port number for SSE transport (if transport is sse)',
    default: 4010
  })
  .help()
  .argv as { transport: 'stdio' | 'sse', port: number }

const main = async () => {
  console.log(`Starting MCP server with transport: ${argv.transport}`)
  if (argv.transport === 'stdio') {
    const transport = new StdioServerTransport()
    console.log('Using stdio transport')
    await server.connect(transport)
    console.log('MCP server connected via stdio')
  }
  else if (argv.transport === 'sse') {
    const app = express()
    app.use(express.json())
    let sseTransport: SSEServerTransport | null = null
    // GET on root ("/") to establish SSE connection
    app.get('/', async (_req, res) => {
      console.log('Received GET request for SSE connection')
      sseTransport = new SSEServerTransport('/', res)
      await server.connect(sseTransport)
      console.log('MCP server connected via SSE')
    })
    // POST on root ("/") to forward client messages
    app.post('/', async (req, res) => {
      console.log('Received POST message on SSE endpoint')
      console.log('Request headers:', req.headers)
      console.log('Request body:', req.body)
      try {
        if (sseTransport) {
          await sseTransport.handlePostMessage(req, res)
          console.log('Handled POST message successfully')
        } else {
          console.error('No SSE connection established')
          res.status(400).send('No SSE connection established')
        }
      } catch (err) {
        console.error('Error handling POST message:', err)
        res.status(400).send('Bad Request: ' + err)
      }
    })
    app.listen(argv.port, () => {
      console.log(`SSE MCP server listening on port ${argv.port}`)
    })
  }
}

main().catch(err => {
  console.error('Error running MCP Gmail server:', err)
  process.exit(1)
})
