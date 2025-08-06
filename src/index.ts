#!/usr/bin/env node

import { hideBin } from 'yargs/helpers'
import yargs from 'yargs'
import express, { Request, Response as ExpressResponse } from 'express'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js'
import { InMemoryEventStore } from '@modelcontextprotocol/sdk/examples/shared/inMemoryEventStore.js'
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
import { Redis } from '@upstash/redis'
import { randomUUID } from 'node:crypto'

// --------------------------------------------------------------------
// Helper: JSON Response Formatter
// --------------------------------------------------------------------
function toTextJson(data: unknown): { content: Array<{ type: 'text'; text: string }> } {
  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify(data, null, 2)
      }
    ]
  };
}

// --------------------------------------------------------------------
// Configuration & Storage Interface
// --------------------------------------------------------------------
interface Config {
  port: number;
  transport: 'sse' | 'stdio' | 'http';
  storage: 'memory-single' | 'memory' | 'upstash-redis-rest';
  googleClientId: string;
  googleClientSecret: string;
  googleRedirectUri: string;
  sendOnly: boolean;
  googleState?: string;
  storageHeaderKey?: string;
  upstashRedisRestUrl?: string;
  upstashRedisRestToken?: string;
}

interface Storage {
  get(memoryKey: string): Promise<Record<string, any> | undefined>;
  set(memoryKey: string, data: Record<string, any>): Promise<void>;
}

// --------------------------------------------------------------------
// In-Memory Storage Implementation
// --------------------------------------------------------------------
class MemoryStorage implements Storage {
  private storage: Record<string, Record<string, any>> = {};

  async get(memoryKey: string) {
    return this.storage[memoryKey];
  }

  async set(memoryKey: string, data: Record<string, any>) {
    this.storage[memoryKey] = { ...this.storage[memoryKey], ...data };
  }
}

// --------------------------------------------------------------------
// Upstash Redis Storage Implementation
// --------------------------------------------------------------------
class RedisStorage implements Storage {
  private redis: Redis;
  private keyPrefix: string;

  constructor(redisUrl: string, redisToken: string, keyPrefix: string) {
    this.redis = new Redis({ url: redisUrl, token: redisToken });
    this.keyPrefix = keyPrefix;
  }

  async get(memoryKey: string): Promise<Record<string, any> | undefined> {
    const data = await this.redis.get(`${this.keyPrefix}:${memoryKey}`);
    if (data === null) return undefined;
    if (typeof data === 'string') {
      try { return JSON.parse(data); } catch { return undefined; }
    }
    return data as any;
  }

  async set(memoryKey: string, data: Record<string, any>) {
    const existing = (await this.get(memoryKey)) || {};
    const newData = { ...existing, ...data };
    await this.redis.set(`${this.keyPrefix}:${memoryKey}`, JSON.stringify(newData));
  }
}

// --------------------------------------------------------------------
// Gmail OAuth & API Helpers
// --------------------------------------------------------------------
function getScopes(sendOnly: boolean): string[] {
  return sendOnly
    ? [ 'https://www.googleapis.com/auth/gmail.send' ]
    : [
        'https://www.googleapis.com/auth/gmail.send',
        'https://www.googleapis.com/auth/gmail.readonly',
        'https://www.googleapis.com/auth/gmail.compose',
        'https://www.googleapis.com/auth/gmail.modify'
      ];
}

async function createOAuth2Client(config: Config, storage: Storage, memoryKey: string): Promise<OAuth2Client> {
  const client = new OAuth2Client(config.googleClientId, config.googleClientSecret, config.googleRedirectUri);
  const stored = await storage.get(memoryKey);
  if (stored && stored.refreshToken) {
    client.setCredentials({ refresh_token: stored.refreshToken });
  }
  return client;
}

async function getGmailClient(config: Config, storage: Storage, memoryKey: string): Promise<gmail_v1.Gmail> {
  const oauth2Client = await createOAuth2Client(config, storage, memoryKey);
  return google.gmail({ version: 'v1', auth: oauth2Client });
}

function getAuthUrl(config: Config, memoryKey: string, storage: Storage): string {
  const client = new OAuth2Client(config.googleClientId, config.googleClientSecret, config.googleRedirectUri);
  const scopes = getScopes(config.sendOnly);
  return client.generateAuthUrl({
    access_type: 'offline',
    prompt: 'consent',
    scope: scopes,
    state: config.googleState
  });
}

async function exchangeAuthCode(code: string, config: Config, storage: Storage, memoryKey: string): Promise<string> {
  const client = new OAuth2Client(config.googleClientId, config.googleClientSecret, config.googleRedirectUri);
  const { tokens } = await client.getToken(code.trim());
  if (!tokens.refresh_token) {
    throw new Error('No refresh token returned by Google.');
  }
  client.setCredentials(tokens);
  await storage.set(memoryKey, { refreshToken: tokens.refresh_token, accessToken: tokens.access_token });
  return tokens.refresh_token;
}

// --------------------------------------------------------------------
// HTML/Markdown Helpers
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
  ]);
  return (tree: any) => {
    visit(tree, 'element', (node, index, parent) => {
      if (node?.tagName && !whitelist.has(node.tagName)) {
        parent?.children?.splice(index, 1);
        return SKIP;
      }
    });
  };
}

function convertHtmlToMarkdown(html: string): string {
  const file = unified()
    .use(rehypeParse, { fragment: true })
    .use(dropUnsupportedNodes)
    .use(rehypeRemark)
    .use(remarkGfm)
    .use(remarkStringify)
    .processSync(html);
  return String(file);
}

function cleanMarkdown(markdown: string): string {
  let cleaned = markdown.replace(/<!--[\s\S]*?-->/g, '');
  cleaned = cleaned.replace(/\n{3,}/g, '\n\n');
  return cleaned.trim();
}

function decodeBase64Url(encoded: string): string {
  const base64 = encoded.replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(base64, 'base64').toString('utf8');
}

function getHeaderValue(
  headers: gmail_v1.Schema$MessagePartHeader[] | undefined,
  headerName: string
): string {
  if (!headers) return '';
  const found = headers.find(h => h.name?.toLowerCase() === headerName.toLowerCase());
  return found?.value || '';
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
  sender: string;
  to: string[];
  cc?: string[];
  bcc?: string[];
  subject: string;
  body: string;
  isHtml?: boolean;
}): Promise<string> {
  const msg = createMimeMessage();
  msg.setSender(sender);
  msg.setTo(to);
  if (cc) msg.setCc(cc);
  if (bcc) msg.setBcc(bcc);
  msg.setSubject(subject);
  msg.addMessage({
    contentType: isHtml ? 'text/html' : 'text/plain',
    data: body
  });
  const raw = msg.asEncoded();
  return raw.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// --------------------------------------------------------------------
// Gmail API Methods
// --------------------------------------------------------------------
async function listEmails(args: {
  maxResults?: number;
  labelIds?: string[];
  query?: string;
  pageToken?: string;
  unreadOnly?: boolean;
}, config: Config, storage: Storage, memoryKey: string) {
  const gmail = await getGmailClient(config, storage, memoryKey);
  const { maxResults = 10, labelIds, query, pageToken, unreadOnly = false } = args;
  const q = [query, unreadOnly ? 'is:unread' : null].filter(Boolean).join(' ');
  const resp = await gmail.users.messages.list({
    userId: 'me',
    maxResults,
    labelIds,
    pageToken,
    ...(q && { q })
  });
  if (!resp.data.messages) {
    return toTextJson(resp.data);
  }
  const enriched = [];
  for (const m of resp.data.messages) {
    const detail = await gmail.users.messages.get({
      userId: 'me',
      id: m.id!,
      format: 'metadata',
      metadataHeaders: ['Subject', 'From', 'To']
    });
    enriched.push({
      id: detail.data.id,
      threadId: detail.data.threadId,
      snippet: detail.data.snippet,
      headers: detail.data.payload?.headers
    });
  }
  return toTextJson({
    nextPageToken: resp.data.nextPageToken,
    resultSizeEstimate: resp.data.resultSizeEstimate,
    messages: enriched
  });
}

async function readEmail(messageId: string, config: Config, storage: Storage, memoryKey: string) {
  const gmail = await getGmailClient(config, storage, memoryKey);
  const resp = await gmail.users.messages.get({
    userId: 'me',
    id: messageId,
    format: 'full'
  });
  if (!resp.data.payload) {
    return toTextJson({ error: 'No payload' });
  }
  const headers = resp.data.payload.headers;
  const subject = getHeaderValue(headers, 'subject');
  const from = getHeaderValue(headers, 'from');
  const to = getHeaderValue(headers, 'to');
  const parts: { mimeType?: string; text: string }[] = [];
  function traverse(p?: gmail_v1.Schema$MessagePart) {
    if (!p) return;
    if (p.body?.data && p.mimeType?.startsWith('text/')) {
      parts.push({ mimeType: p.mimeType, text: decodeBase64Url(p.body.data) });
    }
    p.parts?.forEach(traverse);
  }
  traverse(resp.data.payload);
  const html = parts.find(p => p.mimeType === 'text/html')?.text;
  const body = html
    ? cleanMarkdown(convertHtmlToMarkdown(html))
    : (parts.find(p => p.mimeType === 'text/plain')?.text ?? '');
  return toTextJson({ messageId, subject, from, to, body });
}

async function listDrafts(args: { maxResults?: number; query?: string }, config: Config, storage: Storage, memoryKey: string) {
  const gmail = await getGmailClient(config, storage, memoryKey);
  const resp = await gmail.users.drafts.list({
    userId: 'me',
    maxResults: args.maxResults,
    q: args.query
  });
  return toTextJson(resp.data);
}

async function readDraft(draftId: string, config: Config, storage: Storage, memoryKey: string) {
  const gmail = await getGmailClient(config, storage, memoryKey);
  const resp = await gmail.users.drafts.get({
    userId: 'me',
    id: draftId,
    format: 'full'
  });
  if (!resp.data.message?.id) {
    return toTextJson({ error: 'No message in draft' });
  }
  return readEmail(resp.data.message.id, config, storage, memoryKey);
}

async function draftEmail(args: {
  sender: string;
  to: string[];
  cc?: string[];
  bcc?: string[];
  subject: string;
  body: string;
  isHtml?: boolean;
}, config: Config, storage: Storage, memoryKey: string) {
  const raw = await buildMimeMessage(args);
  const gmail = await getGmailClient(config, storage, memoryKey);
  const resp = await gmail.users.drafts.create({
    userId: 'me',
    requestBody: { message: { raw } }
  });
  return toTextJson(resp.data);
}

async function updateDraft(args: {
  draftId: string;
  sender: string;
  to: string[];
  cc?: string[];
  bcc?: string[];
  subject: string;
  body: string;
  isHtml?: boolean;
}, config: Config, storage: Storage, memoryKey: string) {
  const { draftId, ...rest } = args;
  const raw = await buildMimeMessage(rest);
  const gmail = await getGmailClient(config, storage, memoryKey);
  const resp = await gmail.users.drafts.update({
    userId: 'me',
    id: draftId,
    requestBody: { message: { raw } }
  });
  return toTextJson(resp.data);
}

async function deleteDraft(draftId: string, config: Config, storage: Storage, memoryKey: string) {
  const gmail = await getGmailClient(config, storage, memoryKey);
  await gmail.users.drafts.delete({ userId: 'me', id: draftId });
  return toTextJson({ success: true, deletedDraftId: draftId });
}

async function sendEmailFull(args: {
  sender: string;
  to: string[];
  cc?: string[];
  bcc?: string[];
  subject: string;
  body: string;
  isHtml?: boolean;
  draftId?: string;
}, config: Config, storage: Storage, memoryKey: string) {
  const gmail = await getGmailClient(config, storage, memoryKey);
  if (args.draftId) {
    const resp = await gmail.users.drafts.send({
      userId: 'me',
      requestBody: { id: args.draftId }
    });
    return toTextJson(resp.data);
  }
  const raw = await buildMimeMessage(args);
  const resp = await gmail.users.messages.send({
    userId: 'me',
    requestBody: { raw }
  });
  return toTextJson(resp.data);
}

async function sendEmailOnly(args: {
  sender: string;
  to: string[];
  cc?: string[];
  bcc?: string[];
  subject: string;
  body: string;
  isHtml?: boolean;
}, config: Config, storage: Storage, memoryKey: string) {
  const raw = await buildMimeMessage(args);
  const gmail = await getGmailClient(config, storage, memoryKey);
  const resp = await gmail.users.messages.send({
    userId: 'me',
    requestBody: { raw }
  });
  return toTextJson(resp.data);
}

// --------------------------------------------------------------------
// MCP Server Creation: Register Gmail Tools
// --------------------------------------------------------------------
function createMcpServer(memoryKey: string, config: Config): McpServer {
  const server = new McpServer({
    name: `Gmail MCP Server${config.sendOnly ? ' (Send-Only)' : ''} (Memory Key: ${memoryKey})`,
    version: '1.0.0'
  });
  const storage: Storage = config.storage === 'upstash-redis-rest'
    ? new RedisStorage(config.upstashRedisRestUrl!, config.upstashRedisRestToken!, config.storageHeaderKey!)
    : new MemoryStorage();

  server.tool(
    'auth_url',
    'Return an OAuth URL for Gmail. Visit this URL to grant access.',
    {
      // TODO: MCP SDK bug patch - remove when fixed
      comment: z.string().optional(),
    },
    async () => {
      try {
        const authUrl = getAuthUrl(config, memoryKey, storage);
        return toTextJson({ authUrl });
      } catch (err: any) {
        return toTextJson({ error: String(err.message) });
      }
    }
  );

  server.tool(
    'exchange_auth_code',
    'Exchange an auth code for a refresh token. This sets up Gmail authentication.',
    { code: z.string() },
    async (args: { code: string }) => {
      try {
        const token = await exchangeAuthCode(args.code, config, storage, memoryKey);
        return toTextJson({ refreshToken: token });
      } catch (err: any) {
        return toTextJson({ error: String(err.message) });
      }
    }
  );

  if (config.sendOnly) {
    server.tool(
      'send_email',
      'Send an email using only the gmail.send scope (no draftId required).',
      {
        sender: z.string(),
        to: z.array(z.string()),
        cc: z.array(z.string()).optional(),
        bcc: z.array(z.string()).optional(),
        subject: z.string(),
        body: z.string(),
        isHtml: z.boolean().optional()
      },
      async (args) => {
        try {
          return await sendEmailOnly(args, config, storage, memoryKey);
        } catch (err: any) {
          return toTextJson({ error: String(err.message) });
        }
      }
    );
    return server;
  }

  server.tool(
    'list_emails',
    'List Gmail messages (with snippets, pagination, etc.).',
    {
      maxResults: z.number().optional(),
      labelIds: z.array(z.string()).optional(),
      query: z.string().optional(),
      pageToken: z.string().optional(),
      unreadOnly: z.boolean().optional()
    },
    async (args) => {
      try {
        return await listEmails(args, config, storage, memoryKey);
      } catch (err: any) {
        return toTextJson({ error: String(err.message) });
      }
    }
  );

  server.tool(
    'read_email',
    'Read a single Gmail message in full and convert HTML to Markdown.',
    { messageId: z.string() },
    async (args: { messageId: string }) => {
      try {
        return await readEmail(args.messageId, config, storage, memoryKey);
      } catch (err: any) {
        return toTextJson({ error: String(err.message) });
      }
    }
  );

  server.tool(
    'list_drafts',
    'List Gmail drafts.',
    {
      maxResults: z.number().optional(),
      query: z.string().optional()
    },
    async (args) => {
      try {
        return await listDrafts(args, config, storage, memoryKey);
      } catch (err: any) {
        return toTextJson({ error: String(err.message) });
      }
    }
  );

  server.tool(
    'read_draft',
    'Read a single Gmail draft in full.',
    { draftId: z.string() },
    async (args: { draftId: string }) => {
      try {
        return await readDraft(args.draftId, config, storage, memoryKey);
      } catch (err: any) {
        return toTextJson({ error: String(err.message) });
      }
    }
  );

  server.tool(
    'draft_email',
    'Create a new Gmail draft.',
    {
      sender: z.string(),
      to: z.array(z.string()),
      cc: z.array(z.string()).optional(),
      bcc: z.array(z.string()).optional(),
      subject: z.string(),
      body: z.string(),
      isHtml: z.boolean().optional()
    },
    async (args) => {
      try {
        return await draftEmail(args, config, storage, memoryKey);
      } catch (err: any) {
        return toTextJson({ error: String(err.message) });
      }
    }
  );

  server.tool(
    'update_draft',
    'Update an existing Gmail draft.',
    {
      draftId: z.string(),
      sender: z.string(),
      to: z.array(z.string()),
      cc: z.array(z.string()).optional(),
      bcc: z.array(z.string()).optional(),
      subject: z.string(),
      body: z.string(),
      isHtml: z.boolean().optional()
    },
    async (args) => {
      try {
        return await updateDraft(args, config, storage, memoryKey);
      } catch (err: any) {
        return toTextJson({ error: String(err.message) });
      }
    }
  );

  server.tool(
    'delete_draft',
    'Delete a Gmail draft.',
    { draftId: z.string() },
    async (args: { draftId: string }) => {
      try {
        return await deleteDraft(args.draftId, config, storage, memoryKey);
      } catch (err: any) {
        return toTextJson({ error: String(err.message) });
      }
    }
  );

  server.tool(
    'send_email',
    'Send an email (new or via an existing draft).',
    {
      sender: z.string(),
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
        return await sendEmailFull(args, config, storage, memoryKey);
      } catch (err: any) {
        return toTextJson({ error: String(err.message) });
      }
    }
  );

  return server;
}

// --------------------------------------------------------------------
// Minimal Fly.io "replay" handling (optional)
// --------------------------------------------------------------------
function parseFlyReplaySrc(headerValue: string): Record<string, string> {
  const regex = /(.*?)=(.*?)($|;)/g;
  const matches = headerValue.matchAll(regex);
  const result: Record<string, string> = {};
  for (const match of matches) {
    if (match.length >= 3) {
      result[match[1].trim()] = match[2].trim();
    }
  }
  return result;
}
let machineId: string | null = null;
function saveMachineId(req: Request) {
  if (machineId) return;
  const headerKey = 'fly-replay-src';
  const raw = req.headers[headerKey.toLowerCase()];
  if (!raw || typeof raw !== 'string') return;
  try {
    const parsed = parseFlyReplaySrc(raw);
    if (parsed.state) {
      const decoded = decodeURIComponent(parsed.state);
      const obj = JSON.parse(decoded);
      if (obj.machineId) machineId = obj.machineId;
    }
  } catch {
    // ignore
  }
}

// --------------------------------------------------------------------
// Main: Start the server (HTTP / SSE / stdio)
// --------------------------------------------------------------------
async function main() {
  const argv = yargs(hideBin(process.argv))
    .option('port', { type: 'number', default: 8000 })
    .option('transport', { type: 'string', choices: ['sse', 'stdio', 'http'], default: 'sse' })
    .option('storage', {
      type: 'string',
      choices: ['memory-single', 'memory', 'upstash-redis-rest'],
      default: 'memory-single',
      describe:
        'Choose storage backend: "memory-single" uses fixed single-user storage; "memory" uses multi-user in-memory storage (requires --storageHeaderKey); "upstash-redis-rest" uses Upstash Redis (requires --storageHeaderKey, --upstashRedisRestUrl, and --upstashRedisRestToken).'
    })
    .option('googleClientId', { type: 'string', demandOption: true, describe: "Google Client ID" })
    .option('googleClientSecret', { type: 'string', demandOption: true, describe: "Google Client Secret" })
    .option('googleRedirectUri', { type: 'string', demandOption: true, describe: "Google Redirect URI" })
    .option('sendOnly', { type: 'boolean', default: false, describe: 'If true, only expose send_email tool (gmail.send scope only).' })
    .option('googleState', { type: 'string', describe: "Optional Google OAuth state parameter" })
    .option('storageHeaderKey', { type: 'string', describe: 'For storage "memory" or "upstash-redis-rest": the header name (or key prefix) to use.' })
    .option('upstashRedisRestUrl', { type: 'string', describe: 'Upstash Redis REST URL (if --storage=upstash-redis-rest)' })
    .option('upstashRedisRestToken', { type: 'string', describe: 'Upstash Redis REST token (if --storage=upstash-redis-rest)' })
    .help()
    .parseSync();

  const config: Config = {
    port: argv.port,
    transport: argv.transport as 'sse' | 'stdio' | 'http',
    storage: argv.storage as 'memory-single' | 'memory' | 'upstash-redis-rest',
    googleClientId: argv.googleClientId,
    googleClientSecret: argv.googleClientSecret,
    googleRedirectUri: argv.googleRedirectUri,
    sendOnly: argv.sendOnly,
    googleState: argv.googleState,
    storageHeaderKey:
      (argv.storage === 'memory-single')
        ? undefined
        : (argv.storageHeaderKey && argv.storageHeaderKey.trim()
            ? argv.storageHeaderKey.trim()
            : (() => { console.error('Error: --storageHeaderKey is required for storage modes "memory" or "upstash-redis-rest".'); process.exit(1); return ''; })()),
    upstashRedisRestUrl: argv.upstashRedisRestUrl,
    upstashRedisRestToken: argv.upstashRedisRestToken,
  };

  // Extra validation for Upstash mode
  if ((argv.upstashRedisRestUrl || argv.upstashRedisRestToken) && config.storage !== 'upstash-redis-rest') {
    console.error("Error: --upstashRedisRestUrl and --upstashRedisRestToken can only be used when --storage is 'upstash-redis-rest'.");
    process.exit(1);
  }
  if (config.storage === 'upstash-redis-rest') {
    if (!config.upstashRedisRestUrl || !config.upstashRedisRestUrl.trim()) {
      console.error("Error: --upstashRedisRestUrl is required for storage mode 'upstash-redis-rest'.");
      process.exit(1);
    }
    if (!config.upstashRedisRestToken || !config.upstashRedisRestToken.trim()) {
      console.error("Error: --upstashRedisRestToken is required for storage mode 'upstash-redis-rest'.");
      process.exit(1);
    }
  }

  // stdio
  if (config.transport === 'stdio') {
    const memoryKey = "single";
    const server = createMcpServer(memoryKey, config);
    const transport = new StdioServerTransport();
    void server.connect(transport);
    console.log('Listening on stdio');
    return;
  }

  // Streamable HTTP (root "/")
  if (config.transport === 'http') {
    const app = express();

    // Do not JSON-parse "/" — the transport handles raw body/streaming
    app.use((req, res, next) => {
      if (req.path === '/') return next();
      express.json()(req, res, next);
    });

    interface HttpSession {
      memoryKey: string;
      server: McpServer;
      transport: StreamableHTTPServerTransport;
    }
    const sessions = new Map<string, HttpSession>();

    function resolveMemoryKeyFromHeaders(req: Request): string | undefined {
      if (config.storage === 'memory-single') return 'single';
      const keyName = (config.storageHeaderKey as string).toLowerCase();
      const headerVal = req.headers[keyName];
      if (typeof headerVal !== 'string' || !headerVal.trim()) return undefined;
      return headerVal.trim();
    }

    function createServerFor(memoryKey: string) {
      return createMcpServer(memoryKey, config);
    }

    // POST / — JSON-RPC input; initializes a session if none exists
    app.post('/', async (req: Request, res: ExpressResponse) => {
      try {
        const sessionId = req.headers['mcp-session-id'] as string | undefined;

        if (sessionId && sessions.has(sessionId)) {
          const { transport } = sessions.get(sessionId)!;
          await transport.handleRequest(req, res);
          return;
        }

        // New initialization — require a valid memoryKey (no anonymous)
        const memoryKey = resolveMemoryKeyFromHeaders(req);
        if (!memoryKey) {
          res.status(400).json({
            jsonrpc: '2.0',
            error: { code: -32000, message: `Bad Request: Missing or invalid "${config.storageHeaderKey}" header` },
            id: (req as any)?.body?.id
          });
          return;
        }

        const server = createServerFor(memoryKey);
        const eventStore = new InMemoryEventStore();

        let transport!: StreamableHTTPServerTransport;
        transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          eventStore,
          onsessioninitialized: (newSessionId: string) => {
            sessions.set(newSessionId, { memoryKey, server, transport });
            console.log(`[${newSessionId}] HTTP session initialized for key "${memoryKey}"`);
          }
        });

        transport.onclose = async () => {
          const sid = transport.sessionId;
          if (sid && sessions.has(sid)) {
            sessions.delete(sid);
            console.log(`[${sid}] Transport closed; removed session`);
          }
          try { await server.close(); } catch { /* already closed */ }
        };

        await server.connect(transport);
        await transport.handleRequest(req, res);
      } catch (err) {
        console.error('Error handling HTTP POST /:', err);
        if (!res.headersSent) {
          res.status(500).json({
            jsonrpc: '2.0',
            error: { code: -32603, message: 'Internal server error' },
            id: (req as any)?.body?.id
          });
        }
      }
    });

    // GET / — server->client event stream (SSE under the hood)
    app.get('/', async (req: Request, res: ExpressResponse) => {
      saveMachineId(req);
      const sessionId = req.headers['mcp-session-id'] as string | undefined;
      if (!sessionId || !sessions.has(sessionId)) {
        res.status(400).json({
          jsonrpc: '2.0',
          error: { code: -32000, message: 'Bad Request: No valid session ID provided' },
          id: (req as any)?.body?.id
        });
        return;
      }
      try {
        const { transport } = sessions.get(sessionId)!;
        await transport.handleRequest(req, res);
      } catch (err) {
        console.error(`[${sessionId}] Error handling HTTP GET /:`, err);
        if (!res.headersSent) {
          res.status(500).json({
            jsonrpc: '2.0',
            error: { code: -32603, message: 'Internal server error' },
            id: (req as any)?.body?.id
          });
        }
      }
    });

    // DELETE / — session termination
    app.delete('/', async (req: Request, res: ExpressResponse) => {
      const sessionId = req.headers['mcp-session-id'] as string | undefined;
      if (!sessionId || !sessions.has(sessionId)) {
        res.status(400).json({
          jsonrpc: '2.0',
          error: { code: -32000, message: 'Bad Request: No valid session ID provided' },
          id: (req as any)?.body?.id
        });
        return;
      }
      try {
        const { transport } = sessions.get(sessionId)!;
        await transport.handleRequest(req, res);
      } catch (err) {
        console.error(`[${sessionId}] Error handling HTTP DELETE /:`, err);
        if (!res.headersSent) {
          res.status(500).json({
            jsonrpc: '2.0',
            error: { code: -32603, message: 'Error handling session termination' },
            id: (req as any)?.body?.id
          });
        }
      }
    });

    app.listen(config.port, () => {
      console.log(`Listening on port ${config.port} (http)${config.sendOnly ? ' [SEND-ONLY MODE]' : ''}`);
    });

    return; // do not fall through to SSE
  }

  // SSE
  const app = express();
  interface ServerSession {
    memoryKey: string;
    server: McpServer;
    transport: SSEServerTransport;
    sessionId: string;
  }
  let sessions: ServerSession[] = [];

  app.use((req, res, next) => {
    if (req.path === '/message') return next();
    express.json()(req, res, next);
  });

  app.get('/', async (req: Request, res: ExpressResponse) => {
    saveMachineId(req);
    let memoryKey: string;
    if (config.storage === 'memory-single') {
      memoryKey = "single";
    } else {
      const headerVal = req.headers[config.storageHeaderKey!.toLowerCase()];
      if (typeof headerVal !== 'string' || !headerVal.trim()) {
        res.status(400).json({ error: `Missing or invalid "${config.storageHeaderKey}" header` });
        return;
      }
      memoryKey = headerVal.trim();
    }
    const server = createMcpServer(memoryKey, config);
    const transport = new SSEServerTransport('/message', res);
    await server.connect(transport);
    const sessionId = transport.sessionId;
    sessions.push({ memoryKey, server, transport, sessionId });
    console.log(`[${sessionId}] SSE connected for key: "${memoryKey}"`);
    transport.onclose = () => {
      console.log(`[${sessionId}] SSE connection closed`);
      sessions = sessions.filter(s => s.transport !== transport);
    };
    transport.onerror = (err: Error) => {
      console.error(`[${sessionId}] SSE error:`, err);
      sessions = sessions.filter(s => s.transport !== transport);
    };
    req.on('close', () => {
      console.log(`[${sessionId}] Client disconnected`);
      sessions = sessions.filter(s => s.transport !== transport);
    });
  });

  app.post('/message', async (req: Request, res: ExpressResponse) => {
    const sessionId = req.query.sessionId as string;
    if (!sessionId) {
      console.error('Missing sessionId');
      res.status(400).send({ error: 'Missing sessionId' });
      return;
    }
    const target = sessions.find(s => s.sessionId === sessionId);
    if (!target) {
      console.error(`No active session for sessionId=${sessionId}`);
      res.status(404).send({ error: 'No active session' });
      return;
    }
    try {
      await target.transport.handlePostMessage(req, res);
    } catch (err: any) {
      console.error(`[${sessionId}] Error handling /message:`, err);
      res.status(500).send({ error: 'Internal error' });
    }
  });

  app.listen(config.port, () => {
    console.log(`Listening on port ${config.port} (sse)${config.sendOnly ? ' [SEND-ONLY MODE]' : ''}`);
  });
}

main().catch((err: any) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
