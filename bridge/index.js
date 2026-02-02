#!/usr/bin/env node
/**
 * Burp MCP Bridge (improved)
 *
 * Key improvements over the original:
 * - IPv6-safe Burp base URL construction
 * - Origin allowlist uses "::1" (not "[::1]"), with robust host:port matching
 * - Discovery and health endpoints reflect actual transport configuration
 * - Safer env parsing; guards against NaN
 * - JSON-RPC response validation; clearer fetch error handling (AbortError, ECONNREFUSED via cause)
 * - TLS hardening (minVersion), and key permissions set to 0600
 * - Avoids naming confusion with node:http createServer by renaming method to buildHttpServer()
 * - Basic CORS preflight handling and small security headers
 * - Optional loopback-only enforcement; SSE concurrency + idle TTL limits; POST size guard
 * - Request correlation IDs added to logs and forwarded to Burp via headers
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';

import { createServer as createNodeHttpServer } from 'node:http';
import { createServer as createNodeHttpsServer } from 'node:https';
import { readFileSync, existsSync, mkdirSync, writeFileSync, chmodSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/** Attempt to read version from package.json to keep a single source of truth. */
function getBridgeVersion() {
  try {
    const pkg = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8'));
    return pkg.version || '0.0.0-dev';
  } catch {
    // Fallback if package.json is not co-located (e.g., single-file deployment)
    return '0.0.0-dev';
  }
}

/** Parse integer envs safely with default; trims and handles empty strings. */
function toInt(v, def) {
  const n = Number.parseInt(String(v ?? '').trim(), 10);
  return Number.isFinite(n) ? n : def;
}

/** Extract bare hostname from a Host header value (handles IPv6 [::1]:port). */
function hostHeaderToHostname(hostHeader = '') {
  const s = String(hostHeader);
  if (s.startsWith('[')) {
    // IPv6 form: [::1]:3000
    const end = s.indexOf(']');
    return end > 1 ? s.slice(1, end) : s;
  }
  // IPv4/hostname form: localhost:3000 or 127.0.0.1:3000
  return s.split(':')[0];
}

class BurpMcpBridge {
  constructor() {
    // ---- Core configuration
    this.debug = process.env.BURP_MCP_DEBUG === 'true';

    // Burp target
    const burpPortInt = toInt(process.env.BURP_MCP_SERVER_PORT, 8081);
    this.burpPort = String(burpPortInt);
    this.burpHost = process.env.BURP_MCP_SERVER_HOST ?? 'localhost';

    // Build a robust base URL (IPv4, IPv6, hostname)
    const burpUrl = new URL('http://localhost');
    burpUrl.hostname = this.burpHost;       // "::1" stays unbracketed here
    burpUrl.port = this.burpPort;
    this.burpBaseUrl = burpUrl.toString();

    // Timeouts and limits
    this.requestTimeout = toInt(process.env.BURP_MCP_REQUEST_TIMEOUT, 30_000);
    this.maxSseSessions = toInt(process.env.MCP_MAX_SSE, 100);
    this.maxPostBytes = toInt(process.env.MCP_MAX_POST_BYTES, 1_048_576); // 1 MiB
    this.sessionIdleMs = toInt(process.env.MCP_SESSION_IDLE_MS, 30 * 60 * 1000); // 30 minutes

    // HTTP server config
    this.httpPort = toInt(process.env.MCP_HTTP_PORT, 3000);
    this.useHttps = process.env.MCP_USE_HTTPS !== 'false'; // default: HTTPS enabled
    this.certPath = process.env.MCP_CERT_PATH || join(__dirname, 'certs');
    this.keyFile = process.env.MCP_KEY_FILE || join(this.certPath, 'key.pem');
    this.certFile = process.env.MCP_CERT_FILE || join(this.certPath, 'cert.pem');

    // Host binding
    this.bindLoopbackOnly = process.env.MCP_BIND_LOOPBACK_ONLY !== 'false'; // default: true
    const requestedHost = process.env.MCP_HTTP_HOST ?? '127.0.0.1';
    this.httpHost = this.bindLoopbackOnly ? '127.0.0.1' : requestedHost;

    // Transport mode
    const mode = (process.env.MCP_TRANSPORT_MODE ?? 'both').toLowerCase();
    const validModes = new Set(['stdio', 'http', 'both']);
    this.transportMode = validModes.has(mode) ? mode : 'both';

    // Derived transport name for HTTP
    this.httpTransportName = this.useHttps ? 'https-sse' : 'http-sse';

    // Version
    this.BRIDGE_VERSION = getBridgeVersion();

    // MCP server
    this.server = new Server(
      { name: 'burp-mcp-bridge', version: this.BRIDGE_VERSION },
      { capabilities: { tools: {} } }
    );

    // Track active SSE sessions: sessionId -> { transport, lastSeen }
    this.sseTransports = new Map();

    // HTTP server handle
    this.httpServer = null;

    // Background sweeper for idle SSE sessions
    this.sessionSweepInterval = setInterval(() => this.sweepIdleSessions(), 60_000);

    this.logInfo(`Burp MCP Bridge v${this.BRIDGE_VERSION} initializing…`);
    this.logInfo(`Transport mode: ${this.transportMode}`);
    this.logInfo(`Connecting to Burp extension at: ${this.burpBaseUrl}`);
    this.logInfo(`Request timeout: ${this.requestTimeout}ms`);
    this.logInfo(`HTTP bind: ${this.useHttps ? 'https' : 'http'}://${this.httpHost}:${this.httpPort} (loopback-only: ${this.bindLoopbackOnly})`);

    this.setupHandlers();
  }

  // ---------- Logging
  logInfo(message) {
    console.error(`[INFO] ${new Date().toISOString()} - ${message}`);
  }
  logError(message) {
    console.error(`[ERROR] ${new Date().toISOString()} - ${message}`);
  }
  logDebug(message) {
    if (this.debug) console.error(`[DEBUG] ${new Date().toISOString()} - ${message}`);
  }

  // ---------- MCP Handlers
  setupHandlers() {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      const rid = randomUUID();
      try {
        this.logDebug(`[${rid}] Requesting tools list from Burp extension`);
        const response = await this.callBurpExtension('tools/list', {}, { rid });
        const count = response?.result?.tools?.length ?? 0;
        this.logDebug(`[${rid}] Received ${count} tools from Burp extension`);
        return response.result;
      } catch (error) {
        this.logError(`[${rid}] Error getting tools list: ${error.message}`);
        return { tools: [] };
      }
    });

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const rid = randomUUID();
      const toolName = request.params.name;
      try {
        this.logDebug(`[${rid}] Calling tool: ${toolName}`);

        // Forward tool call to Burp extension (async handling)
        const response = await this.callBurpExtension(
          'tools/call',
          { name: toolName, arguments: request.params.arguments || {} },
          { rid, toolName }
        );

        if (response.error) {
          const msg = String(response.error.message || 'Unknown error');
          this.logError(`[${rid}] Tool ${toolName} returned error: ${msg}`);
          return { content: [{ type: 'text', text: `❌ Error: ${msg}` }], isError: true };
        }

        this.logDebug(`[${rid}] Tool ${toolName} completed successfully`);
        return response.result;
      } catch (error) {
        this.logError(`[${rid}] Error calling tool ${toolName}: ${error.message}`);
        return {
          content: [{
            type: 'text',
            text:
              `❌ Connection Error: ${error.message}\n\n` +
              `Troubleshooting:\n` +
              `• Ensure Burp Suite Professional is running\n` +
              `• Verify Burp MCP Bridge extension is loaded\n` +
              `• Check that ${this.burpBaseUrl} is reachable`
          }],
          isError: true
        };
      }
    });
  }

  // ---------- Burp JSON-RPC call
  async callBurpExtension(method, params, { rid, toolName } = {}) {
    const requestBody = {
      jsonrpc: '2.0',
      id: Date.now(),
      method,
      params
    };

    const headers = {
      'Content-Type': 'application/json',
      'User-Agent': `Burp-MCP-Bridge/${this.BRIDGE_VERSION}`,
      ...(rid ? { 'X-Request-Id': rid } : {}),
      ...(toolName ? { 'X-Tool-Name': String(toolName) } : {})
    };

    this.logDebug(`${rid ? `[${rid}] ` : ''}Sending request to Burp: ${method}`);

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.requestTimeout);

    try {
      const response = await fetch(this.burpBaseUrl, {
        method: 'POST',
        headers,
        body: JSON.stringify(requestBody),
        signal: controller.signal
      });
      clearTimeout(timeoutId);

      if (!response.ok) {
        if (response.status === 404) {
          throw new Error(`Burp MCP extension endpoint not found at ${this.burpBaseUrl}. Is the extension loaded?`);
        }
        if (response.status >= 500) {
          throw new Error(`Burp extension server error (${response.status}): ${response.statusText}`);
        }
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      // Parse body defensively
      const raw = await response.text();
      let result;
      try {
        result = JSON.parse(raw);
      } catch {
        throw new Error('Invalid JSON response from Burp extension');
      }

      // Minimal JSON-RPC shape validation
      const valid = result && result.jsonrpc === '2.0' && ('result' in result || 'error' in result);
      if (!valid) throw new Error('Invalid JSON-RPC response from Burp extension');

      this.logDebug(`${rid ? `[${rid}] ` : ''}Received response from Burp: ${result.error ? 'ERROR' : 'SUCCESS'}`);
      return result;
    } catch (error) {
      clearTimeout(timeoutId);
      if (error.name === 'AbortError') {
        throw new Error(`Request timeout after ${this.requestTimeout}ms. Burp extension may be overloaded.`);
      }
      const code = error.code || error.cause?.code;
      if (code === 'ECONNREFUSED') {
        throw new Error(`Cannot connect to Burp extension at ${this.burpBaseUrl}. Is Burp Suite running with the MCP Bridge extension loaded?`);
      }
      throw error;
    }
  }

  // ---------- Optional extension stats (non-fatal)
  async getBurpStats() {
    try {
      return await this.callBurpExtension('stats', {});
    } catch (error) {
      this.logError(`Error getting Burp stats: ${error.message}`);
      return null;
    }
  }

  // ---------- TLS certificate management
  generateSelfSignedCert() {
    this.logInfo('Generating self-signed certificate for HTTPS…');

    try {
      if (!existsSync(this.certPath)) {
        mkdirSync(this.certPath, { recursive: true });
        this.logInfo(`Created directory: ${this.certPath}`);
      }

      const certConfig = `
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = localhost

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
IP.2 = ::1
`.trim();

      const configFile = join(this.certPath, 'openssl.cnf');
      writeFileSync(configFile, certConfig, 'utf8');

      // Generate private key and certificate via openssl
      execSync(
        `openssl req -x509 -newkey rsa:4096 -keyout "${this.keyFile}" -out "${this.certFile}" -days 365 -nodes -config "${configFile}"`,
        { stdio: 'pipe' }
      );

      // Ensure private key is not world-readable
      try { chmodSync(this.keyFile, 0o600); } catch {}

      this.logInfo('✅ Self-signed certificate generated successfully');
      this.logInfo(`   Key:  ${this.keyFile}`);
      this.logInfo(`   Cert: ${this.certFile}`);
    } catch (error) {
      this.logError(`Failed to generate certificate: ${error.message}`);
      throw error;
    }
  }

  loadOrGenerateCerts() {
    if (existsSync(this.keyFile) && existsSync(this.certFile)) {
      this.logInfo('Using existing SSL certificates');
      try {
        const key = readFileSync(this.keyFile);
        const cert = readFileSync(this.certFile);
        return { key, cert };
      } catch (error) {
        this.logError(`Failed to read certificates: ${error.message}`);
        this.logInfo('Regenerating certificates…');
      }
    }
    this.generateSelfSignedCert();
    return {
      key: readFileSync(this.keyFile),
      cert: readFileSync(this.certFile)
    };
  }

  // ---------- HTTP server & requests
  buildHttpServer() {
    if (this.useHttps) {
      const credentials = this.loadOrGenerateCerts();
      return createNodeHttpsServer(
        { ...credentials, minVersion: 'TLSv1.2' },
        (req, res) => this.handleHttpRequest(req, res)
      );
    }
    return createNodeHttpServer((req, res) => this.handleHttpRequest(req, res));
  }

  setSecurityHeaders(res) {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Cache-Control', 'no-store');
  }

  // Returns true if the provided hostname resolves to loopback forms.
  isLoopbackHostname(hostname) {
    return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1';
  }

  allowedHostsFromEnv(baseSet) {
    const allowedHosts = new Set(baseSet);
    if (process.env.MCP_ALLOWED_ORIGINS) {
      for (const raw of process.env.MCP_ALLOWED_ORIGINS.split(',')) {
        const entry = raw.trim();
        if (!entry) continue;
        try {
          const u = new URL(entry);
          const hostPort = u.port ? `${u.hostname}:${u.port}` : u.hostname;
          allowedHosts.add(hostPort);
        } catch {
          // Allow bare host[:port] entries too
          allowedHosts.add(entry);
        }
      }
    }
    return allowedHosts;
  }

  isAllowedOrigin(origin) {
    // Parse origin URL defensively
    let originUrl;
    try {
      originUrl = new URL(origin);
    } catch {
      this.logError(`Invalid origin URL: ${origin}`);
      return false;
    }

    // Default allowlist (store "::1", not "[::1]")
    const baseAllowed = ['localhost', '127.0.0.1', '::1'];
    const allowedHosts = this.allowedHostsFromEnv(baseAllowed);

    // Check hostname and hostname:port forms
    const originHost = originUrl.hostname; // "::1" for IPv6
    const originHostPort = originUrl.port ? `${originHost}:${originUrl.port}` : originHost;

    const isAllowed = allowedHosts.has(originHost) || allowedHosts.has(originHostPort);
    if (!isAllowed) {
      this.logDebug(`Origin rejected - hostname: ${originHost}; allowed: ${Array.from(allowedHosts).join(', ')}`);
    }
    return isAllowed;
  }

  // Respond to CORS preflight for supported endpoints
  handlePreflight(req, res, url, originOk) {
    if (!originOk) {
      res.writeHead(403, { 'Content-Type': 'text/plain' });
      res.end('Forbidden: Invalid origin');
      return;
    }
    const headers = {
      'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
      'Access-Control-Allow-Headers': 'mcp-session-id, content-type',
      'Access-Control-Max-Age': '600',
      'Vary': 'Origin'
    };
    if (req.headers.origin) headers['Access-Control-Allow-Origin'] = req.headers.origin;
    this.setSecurityHeaders(res);
    res.writeHead(204, headers);
    res.end();
  }

  transportsEnabled() {
    const transports = [];
    if (this.transportMode === 'stdio' || this.transportMode === 'both') transports.push('stdio');
    // Only report HTTP/SSE as enabled if the server actually started
    if ((this.transportMode === 'http' || this.transportMode === 'both') && this.httpServer) {
      transports.push(this.httpTransportName);
    }
    return transports;
  }

  async handleHttpRequest(req, res) {
    // Optional loopback-only guard using Host header
    const hostHeader = req.headers.host;
    const requestedHost = hostHeaderToHostname(hostHeader);
    if (this.bindLoopbackOnly && !this.isLoopbackHostname(requestedHost)) {
      this.logError(`Rejected non-loopback Host header: ${hostHeader}`);
      res.writeHead(403, { 'Content-Type': 'text/plain' });
      res.end('Forbidden: Loopback only');
      return;
    }

    // Origin validation (when provided)
    const origin = req.headers.origin;
    const originOk = !origin || this.isAllowedOrigin(origin);

    const protocol = this.useHttps ? 'https' : 'http';
    const url = new URL(req.url || '/', `${protocol}://${hostHeader || 'localhost'}`);

    // Handle CORS preflight
    if (req.method === 'OPTIONS') {
      return this.handlePreflight(req, res, url, originOk);
    }

    // Reject if bad origin
    if (!originOk) {
      this.logError(`Rejected request from unauthorized origin: ${origin}`);
      res.writeHead(403, { 'Content-Type': 'text/plain' });
      res.end('Forbidden: Invalid origin');
      return;
    }

    // Add simple security headers on all non-SSE responses
    this.setSecurityHeaders(res);
    if (origin) {
      res.setHeader('Vary', 'Origin');
      res.setHeader('Access-Control-Allow-Origin', origin);
    }

    // --- Routing
    if (url.pathname === '/.well-known/mcp') {
      const payload = {
        name: 'burp-mcp-bridge',
        version: this.BRIDGE_VERSION,
        transports: this.transportsEnabled(),
        capabilities: ['tools'],
        endpoints: { sse: '/mcp', health: '/health' }
      };
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(payload));
      return;
    }

    if (url.pathname === '/health') {
      const payload = {
        status: 'ok',
        version: this.BRIDGE_VERSION,
        burpConnection: this.burpBaseUrl,
        transports: this.transportsEnabled(),
        activeSseSessions: this.sseTransports.size
      };
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(payload));
      return;
    }

    if (url.pathname === '/mcp') {
      if (req.method === 'GET') {
        // Concurrency guard
        if (this.sseTransports.size >= this.maxSseSessions) {
          res.writeHead(503, { 'Content-Type': 'text/plain' });
          res.end('Service Unavailable: Too many concurrent SSE sessions');
          return;
        }

        // For browsers, keep CORS headers on SSE as well
        if (origin) {
          res.setHeader('Vary', 'Origin');
          res.setHeader('Access-Control-Allow-Origin', origin);
        }

        // Establish SSE transport
        const transport = new SSEServerTransport('/mcp', res);

        transport.onclose = () => {
          this.logDebug(`SSE connection closed: ${transport.sessionId}`);
          this.sseTransports.delete(transport.sessionId);
        };
        transport.onerror = (error) => {
          this.logError(`SSE transport error: ${error?.message || error}`);
          this.sseTransports.delete(transport.sessionId);
        };

        // Track session
        this.sseTransports.set(transport.sessionId, { transport, lastSeen: Date.now() });

        // Start
        await this.server.connect(transport);
        this.logInfo(`New SSE session started: ${transport.sessionId}`);
        return;
      }

      if (req.method === 'POST') {
        const sessionId = req.headers['mcp-session-id'];
        if (!sessionId || typeof sessionId !== 'string') {
          res.writeHead(400, { 'Content-Type': 'text/plain' });
          res.end('Bad Request: Missing mcp-session-id header');
          return;
        }

        // Basic size guard (uses Content-Length if present)
        const len = toInt(req.headers['content-length'], 0);
        if (len > this.maxPostBytes) {
          res.writeHead(413, { 'Content-Type': 'text/plain' });
          res.end('Payload Too Large');
          return;
        }

        const rec = this.sseTransports.get(sessionId);
        if (!rec) {
          this.logError(`No active session found for ID: ${sessionId}`);
          res.writeHead(404, { 'Content-Type': 'text/plain' });
          res.end('Session not found');
          return;
        }

        // Update activity and dispatch
        rec.lastSeen = Date.now();
        await rec.transport.handlePostMessage(req, res);
        return;
      }

      res.writeHead(405, { 'Content-Type': 'text/plain' });
      res.end('Method Not Allowed');
      return;
    }

    // Default 404
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found');
  }

  sweepIdleSessions() {
    const now = Date.now();
    for (const [sessionId, rec] of this.sseTransports.entries()) {
      if (now - rec.lastSeen > this.sessionIdleMs) {
        this.logInfo(`Closing idle SSE session: ${sessionId}`);
        try { rec.transport.close(); } catch {}
        this.sseTransports.delete(sessionId);
      }
    }
  }

  // ---------- Lifecycle
  async start() {
    try {
      // Test connection to Burp extension on startup
      this.logInfo('Testing connection to Burp extension…');
      await this.callBurpExtension('ping', {});
      this.logInfo('✅ Successfully connected to Burp extension');

      const stats = await this.getBurpStats();
      if (stats?.result) this.logInfo(`Extension status: ${stats.result.stats}`);
    } catch (error) {
      this.logError(`⚠️  Cannot connect to Burp extension: ${error.message}`);
      this.logError('Bridge will start anyway; tool calls will fail until Burp is ready.');
    }

    // Start stdio transport if enabled
    if (this.transportMode === 'stdio' || this.transportMode === 'both') {
      const transport = new StdioServerTransport();
      await this.server.connect(transport);
      this.logInfo('✅ Stdio transport started');
    }

    // Start HTTP/SSE transport if enabled
    if (this.transportMode === 'http' || this.transportMode === 'both') {
      this.httpServer = this.buildHttpServer();

      try {
        await new Promise((resolve, reject) => {
          this.httpServer.on('error', (error) => {
            reject(error);
          });

          this.httpServer.listen(this.httpPort, this.httpHost, () => {
            const protocol = this.useHttps ? 'https' : 'http';
            this.logInfo(`✅ ${protocol.toUpperCase()}/SSE transport started on ${protocol}://${this.httpHost}:${this.httpPort}/mcp`);
            this.logInfo(`   Endpoints: /mcp (SSE), /health, /.well-known/mcp`);
            if (this.useHttps) {
              this.logInfo('   ⚠️  Using self-signed certificate — clients may need to accept a security warning');
            }
            resolve();
          });
        });
      } catch (error) {
        this.logError(`HTTP server error: ${error.message}`);

        // If this was mode 'both' and HTTP failed, we can still continue with stdio
        if (this.transportMode === 'both') {
          this.logInfo('⚠️  HTTP/SSE transport failed to start, continuing with stdio only');
          this.httpServer = null;
        } else {
          // If mode was 'http' only, this is fatal
          throw error;
        }
      }
    }

    this.logInfo(`🚀 Burp MCP Bridge v${this.BRIDGE_VERSION} started and ready`);
    this.logInfo(`Configuration: ${this.burpBaseUrl} (timeout: ${this.requestTimeout}ms)`);
    this.logInfo(`Active transports: ${this.transportsEnabled().join(', ')}`);
  }

  async shutdown() {
    this.logInfo('🛑 Shutting down Burp MCP Bridge…');

    clearInterval(this.sessionSweepInterval);

    // Close all SSE connections
    for (const [sessionId, rec] of this.sseTransports.entries()) {
      this.logDebug(`Closing SSE session: ${sessionId}`);
      try { await rec.transport.close(); } catch (error) {
        this.logError(`Error closing SSE transport ${sessionId}: ${error.message}`);
      }
    }
    this.sseTransports.clear();

    // Close HTTP server if running
    if (this.httpServer) {
      await new Promise((resolve) => {
        this.httpServer.close(() => {
          this.logInfo('✅ HTTP server closed');
          resolve();
        });
      });
    }

    this.logInfo('✅ Burp MCP Bridge shut down gracefully');
    process.exit(0);
  }
}

// ---- Boot
const bridge = new BurpMcpBridge();
bridge.start().catch((e) => {
  console.error(`[FATAL] ${e?.stack || e}`);
  process.exit(1);
});

// Graceful shutdown handlers
process.on('SIGINT', async () => {
  console.error('\n[INFO] Received SIGINT (Ctrl+C)');
  await bridge.shutdown();
});
process.on('SIGTERM', async () => {
  console.error('\n[INFO] Received SIGTERM');
  await bridge.shutdown();
});
