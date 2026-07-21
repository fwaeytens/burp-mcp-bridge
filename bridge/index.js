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
 * - Optional loopback-only enforcement; SSE + streamable HTTP concurrency + idle TTL limits; POST size guard
 * - Request correlation IDs added to logs and forwarded to Burp via headers
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';

import { createServer as createNodeHttpServer } from 'node:http';
import { createServer as createNodeHttpsServer } from 'node:https';
import { readFileSync, existsSync, mkdirSync, writeFileSync, chmodSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import {
  hostHeaderToHostname,
  normalizeBareHostEntry,
  stripIpv6Brackets,
  toInt
} from './lib/bridge-utils.js';
import { createBridgeConfig } from './lib/bridge-config.js';
import { BurpJsonRpcClient } from './lib/burp-json-rpc-client.js';
import { registerMcpToolHandlers } from './lib/mcp-tool-handlers.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

class BurpMcpBridge {
  constructor() {
    const bridgeConfig = createBridgeConfig({ bridgeDir: __dirname });
    Object.assign(this, bridgeConfig);
    this.BRIDGE_VERSION = bridgeConfig.bridgeVersion;

    this.burpClient = new BurpJsonRpcClient({
      baseUrl: this.burpBaseUrl,
      version: this.BRIDGE_VERSION,
      requestTimeout: this.requestTimeout,
      logDebug: (message) => this.logDebug(message)
    });

    // MCP server for stdio and SSE transports
    this.server = this.createMcpServer();

    // Track active SSE sessions: sessionId -> { transport, lastSeen }
    this.sseTransports = new Map();

    // Track active streamable HTTP sessions: sessionId -> { transport, lastSeen }
    this.httpTransports = new Map();

    // HTTP server handle
    this.httpServer = null;

    // Background sweeper for idle SSE and streamable HTTP sessions
    this.sessionSweepInterval = setInterval(() => this.sweepIdleSessions(), 60_000);

    this.logInfo(`Burp MCP Bridge v${this.BRIDGE_VERSION} initializing…`);
    this.logInfo(`Transport mode: ${this.transportMode}`);
    this.logInfo(`Connecting to Burp extension at: ${this.burpBaseUrl}`);
    this.logInfo(`Request timeout: ${this.requestTimeout}ms`);
    this.logInfo(`HTTP bind: ${this.useHttps ? 'https' : 'http'}://${this.httpHost}:${this.httpPort} (loopback-only: ${this.bindLoopbackOnly})`);
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
  createMcpServer() {
    const server = new Server(
      { name: 'burp-mcp-bridge', version: this.BRIDGE_VERSION },
      { capabilities: { tools: {} } }
    );
    this.setupHandlers(server);
    return server;
  }

  setupHandlers(server = this.server) {
    registerMcpToolHandlers({
      server,
      callBurpExtension: (method, params, context) => this.callBurpExtension(method, params, context),
      burpBaseUrl: this.burpBaseUrl,
      logDebug: (message) => this.logDebug(message),
      logError: (message) => this.logError(message)
    });
  }

  // ---------- Burp JSON-RPC call
  async callBurpExtension(method, params, { rid, toolName } = {}) {
    return this.burpClient.call(method, params, { rid, toolName });
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
  // Normalize IPv6 brackets first so "[::1]" (URL.hostname form) also matches.
  isLoopbackHostname(hostname) {
    const h = stripIpv6Brackets(hostname);
    return h === 'localhost' || h === '127.0.0.1' || h === '::1';
  }

  allowedHostsFromEnv(baseSet) {
    const allowedHosts = new Set(baseSet);
    if (process.env.MCP_ALLOWED_ORIGINS) {
      for (const raw of process.env.MCP_ALLOWED_ORIGINS.split(',')) {
        const entry = raw.trim();
        if (!entry) continue;
        try {
          const u = new URL(entry);
          // A bare "example.com:3000" parses as a custom scheme with an EMPTY hostname
          // (not a real URL) — treat it as a bare host[:port] entry, not a URL.
          if (!u.hostname) {
            allowedHosts.add(normalizeBareHostEntry(entry));
          } else {
            // Normalize IPv6 brackets so "[::1]" and "::1" compare equal.
            const host = stripIpv6Brackets(u.hostname);
            const hostPort = u.port ? `${host}:${u.port}` : host;
            allowedHosts.add(hostPort);
          }
        } catch {
          // Allow bare host[:port] entries too (e.g. "example.com:3000", "[::1]:3000").
          allowedHosts.add(normalizeBareHostEntry(entry));
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

    // Default allowlist stored in unbracketed IPv6 form ("::1", not "[::1]").
    const baseAllowed = ['localhost', '127.0.0.1', '::1'];
    const allowedHosts = this.allowedHostsFromEnv(baseAllowed);

    // Check hostname and hostname:port forms. URL.hostname returns "[::1]" for IPv6,
    // so strip brackets to match the unbracketed allowlist entries.
    const originHost = stripIpv6Brackets(originUrl.hostname);
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
      'Access-Control-Allow-Methods': 'GET,POST,DELETE,OPTIONS',
      'Access-Control-Allow-Headers': 'mcp-session-id, content-type, accept, last-event-id',
      'Access-Control-Expose-Headers': 'mcp-session-id',
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
    // Only report HTTP transports as enabled if the server actually started
    if ((this.transportMode === 'http' || this.transportMode === 'both') && this.httpServer) {
      transports.push(this.httpSseTransportName, this.streamableHttpTransportName);
    }
    return transports;
  }

  createHttpTransport() {
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      enableJsonResponse: true,
      onsessioninitialized: (sessionId) => {
        this.logInfo(`New streamable HTTP session started: ${sessionId}`);
        this.httpTransports.set(sessionId, { transport, lastSeen: Date.now() });
      }
    });

    transport.onclose = () => {
      const sessionId = transport.sessionId;
      if (sessionId) {
        this.logDebug(`Streamable HTTP connection closed: ${sessionId}`);
        this.httpTransports.delete(sessionId);
      }
    };

    transport.onerror = (error) => {
      this.logError(`Streamable HTTP transport error: ${error?.message || error}`);
      const sessionId = transport.sessionId;
      if (sessionId) {
        this.httpTransports.delete(sessionId);
      }
    };

    return transport;
  }

  async handleHttpRequest(req, res) {
    // Socket-level loopback enforcement (immune to DNS rebinding / Host header spoofing)
    if (this.bindLoopbackOnly) {
      const remoteIp = req.socket.remoteAddress;
      if (remoteIp !== '127.0.0.1' && remoteIp !== '::1' && remoteIp !== '::ffff:127.0.0.1') {
        this.logError(`Rejected non-loopback connection from IP: ${remoteIp}`);
        req.socket.destroy();
        return;
      }
    }

    // Host header guard (defense in depth)
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

    // Add simple security headers on all non-streaming responses
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
        endpoints: { sse: '/mcp', streamableHttp: '/mcp', health: '/health' }
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
        activeSseSessions: this.sseTransports.size,
        activeHttpSessions: this.httpTransports.size
      };
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(payload));
      return;
    }

    if (url.pathname === '/mcp') {
      if (!['GET', 'POST', 'DELETE'].includes(req.method || '')) {
        res.writeHead(405, { 'Content-Type': 'text/plain' });
        res.end('Method Not Allowed');
        return;
      }

      if (req.method === 'POST') {
        const len = toInt(req.headers['content-length'], 0);
        if (len > this.maxPostBytes) {
          res.writeHead(413, { 'Content-Type': 'text/plain' });
          res.end('Payload Too Large');
          return;
        }
      }

      const sessionId = typeof req.headers['mcp-session-id'] === 'string'
        ? req.headers['mcp-session-id']
        : null;

      if (sessionId) {
        const sseRec = this.sseTransports.get(sessionId);
        if (sseRec) {
          if (req.method !== 'POST') {
            res.writeHead(405, { 'Content-Type': 'text/plain' });
            res.end('Method Not Allowed');
            return;
          }

          sseRec.lastSeen = Date.now();
          await sseRec.transport.handlePostMessage(req, res);
          return;
        }

        const httpRec = this.httpTransports.get(sessionId);
        if (!httpRec) {
          this.logError(`No active session found for ID: ${sessionId}`);
          res.writeHead(404, { 'Content-Type': 'text/plain' });
          res.end('Session not found');
          return;
        }

        httpRec.lastSeen = Date.now();
        await httpRec.transport.handleRequest(req, res);
        return;
      }

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

      if (req.method !== 'POST') {
        res.writeHead(400, { 'Content-Type': 'text/plain' });
        res.end('Bad Request: Missing mcp-session-id header');
        return;
      }

      if (this.httpTransports.size >= this.maxHttpSessions) {
        res.writeHead(503, { 'Content-Type': 'text/plain' });
        res.end('Service Unavailable: Too many concurrent HTTP sessions');
        return;
      }

      const transport = this.createHttpTransport();
      const server = this.createMcpServer();
      await server.connect(transport);
      await transport.handleRequest(req, res);
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
    for (const [sessionId, rec] of this.httpTransports.entries()) {
      if (now - rec.lastSeen > this.sessionIdleMs) {
        this.logInfo(`Closing idle streamable HTTP session: ${sessionId}`);
        try { rec.transport.close(); } catch {}
        this.httpTransports.delete(sessionId);
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

    // Start HTTP transport if enabled
    if (this.transportMode === 'http' || this.transportMode === 'both') {
      this.httpServer = this.buildHttpServer();

      try {
        await new Promise((resolve, reject) => {
          this.httpServer.on('error', (error) => {
            reject(error);
          });

          this.httpServer.listen(this.httpPort, this.httpHost, () => {
            const protocol = this.useHttps ? 'https' : 'http';
            this.logInfo(`✅ ${protocol.toUpperCase()} transport started on ${protocol}://${this.httpHost}:${this.httpPort}/mcp`);
            this.logInfo(`   Endpoints: /mcp (SSE + streamable HTTP), /health, /.well-known/mcp`);
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
          this.logInfo('⚠️  HTTP transport failed to start, continuing with stdio only');
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

    // Close all streamable HTTP connections
    for (const [sessionId, rec] of this.httpTransports.entries()) {
      this.logDebug(`Closing streamable HTTP session: ${sessionId}`);
      try { await rec.transport.close(); } catch (error) {
        this.logError(`Error closing streamable HTTP transport ${sessionId}: ${error.message}`);
      }
    }
    this.httpTransports.clear();

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
