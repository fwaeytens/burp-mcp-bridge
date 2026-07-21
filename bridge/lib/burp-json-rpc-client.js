export class BurpJsonRpcClient {
  constructor({
    baseUrl,
    version,
    requestTimeout,
    fetchImpl = globalThis.fetch,
    logDebug = () => {}
  }) {
    this.baseUrl = baseUrl;
    this.version = version;
    this.requestTimeout = requestTimeout;
    this.fetchImpl = fetchImpl;
    this.logDebug = logDebug;
  }

  async call(method, params, { rid, toolName } = {}) {
    const requestBody = {
      jsonrpc: '2.0',
      id: Date.now(),
      method,
      params
    };

    const headers = {
      'Content-Type': 'application/json',
      'User-Agent': `Burp-MCP-Bridge/${this.version}`,
      ...(rid ? { 'X-Request-Id': rid } : {}),
      ...(toolName ? { 'X-Tool-Name': String(toolName) } : {})
    };

    this.logDebug(`${rid ? `[${rid}] ` : ''}Sending request to Burp: ${method}`);

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.requestTimeout);

    try {
      const response = await this.fetchImpl(this.baseUrl, {
        method: 'POST',
        headers,
        body: JSON.stringify(requestBody),
        signal: controller.signal
      });

      if (!response.ok) {
        if (response.status === 404) {
          throw new Error(`Burp MCP extension endpoint not found at ${this.baseUrl}. Is the extension loaded?`);
        }
        if (response.status >= 500) {
          throw new Error(`Burp extension server error (${response.status}): ${response.statusText}`);
        }
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const raw = await response.text();
      let result;
      try {
        result = JSON.parse(raw);
      } catch {
        throw new Error('Invalid JSON response from Burp extension');
      }

      const valid = result && result.jsonrpc === '2.0' && ('result' in result || 'error' in result);
      if (!valid) {
        throw new Error('Invalid JSON-RPC response from Burp extension');
      }

      this.logDebug(`${rid ? `[${rid}] ` : ''}Received response from Burp: ${result.error ? 'ERROR' : 'SUCCESS'}`);
      return result;
    } catch (error) {
      if (error.name === 'AbortError') {
        throw new Error(`Request timeout after ${this.requestTimeout}ms. Burp extension may be overloaded.`);
      }
      const code = error.code || error.cause?.code;
      if (code === 'ECONNREFUSED') {
        throw new Error(`Cannot connect to Burp extension at ${this.baseUrl}. Is Burp Suite running with the MCP Bridge extension loaded?`);
      }
      throw error;
    } finally {
      clearTimeout(timeoutId);
    }
  }
}
