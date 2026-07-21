import { randomUUID } from 'node:crypto';

import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';

import { fixContentLength, truncateResult } from './bridge-utils.js';

export function prepareToolArguments(toolName, inputArguments = {}) {
  const args = { ...(inputArguments || {}) };
  if (toolName !== 'burp_custom_http') {
    return args;
  }

  const preserveBytes = args.raw_request === true || args.action === 'SEND_PIPELINED';
  if (preserveBytes) {
    return args;
  }

  if (typeof args.request === 'string') {
    args.request = fixContentLength(args.request);
  }
  if (Array.isArray(args.requests)) {
    args.requests = args.requests.map((request) => typeof request === 'string' ? fixContentLength(request) : request);
  }
  return args;
}

export function registerMcpToolHandlers({
  server,
  callBurpExtension,
  burpBaseUrl,
  logDebug = () => {},
  logError = () => {},
  requestIdFactory = randomUUID
}) {
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    const rid = requestIdFactory();
    try {
      logDebug(`[${rid}] Requesting tools list from Burp extension`);
      const response = await callBurpExtension('tools/list', {}, { rid });
      const count = response?.result?.tools?.length ?? 0;
      logDebug(`[${rid}] Received ${count} tools from Burp extension`);
      return response.result;
    } catch (error) {
      logError(`[${rid}] Error getting tools list: ${error.message}`);
      return { tools: [] };
    }
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const rid = requestIdFactory();
    const toolName = request.params.name;
    try {
      logDebug(`[${rid}] Calling tool: ${toolName}`);
      const args = prepareToolArguments(toolName, request.params.arguments);
      const response = await callBurpExtension(
        'tools/call',
        { name: toolName, arguments: args },
        { rid, toolName }
      );

      if (response.error) {
        const msg = String(response.error.message || 'Unknown error');
        logError(`[${rid}] Tool ${toolName} returned error: ${msg}`);
        return { content: [{ type: 'text', text: `❌ Error: ${msg}` }], isError: true };
      }

      logDebug(`[${rid}] Tool ${toolName} completed successfully`);
      return truncateResult(response.result);
    } catch (error) {
      logError(`[${rid}] Error calling tool ${toolName}: ${error.message}`);
      return {
        content: [{
          type: 'text',
          text:
            `❌ Connection Error: ${error.message}\n\n` +
            `Troubleshooting:\n` +
            `• Ensure Burp Suite Professional is running\n` +
            `• Verify Burp MCP Bridge extension is loaded\n` +
            `• Check that ${burpBaseUrl} is reachable`
        }],
        isError: true
      };
    }
  });
}
