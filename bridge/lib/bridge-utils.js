/**
 * Auto-fix Content-Length in raw HTTP requests.
 * LLMs frequently miscount body bytes, causing servers to hang waiting for data.
 */
export function fixContentLength(rawRequest) {
  const separator = '\r\n\r\n';
  const sepIndex = rawRequest.indexOf(separator);
  if (sepIndex === -1) return rawRequest;

  const headersPart = rawRequest.substring(0, sepIndex);
  const body = rawRequest.substring(sepIndex + separator.length);

  if (!body) return rawRequest;

  const actualLength = Buffer.byteLength(body, 'utf-8');

  const clRegex = /^Content-Length:\s*\d+$/mi;
  let fixedHeaders;
  if (clRegex.test(headersPart)) {
    fixedHeaders = headersPart.replace(clRegex, `Content-Length: ${actualLength}`);
  } else {
    fixedHeaders = headersPart + `\r\nContent-Length: ${actualLength}`;
  }

  return fixedHeaders + separator + body;
}

/**
 * Truncate MCP tool results that exceed the size limit.
 * Claude Code caps MCP results at 100,000 chars, so keep a little headroom.
 */
export const MAX_RESULT_CHARS = 95_000;

export function truncateResult(result) {
  if (!result) return result;

  const serialized = JSON.stringify(result);
  if (serialized.length <= MAX_RESULT_CHARS) return result;

  const trimmed = { ...result };
  delete trimmed.structuredContent;

  const afterDrop = JSON.stringify(trimmed);
  if (afterDrop.length <= MAX_RESULT_CHARS) return trimmed;

  if (!Array.isArray(trimmed.content)) return trimmed;

  let remaining = MAX_RESULT_CHARS;
  const truncatedContent = [];

  for (const block of trimmed.content) {
    if (block.type === 'text' && typeof block.text === 'string') {
      if (remaining <= 0) continue;
      if (block.text.length <= remaining) {
        truncatedContent.push(block);
        remaining -= block.text.length;
      } else {
        truncatedContent.push({ ...block, text: block.text.slice(0, remaining) });
        remaining = 0;
      }
    } else {
      truncatedContent.push(block);
    }
  }

  truncatedContent.push({
    type: 'text',
    text: `\n\n⚠️ Result truncated (${serialized.length.toLocaleString()} chars exceeded ${MAX_RESULT_CHARS.toLocaleString()} char limit). Use 'limit' parameter or narrower filters to reduce output size.`
  });

  return { ...trimmed, content: truncatedContent };
}

/** Parse integer envs safely with default; trims and handles empty strings. */
export function toInt(v, def) {
  const n = Number.parseInt(String(v ?? '').trim(), 10);
  return Number.isFinite(n) ? n : def;
}

/** Extract bare hostname from a Host header value (handles IPv6 [::1]:port). */
export function hostHeaderToHostname(hostHeader = '') {
  const s = String(hostHeader);
  if (s.startsWith('[')) {
    const end = s.indexOf(']');
    return end > 1 ? s.slice(1, end) : s;
  }
  return s.split(':')[0];
}

/** True if the host string is a bare (unbracketed) IPv6 literal. */
export function isBareIpv6(host = '') {
  const s = String(host);
  return s.includes(':') && !s.startsWith('[');
}

/** Strip a single surrounding pair of brackets from an IPv6 literal. */
export function stripIpv6Brackets(host = '') {
  const s = String(host);
  return s.startsWith('[') && s.endsWith(']') ? s.slice(1, -1) : s;
}

/** Wrap a bare IPv6 literal in brackets for URL use. */
export function bracketIpv6(host = '') {
  return isBareIpv6(host) ? `[${host}]` : String(host);
}

/**
 * Normalize a bare host[:port] allowlist entry to the same form the origin check uses.
 */
export function normalizeBareHostEntry(entry = '') {
  const s = String(entry).trim();
  if (s.startsWith('[')) {
    const end = s.indexOf(']');
    if (end > 1) return s.slice(1, end) + s.slice(end + 1);
  }
  return s;
}
