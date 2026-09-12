// Keep the fallback useful when Burp is starting or an older extension omits
// initialization instructions. Current schemas and workflows come from help.
export const FALLBACK_INSTRUCTIONS = [
  'Use burp_help to search by capability or fetch a tool\'s parameters, action requirements, examples, and result fields before unfamiliar operations.',
  'Use burp_custom_http for immediate HTTP requests and protocol controls. Use burp_http_jobs for managed background batches: START returns job_id; poll STATUS and page RESULTS; PAUSE, RESUME, and CANCEL control the job. End of result pagination does not imply job completion.',
  'burp_repeater creates UI tabs and burp_intruder configures UI attacks; neither executes requests programmatically.',
  'Read each tool\'s request framing and TLS rules. Supply explicit authentication where required. Configure a browser to use Burp\'s proxy before expecting its traffic in Proxy History.',
  'Check isError and truncation fields. Tool annotations describe the entire action set; some comparison and analysis actions send fresh network requests.'
].join('\n\n');

export async function loadMcpInstructions(callBurpExtension, version, onUnavailable = () => {}) {
  try {
    const response = await callBurpExtension('initialize', {
      protocolVersion: '2025-06-18',
      capabilities: {},
      clientInfo: { name: 'burp-mcp-bridge', version }
    });
    if (response.error) throw new Error(response.error.message || 'Extension initialization failed');
    const instructions = response.result?.instructions;
    if (typeof instructions === 'string' && instructions.trim()) return instructions;
  } catch (error) {
    onUnavailable(error);
  }
  return FALLBACK_INSTRUCTIONS;
}
