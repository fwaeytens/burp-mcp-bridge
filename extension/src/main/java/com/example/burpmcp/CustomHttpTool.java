package com.example.burpmcp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.RedirectionMode;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpTransformation;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.Cookie;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import java.nio.charset.StandardCharsets;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.ByteArrayOutputStream;
import java.net.InetSocketAddress;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.UUID;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.ArrayNode;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.time.Duration;

public class CustomHttpTool implements McpTool {
    private final MontoyaApi api;
    private final ObjectMapper mapper = new ObjectMapper();
    private static final Map<String, Long> connectionLastUsed = new ConcurrentHashMap<>();
    private static final long CONNECTION_TIMEOUT_MS = 30000; // 30 seconds
    private static final List<String> SUPPORTED_ACTIONS = List.of(
        "SEND_REQUEST",
        "SEND_PARALLEL",
        "SEND_PIPELINED",
        "TOGGLE_REQUEST_METHOD",
        "ANALYZE_PROTOCOL"
    );

    public CustomHttpTool(MontoyaApi api) {
        this.api = api;
    }

    @Override
    public Map<String, Object> getToolInfo() {
        Map<String, Object> tool = new HashMap<>();
        tool.put("name", "burp_custom_http");
        tool.put("title", "HTTP Client (Primary)");
        tool.put("description", "PRIMARY TOOL for sending HTTP requests and receiving responses programmatically. " +
            "CRITICAL: ALWAYS specify port in Host header - use 'Host: example.com:80' for HTTP or 'Host: example.com:443' for HTTPS. " +
            "Without explicit port, defaults to HTTPS:443 which causes timeouts on HTTP-only servers. " +
            "Content-Length is automatically calculated - no need to specify it accurately. " +
            "Line endings are auto-normalized (LF to CRLF). " +
            "Actions: SEND_REQUEST (single request), SEND_PARALLEL (race condition testing with array of requests), " +
            "SEND_PIPELINED (HTTP/1.1 only — write 2-20 raw requests back-to-back on ONE TLS socket, for CL.0/TE.CL/CL.TE/TE.0/0.CL/connection-state smuggling labs), " +
            "TOGGLE_REQUEST_METHOD (GET<>POST), ANALYZE_PROTOCOL (HTTP/HTTPS detection). " +
            "Supports HTTP/1.1, HTTP/2, SNI, redirects, and connection reuse. " +
            "BROWSER SYNC: By default, copies headers from proxy traffic and cookies from Burp's cookie jar. " +
            "ADVANCED: Use target_host/target_port to decouple TCP destination from Host header (host-header SSRF). " +
            "Use raw_request=true to preserve absolute-URI request lines verbatim (parser-discrepancy / request-smuggling tests). " +
            "SEND_PARALLEL: defaults to max_concurrency=10 to prevent tail-of-batch drops; pass max_concurrency=50 to opt back into " +
            "fire-all-at-once behavior for race-condition tests. Use this instead of burp_repeater (which only opens UI tabs). " +
            "HISTORY VISIBILITY: route_via_proxy tunnels the request through Burp's local proxy listener (default 127.0.0.1:8080) " +
            "so it appears in Proxy → HTTP history. Default is TRUE for SEND_REQUEST (normal day-to-day testing) and FALSE for " +
            "SEND_PARALLEL / SEND_PIPELINED (proxy may serialize parallel work or break pipelined smuggling semantics). " +
            "Set route_via_proxy=false on SEND_REQUEST when you need byte-exact wire behavior (raw_request smuggling, host-header tricks " +
            "that proxy match/replace would clobber). Set route_via_proxy=true on SEND_PARALLEL/SEND_PIPELINED only when you accept " +
            "those caveats and want history visibility. When route_via_proxy is on, http_mode is forced to HTTP/1.1, redirection_mode " +
            "is ignored (handle redirects yourself), and connection_id is ignored — all options that only the Montoya direct-send path supports.");

        // MCP 2025-06-18 annotations
        Map<String, Object> annotations = new HashMap<>();
        annotations.put("readOnlyHint", false);
        annotations.put("destructiveHint", false);
        annotations.put("idempotentHint", false);
        annotations.put("openWorldHint", true);
        annotations.put("title", "HTTP Client (Primary)");
        tool.put("annotations", annotations);

        Map<String, Object> meta = new HashMap<>();
        meta.put("anthropic/alwaysLoad", true);
        meta.put("anthropic/searchHint", "send raw HTTP request modify replay fuzz");
        tool.put("_meta", meta);

        Map<String, Object> inputSchema = new HashMap<>();
        Map<String, Object> properties = new HashMap<>();

        properties.put("action", Map.of(
            "type", "string",
            "enum", SUPPORTED_ACTIONS,
            "description", "The HTTP action to perform. SEND_REQUEST sends a single request, SEND_PARALLEL sends multiple for race conditions, " +
                "TOGGLE_REQUEST_METHOD converts GET↔POST, ANALYZE_PROTOCOL checks HTTP/HTTPS configuration"
        ));
        
        properties.put("request", Map.of(
            "type", "string",
            "description", "Raw HTTP request string. Line endings auto-normalized. " +
                "ALWAYS include port in Host header: 'Host: example.com:80' for HTTP, 'Host: example.com:443' for HTTPS. " +
                "Example: 'GET /path HTTP/1.1\\r\\nHost: example.com:80\\r\\nConnection: close\\r\\n\\r\\n'. " +
                "Without port, defaults to HTTPS:443 causing timeouts on HTTP-only servers."
        ));
        
        properties.put("requests", Map.of(
            "type", "array",
            "description", "Array of raw HTTP request strings for parallel/race condition testing. Line endings auto-normalized. " +
                "ALWAYS include port in Host header: ':80' for HTTP, ':443' for HTTPS. " +
                "Without port, defaults to HTTPS:443 causing timeouts on HTTP-only servers.",
            "items", Map.of("type", "string")
        ));
        
        properties.put("http_mode", Map.of(
            "type", "string",
            "enum", Arrays.asList("HTTP_1", "HTTP_2", "HTTP_2_IGNORE_ALPN", "AUTO"),
            "description", "HTTP protocol version. HTTP_1 for standard HTTP/1.1, HTTP_2 for multiplexed HTTP/2, " +
                "HTTP_2_IGNORE_ALPN for HTTP/2 without ALPN negotiation (useful for non-standard implementations), " +
                "AUTO lets Burp choose the best protocol",
            "default", "AUTO"
        ));
        
        properties.put("connection_id", Map.of(
            "type", "string",
            "description", "Unique identifier for connection reuse. Requests with the same connection_id will use the same TCP connection. " +
                "Useful for maintaining session state or testing connection-specific behaviors"
        ));
        
        properties.put("redirection_mode", Map.of(
            "type", "string",
            "enum", Arrays.asList("ALWAYS", "NEVER", "SAME_HOST", "IN_SCOPE"),
            "description", "How to handle HTTP redirects. ALWAYS follows all redirects, NEVER ignores all redirects, " +
                "SAME_HOST only follows redirects to the same host (prevents redirect to external sites), " +
                "IN_SCOPE only follows redirects to targets in Burp's scope",
            "default", "NEVER"
        ));
        
        properties.put("follow_redirects", Map.of(
            "type", "boolean",
            "description", "⚠️ DEPRECATED — DO NOT USE. Use redirection_mode instead. " +
                "[DEPRECATED - use redirection_mode instead] Legacy boolean for redirect following. " +
                "true maps to ALWAYS, false maps to NEVER. Maintained for backward compatibility"
        ));
        
        properties.put("upstream_tls_verification", Map.of(
            "type", "boolean",
            "description", "Enable TLS certificate verification for upstream servers. When true, validates SSL/TLS certificates. " +
                "Useful for testing certificate validation bypasses or connecting to servers with self-signed certificates",
            "default", false
        ));

        properties.put("allow_h2c", Map.of(
            "type", "boolean",
            "description", "Allow HTTP/2 cleartext (h2c) mode for non-TLS connections. When true, attempts HTTP/2 without TLS. " +
                "Note: Server must support h2c protocol upgrade. Most servers only support HTTP/2 over TLS",
            "default", false
        ));

        properties.put("add_to_sitemap", Map.of(
            "type", "boolean",
            "description", "Add the request/response to Burp's Site Map for visibility and further testing. " +
                "This makes requests from burp_custom_http visible in Target > Site Map. Default: true",
            "default", true
        ));

        properties.put("use_cookie_jar", Map.of(
            "type", "boolean",
            "description", "Automatically include cookies from Burp's cookie jar for the target domain. " +
                "COOKIE BEHAVIOR: (1) Default true = cookies from jar are merged with request's Cookie header, " +
                "ensuring requests use the same authenticated session as browser traffic through the proxy. " +
                "(2) Request cookies take PRECEDENCE - if you specify 'Cookie: session=abc' and jar has 'session=xyz', " +
                "YOUR 'session=abc' is used; only jar cookies with DIFFERENT names are added. " +
                "(3) Set to FALSE when you want to: test with a completely different session, " +
                "send unauthenticated requests, or test access control by using only cookies you explicitly specify. " +
                "EXAMPLES: To use browser session = omit Cookie header (jar provides all). " +
                "To override one cookie = include it in request (yours wins, jar adds others). " +
                "To use completely custom cookies = set use_cookie_jar:false and specify your own Cookie header.",
            "default", true
        ));

        properties.put("use_proxy_headers", Map.of(
            "type", "boolean",
            "description", "Automatically copy headers from the most recent proxy history entry for the same host. " +
                "HEADER BEHAVIOR: (1) Default true = finds the most recent browser request to the same host in proxy history " +
                "and copies headers like User-Agent, Accept, Sec-Ch-*, Sec-Fetch-*, Accept-Language, Accept-Encoding, etc. " +
                "(2) Request headers take PRECEDENCE - any headers you specify in your request will NOT be overwritten. " +
                "(3) Cookie header is handled separately by use_cookie_jar, not copied from proxy history. " +
                "(4) Set to FALSE when you want complete control over headers or are testing header-specific vulnerabilities. " +
                "This ensures requests look like realistic browser traffic without manually copying headers.",
            "default", true
        ));

        properties.put("response_timeout", Map.of(
            "type", "number",
            "description", "Maximum time to wait for a response in milliseconds. Prevents hanging on slow endpoints. " +
                "Range: 100-600000 (0.1 second to 10 minutes)",
            "minimum", 100,
            "maximum", 600000,
            "default", 30000
        ));
        
        properties.put("server_name_indicator", Map.of(
            "type", "string",
            "description", "Server Name Indication (SNI) hostname for TLS connections. Overrides the default SNI derived from the Host header. " +
                "Useful for testing virtual hosting, CDN configurations, or SNI-based routing. Example: 'admin.example.com'",
            "format", "hostname"
        ));
        
        properties.put("url", Map.of(
            "type", "string",
            "description", "URL to analyze in ANALYZE_PROTOCOL action. Alternative to providing a full request. " +
                "The tool will determine if it's HTTP or HTTPS, extract port information, and check for default ports. " +
                "Example: 'https://example.com:8443/api'",
            "format", "uri"
        ));

        properties.put("target_host", Map.of(
            "type", "string",
            "description", "TCP destination hostname or IP. Overrides whatever is in the Host header. " +
                "Required for host-header SSRF / routing-based SSRF / virtual-host confusion attacks where the " +
                "Host header must lie (e.g. Host: 192.168.0.1) while the socket still hits the real front-end. " +
                "When set with server_name_indicator and an IP, the SNI is used for TLS and the IP for the socket. " +
                "If unset, falls back to parsing the Host header (current behavior)."
        ));

        properties.put("target_port", Map.of(
            "type", "integer",
            "description", "TCP destination port (paired with target_host). Defaults to 443 if HTTPS, else 80. " +
                "Range: 1-65535.",
            "minimum", 1,
            "maximum", 65535
        ));

        properties.put("raw_request", Map.of(
            "type", "boolean",
            "description", "Send the request bytes verbatim: no request-line rewriting (absolute-URI form preserved), " +
                "no URL re-parsing, no implicit Host-header insertion, no header reordering. " +
                "Line endings are still normalized LF->CRLF. " +
                "Required for parser-discrepancy / request-smuggling tests where front-end and back-end disagree " +
                "on how to interpret 'GET https://victim.com/admin HTTP/1.1' vs the Host header. " +
                "Default false (current parsing behavior preserved).",
            "default", false
        ));

        properties.put("max_concurrency", Map.of(
            "type", "integer",
            "description", "SEND_PARALLEL only. Maximum number of in-flight requests at any moment. " +
                "Requests beyond this wait in a FIFO queue. Default 10 (bug-fix: previously unbounded, " +
                "which caused tail requests to be silently dropped as 'No response' on large batches). " +
                "Range: 1-50. Set to 50 to opt back into burst/fire-all-at-once behavior for race-condition testing.",
            "minimum", 1,
            "maximum", 50,
            "default", 10
        ));

        properties.put("request_delay_ms", Map.of(
            "type", "integer",
            "description", "SEND_PARALLEL only. Minimum gap in milliseconds between dispatching successive requests from the queue. " +
                "0 = no pacing (fire as fast as max_concurrency allows). Useful for rate-limited targets. Range: 0-10000.",
            "minimum", 0,
            "maximum", 10000,
            "default", 0
        ));

        properties.put("inter_request_delay_ms", Map.of(
            "type", "integer",
            "description", "SEND_PIPELINED only. Gap (ms) between writing successive requests to the SAME socket. " +
                "0 (default) = concatenate all bytes and send in a single write() — required for most smuggling attacks. " +
                ">0 = write each request, sleep, write next — used for pause-based desync and timing-sensitive attacks. " +
                "Range: 0-10000.",
            "minimum", 0,
            "maximum", 10000,
            "default", 0
        ));

        properties.put("expect_responses", Map.of(
            "type", "integer",
            "description", "SEND_PIPELINED only. Number of HTTP responses to wait for before closing the socket. " +
                "Defaults to requests.length. Override when smuggling shapes consume requests asymmetrically (e.g. the smuggled " +
                "request may be absorbed by the back-end queue and produce no client-visible response). Range: 0-50.",
            "minimum", 0,
            "maximum", 50
        ));

        properties.put("route_via_proxy", Map.of(
            "type", "boolean",
            "description", "Tunnel the request(s) through Burp's local proxy listener so they appear in Proxy → HTTP history. " +
                "DEFAULTS: TRUE for SEND_REQUEST (history visibility is usually what you want), FALSE for SEND_PARALLEL and " +
                "SEND_PIPELINED (proxy may serialize parallel dispatch and almost certainly breaks pipelined-smuggling framing " +
                "since Burp re-frames requests on its own upstream connections). " +
                "MECHANISM: opens TCP to proxy_host:proxy_port, sends CONNECT target:port, then (for HTTPS targets) wraps the " +
                "tunnel in TLS, then sends the actual request bytes. Burp decrypts, logs to HTTP history, and forwards upstream. " +
                "TRADE-OFFS WHEN ON: (1) http_mode is forced to HTTP/1.1 (proxy CONNECT path can't multiplex H2), " +
                "(2) redirection_mode is ignored (you must follow redirects yourself), (3) connection_id is ignored, " +
                "(4) Burp's match/replace and proxy interception rules apply to the request — bad for raw_request byte-exact tests. " +
                "TURN OFF when: you need raw byte fidelity (smuggling labs), you're testing through a flaky/dead proxy, or you " +
                "want HTTP/2 / redirects / connection reuse. " +
                "TURN ON when: you want the requests visible in HTTP history for review / cross-referencing with browser traffic."
        ));

        properties.put("proxy_host", Map.of(
            "type", "string",
            "description", "Hostname or IP of Burp's proxy listener. Used only when route_via_proxy=true. Default: 127.0.0.1.",
            "default", "127.0.0.1"
        ));

        properties.put("proxy_port", Map.of(
            "type", "integer",
            "description", "Port of Burp's proxy listener. Used only when route_via_proxy=true. Default: 8080. Range: 1-65535.",
            "minimum", 1,
            "maximum", 65535,
            "default", 8080
        ));

        properties.put("read_timeout_ms", Map.of(
            "type", "integer",
            "description", "SEND_PIPELINED only. After expect_responses have been parsed, wait this many ms for any trailing bytes " +
                "(stray queued responses, poisoned response from previous victim) before closing. Also serves as the per-read socket " +
                "timeout during the main read loop. Range: 100-60000.",
            "minimum", 100,
            "maximum", 60000,
            "default", 5000
        ));
        
        inputSchema.put("type", "object");
        inputSchema.put("properties", properties);
        inputSchema.put("required", Arrays.asList("action"));

        // Action-specific required parameters validated at runtime (allOf removed for Claude API compatibility)

        tool.put("inputSchema", inputSchema);

        // Output schema
        Map<String, Object> outputProps = new HashMap<>();
        outputProps.put("success", SchemaHelper.boolProp("Whether the request was sent successfully"));
        outputProps.put("request", SchemaHelper.objectProp("Request metadata (url, method, http_version)"));
        outputProps.put("response", SchemaHelper.objectProp("Response data (status_code, headers, body, response_time_ms)"));
        tool.put("outputSchema", SchemaHelper.outputSchema(outputProps));

        return tool;
    }

    @Override
    public Object execute(JsonNode arguments) throws Exception {
        try {
            McpUtils.ActionResolution actionResolution = McpUtils.resolveAction(arguments, SUPPORTED_ACTIONS);
            if (actionResolution.hasError()) {
                return McpUtils.createErrorResponse(actionResolution.getErrorMessage());
            }

            String action = actionResolution.getAction();

            switch (action) {
                case "SEND_REQUEST":
                    return sendRequest(arguments);
                case "SEND_PARALLEL":
                    return sendParallelRequests(arguments);
                case "SEND_PIPELINED":
                    return sendPipelined(arguments);
                case "TOGGLE_REQUEST_METHOD":
                    return toggleRequestMethod(arguments);
                case "ANALYZE_PROTOCOL":
                    return analyzeProtocol(arguments);
                default:
                    return McpUtils.createErrorResponse("Unknown action: " + action + ". " +
                        "For response analysis use burp_response_analyzer. For session management use burp_session_management.");
            }
        } catch (Exception e) {
            api.logging().logToError("Error in CustomHttpTool: " + e.getMessage());
            return McpUtils.createErrorResponse("Error: " + e.getMessage());
        }
    }

    private Object sendRequest(JsonNode arguments) {
        if (!arguments.has("request")) {
            return McpUtils.createErrorResponse("Request is required");
        }

        try {
            String requestStr = McpUtils.getStringParam(arguments, "request", "");

            // Use the same logic as SEND_PARALLEL but with a single request
            // This works reliably while sendRequest() has issues
            HttpRequest request = createHttpRequest(requestStr, arguments);

            // Apply headers from proxy history (default: enabled) - must be before cookies
            request = applyHeadersFromProxyHistory(request, arguments);

            // Apply cookies from Burp's cookie jar (default: enabled)
            request = applyCookiesFromJar(request, arguments);

            // Route via Burp's proxy listener so the request appears in HTTP history?
            // SEND_REQUEST defaults TRUE — this is the day-to-day behaviour users expect.
            // Caller can disable for byte-exact tests.
            boolean routeViaProxy = resolveRouteViaProxy(arguments, true);
            if (routeViaProxy) {
                return sendRequestViaProxyTunnel(request, arguments);
            }

            HttpRequestResponse response = sendSingleRequestWithOptions(request, arguments);

            if (response == null) {
                return McpUtils.createErrorResponse("No response received");
            }

            // Add to site map if requested (default: true)
            boolean addToSiteMap = McpUtils.getBooleanParam(arguments, "add_to_sitemap", true);
            if (addToSiteMap && response.response() != null) {
                try {
                    // Add annotation to identify this as an MCP request
                    HttpRequestResponse annotatedResponse = response.withAnnotations(
                        Annotations.annotations("MCP: burp_custom_http request"));
                    api.siteMap().add(annotatedResponse);
                    api.logging().logToOutput("CustomHttpTool: Added request to site map with annotation: " + response.request().url());
                } catch (Exception e) {
                    api.logging().logToError("CustomHttpTool: Failed to add to site map: " + e.getMessage());
                }
            }

            ObjectNode result = mapper.createObjectNode();
            result.put("success", true);
            result.put("added_to_sitemap", addToSiteMap && response.response() != null);
            
            // Request details
            ObjectNode reqDetails = mapper.createObjectNode();
            reqDetails.put("url", response.request().url());
            reqDetails.put("method", response.request().method());
            reqDetails.put("http_version", response.request().httpVersion());
            result.set("request", reqDetails);
            
            // Response details
            if (response.response() != null) {
                HttpResponse resp = response.response();
                ObjectNode respDetails = mapper.createObjectNode();
                respDetails.put("status_code", resp.statusCode());
                respDetails.put("reason_phrase", resp.reasonPhrase());
                respDetails.put("http_version", resp.httpVersion());
                respDetails.put("body_length", resp.body().length());
                respDetails.put("mime_type", resp.statedMimeType().toString());
                
                // Timing data if available
                if (response.timingData().isPresent()) {
                    Duration responseTime = response.timingData().get().timeBetweenRequestSentAndEndOfResponse();
                    respDetails.put("response_time_ms", responseTime.toMillis());
                }
                
                // Include headers
                ArrayNode headers = mapper.createArrayNode();
                for (var header : resp.headers()) {
                    ObjectNode h = mapper.createObjectNode();
                    h.put("name", header.name());
                    h.put("value", header.value());
                    headers.add(h);
                }
                respDetails.set("headers", headers);
                
                // Include body (truncated if large)
                String body = resp.bodyToString();
                if (body.length() > 5000) {
                    body = body.substring(0, 5000) + "\n... [truncated]";
                }
                respDetails.put("body", body);
                
                result.set("response", respDetails);
            } else {
                result.put("error", "No response received");
            }
            
            return McpUtils.createSuccessResponse(result.toString());
            
        } catch (Exception e) {
            String errorMsg = "CustomHttpTool.sendRequest error: " + e.getMessage();
            api.logging().logToError(errorMsg);
            api.logging().logToError("Stack trace: " + getStackTraceString(e));
            return McpUtils.createErrorResponse("Failed to send request: " + e.getMessage());
        }
    }

    /**
     * SEND_REQUEST via Burp's local proxy listener. Tunnels through CONNECT so the
     * request lands in Proxy → HTTP history. Same response shape as the direct path.
     */
    private Object sendRequestViaProxyTunnel(HttpRequest request, JsonNode arguments) {
        warnIgnoredOptionsOnProxyPath(arguments, "SEND_REQUEST");
        try {
            HttpService svc = request.httpService();
            int timeout = 30000;
            if (arguments.has("response_timeout") && arguments.get("response_timeout").canConvertToLong()) {
                long t = arguments.get("response_timeout").asLong(30000L);
                if (t >= 100 && t <= 600000) timeout = (int) t;
            }
            boolean tlsVerify = arguments.has("upstream_tls_verification") && arguments.get("upstream_tls_verification").asBoolean(false);
            String sni = McpUtils.getTrimmedStringParam(arguments, "server_name_indicator");
            ProxyTunnelConfig cfg = new ProxyTunnelConfig(
                proxyHostOf(arguments), proxyPortOf(arguments),
                svc.host(), svc.port(), svc.secure(),
                sni, tlsVerify, timeout);

            byte[] reqBytes = request.toByteArray().getBytes();
            long start = System.currentTimeMillis();
            api.logging().logToOutput("CustomHttpTool: route_via_proxy=true SEND_REQUEST tunnelling " +
                svc.host() + ":" + svc.port() + " via " + cfg.proxyHost + ":" + cfg.proxyPort +
                (svc.secure() ? " (TLS)" : " (cleartext)"));
            ParsedResponse pr = sendOneViaTunnel(reqBytes, cfg);
            long elapsed = System.currentTimeMillis() - start;

            ObjectNode result = mapper.createObjectNode();
            result.put("success", true);
            result.put("routed_via_proxy", true);
            result.put("proxy", cfg.proxyHost + ":" + cfg.proxyPort);
            // Sitemap is intentionally skipped — Burp's proxy logs to HTTP history natively.
            result.put("added_to_sitemap", false);

            ObjectNode reqDetails = mapper.createObjectNode();
            reqDetails.put("url", request.url());
            reqDetails.put("method", request.method());
            reqDetails.put("http_version", request.httpVersion());
            result.set("request", reqDetails);

            ObjectNode respDetails = mapper.createObjectNode();
            if (pr.parseError != null) {
                respDetails.put("parse_error", pr.parseError);
                respDetails.put("raw_bytes", Base64.getEncoder().encodeToString(pr.rawBytes));
            } else {
                respDetails.put("status_code", pr.statusCode);
                respDetails.put("reason_phrase", pr.reasonPhrase);
                respDetails.put("http_version", pr.httpVersion);
                respDetails.put("body_length", pr.body.length);
                respDetails.put("response_time_ms", elapsed);
                ArrayNode headers = mapper.createArrayNode();
                for (Map.Entry<String, String> e : pr.headers.entrySet()) {
                    ObjectNode h = mapper.createObjectNode();
                    h.put("name", e.getKey());
                    h.put("value", e.getValue());
                    headers.add(h);
                }
                respDetails.set("headers", headers);
                String body = new String(pr.body, StandardCharsets.ISO_8859_1);
                if (body.length() > 5000) body = body.substring(0, 5000) + "\n... [truncated]";
                respDetails.put("body", body);
            }
            result.set("response", respDetails);

            return McpUtils.createSuccessResponse(result.toString());
        } catch (Exception e) {
            String msg = "Proxy-tunnel send failed: " + e.getMessage() +
                ". Burp proxy listener reachable at " + proxyHostOf(arguments) + ":" + proxyPortOf(arguments) + "? " +
                "Set route_via_proxy=false to bypass the proxy.";
            api.logging().logToError("CustomHttpTool: " + msg);
            return McpUtils.createErrorResponse(msg);
        }
    }

    /**
     * SEND_PARALLEL via Burp's proxy listener. Each worker opens its own CONNECT tunnel
     * — extra TLS handshake per request, but each lands in HTTP history independently.
     */
    private Object sendParallelRequestsViaProxyTunnel(List<HttpRequest> requests, JsonNode arguments) {
        warnIgnoredOptionsOnProxyPath(arguments, "SEND_PARALLEL");
        int n = requests.size();
        int maxConcurrency = 10;
        if (arguments.has("max_concurrency") && arguments.get("max_concurrency").canConvertToInt()) {
            maxConcurrency = Math.min(50, Math.max(1, arguments.get("max_concurrency").asInt(10)));
        }
        int delayMs = 0;
        if (arguments.has("request_delay_ms") && arguments.get("request_delay_ms").canConvertToInt()) {
            delayMs = Math.min(10000, Math.max(0, arguments.get("request_delay_ms").asInt(0)));
        }
        int timeout = 30000;
        if (arguments.has("response_timeout") && arguments.get("response_timeout").canConvertToLong()) {
            long t = arguments.get("response_timeout").asLong(30000L);
            if (t >= 100 && t <= 600000) timeout = (int) t;
        }
        boolean tlsVerify = arguments.has("upstream_tls_verification") && arguments.get("upstream_tls_verification").asBoolean(false);
        String sni = McpUtils.getTrimmedStringParam(arguments, "server_name_indicator");
        String proxyHost = proxyHostOf(arguments);
        int proxyPort = proxyPortOf(arguments);

        api.logging().logToOutput("CustomHttpTool: route_via_proxy=true SEND_PARALLEL dispatching " + n +
            " requests via " + proxyHost + ":" + proxyPort + " (max_concurrency=" + maxConcurrency + ")");

        ParsedResponse[] results = new ParsedResponse[n];
        long[] elapsed = new long[n];
        int poolSize = Math.min(maxConcurrency, Math.max(1, n));
        ExecutorService exec = Executors.newFixedThreadPool(poolSize);
        Semaphore slots = new Semaphore(maxConcurrency);
        List<Future<?>> futures = new ArrayList<>(n);
        final int finalTimeout = timeout;
        final boolean finalTlsVerify = tlsVerify;
        final String finalSni = sni;
        long startAll = System.currentTimeMillis();
        try {
            long lastDispatch = 0;
            for (int i = 0; i < n; i++) {
                final int idx = i;
                final HttpRequest req = requests.get(i);
                slots.acquire();
                if (delayMs > 0 && lastDispatch != 0) {
                    long wait = lastDispatch + delayMs - System.currentTimeMillis();
                    if (wait > 0) Thread.sleep(wait);
                }
                lastDispatch = System.currentTimeMillis();
                futures.add(exec.submit(() -> {
                    long s = System.currentTimeMillis();
                    try {
                        HttpService svc = req.httpService();
                        ProxyTunnelConfig cfg = new ProxyTunnelConfig(
                            proxyHost, proxyPort,
                            svc.host(), svc.port(), svc.secure(),
                            finalSni, finalTlsVerify, finalTimeout);
                        results[idx] = sendOneViaTunnel(req.toByteArray().getBytes(), cfg);
                    } catch (Exception e) {
                        ParsedResponse err = new ParsedResponse();
                        err.parseError = "dispatch failed: " + e.getMessage();
                        results[idx] = err;
                    } finally {
                        elapsed[idx] = System.currentTimeMillis() - s;
                        slots.release();
                    }
                }));
            }
            for (Future<?> f : futures) f.get();
        } catch (Exception e) {
            Thread.currentThread().interrupt();
            return McpUtils.createErrorResponse("Failed to send parallel requests via proxy: " + e.getMessage());
        } finally {
            exec.shutdown();
            try {
                if (!exec.awaitTermination(5, TimeUnit.SECONDS)) exec.shutdownNow();
            } catch (InterruptedException ie) {
                exec.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }

        ObjectNode result = mapper.createObjectNode();
        result.put("success", true);
        result.put("routed_via_proxy", true);
        result.put("proxy", proxyHost + ":" + proxyPort);
        result.put("total_requests", n);
        result.put("total_responses", n);
        // Sitemap is intentionally skipped — Burp's proxy logs to HTTP history natively.
        result.put("added_to_sitemap", 0);

        ArrayNode respArr = mapper.createArrayNode();
        long totalTime = 0;
        int responseCount = 0;
        for (int i = 0; i < n; i++) {
            ObjectNode r = mapper.createObjectNode();
            r.put("index", i);
            r.put("url", requests.get(i).url());
            ParsedResponse pr = results[i];
            if (pr == null || pr.parseError != null) {
                r.put("error", pr == null ? "dispatch failed" : pr.parseError);
                r.put("error_type", "dispatch_failed");
            } else {
                r.put("status_code", pr.statusCode);
                r.put("body_length", pr.body.length);
                r.put("response_time_ms", elapsed[i]);
                totalTime += elapsed[i];
                responseCount++;
            }
            respArr.add(r);
        }
        result.set("responses", respArr);

        ObjectNode stats = mapper.createObjectNode();
        stats.put("total_time_ms", System.currentTimeMillis() - startAll);
        stats.put("average_time_ms", responseCount > 0 ? totalTime / responseCount : 0);
        result.set("statistics", stats);

        return McpUtils.createSuccessResponse(result.toString());
    }

    private void warnIgnoredOptionsOnProxyPath(JsonNode arguments, String action) {
        if (arguments == null) return;
        List<String> ignored = new ArrayList<>();
        if (arguments.has("http_mode")) {
            String m = McpUtils.getStringParam(arguments, "http_mode", "AUTO");
            if (m != null && m.contains("HTTP_2")) ignored.add("http_mode=" + m + " (forced HTTP/1.1)");
        }
        if (arguments.has("redirection_mode")) ignored.add("redirection_mode (follow redirects yourself)");
        if (arguments.has("follow_redirects") && arguments.get("follow_redirects").asBoolean(false)) {
            ignored.add("follow_redirects (follow redirects yourself)");
        }
        if (arguments.has("connection_id")) {
            String cid = McpUtils.getTrimmedStringParam(arguments, "connection_id");
            if (cid != null && !cid.isEmpty()) ignored.add("connection_id (per-call tunnels)");
        }
        if (!ignored.isEmpty()) {
            api.logging().logToOutput("CustomHttpTool: " + action + " route_via_proxy=true ignores: " + String.join(", ", ignored));
        }
    }

    private Object sendParallelRequests(JsonNode arguments) {
        if (!arguments.has("requests") || !arguments.get("requests").isArray()) {
            return McpUtils.createErrorResponse("Requests array is required");
        }

        try {
            List<HttpRequest> requests = new ArrayList<>();
            for (JsonNode reqNode : arguments.get("requests")) {
                HttpRequest req = createHttpRequest(reqNode.asText(), arguments);
                // Apply headers from proxy history (default: enabled) - must be before cookies
                req = applyHeadersFromProxyHistory(req, arguments);
                // Apply cookies from Burp's cookie jar (default: enabled)
                req = applyCookiesFromJar(req, arguments);
                requests.add(req);
            }

            // SEND_PARALLEL defaults to direct (Montoya) send. Caller must explicitly
            // opt in to route_via_proxy=true to accept the trade-off (proxy may serialize
            // dispatch, match/replace rewrites apply).
            boolean routeViaProxy = resolveRouteViaProxy(arguments, false);
            if (routeViaProxy) {
                return sendParallelRequestsViaProxyTunnel(requests, arguments);
            }

            List<HttpRequestResponse> responses = sendBatchRequests(requests, arguments);

            // Add to site map if requested (default: true)
            boolean addToSiteMap = McpUtils.getBooleanParam(arguments, "add_to_sitemap", true);
            int addedToSiteMap = 0;
            if (addToSiteMap) {
                for (HttpRequestResponse resp : responses) {
                    if (resp != null && resp.response() != null) {
                        try {
                            // Add annotation to identify this as an MCP request
                            HttpRequestResponse annotatedResponse = resp.withAnnotations(
                                Annotations.annotations("MCP: burp_custom_http parallel request"));
                            api.siteMap().add(annotatedResponse);
                            addedToSiteMap++;
                        } catch (Exception e) {
                            api.logging().logToError("CustomHttpTool: Failed to add to site map: " + e.getMessage());
                        }
                    }
                }
                if (addedToSiteMap > 0) {
                    api.logging().logToOutput("CustomHttpTool: Added " + addedToSiteMap + " requests to site map");
                }
            }

            ObjectNode result = mapper.createObjectNode();
            result.put("success", true);
            result.put("total_requests", requests.size());
            result.put("total_responses", responses.size());
            result.put("added_to_sitemap", addedToSiteMap);
            
            ArrayNode respArray = mapper.createArrayNode();
            for (int i = 0; i < responses.size(); i++) {
                HttpRequestResponse resp = responses.get(i);
                ObjectNode respObj = mapper.createObjectNode();
                respObj.put("index", i);

                if (resp == null) {
                    // Dispatch threw before we got an HttpRequestResponse back. Still
                    // report something useful — input URL from the original request list.
                    respObj.put("url", requests.get(i).url());
                    respObj.put("error", "Dispatch failed");
                    respObj.put("error_type", "dispatch_failed");
                } else {
                    respObj.put("url", resp.request().url());
                    if (resp.response() != null) {
                        respObj.put("status_code", resp.response().statusCode());
                        respObj.put("body_length", resp.response().body().length());

                        if (resp.timingData().isPresent()) {
                            Duration responseTime = resp.timingData().get().timeBetweenRequestSentAndEndOfResponse();
                            respObj.put("response_time_ms", responseTime.toMillis());
                        }
                    } else {
                        respObj.put("error", "No response");
                        respObj.put("error_type", "no_response");
                    }
                }
                respArray.add(respObj);
            }
            result.set("responses", respArray);
            
            // Calculate statistics
            ObjectNode stats = mapper.createObjectNode();
            long totalTime = responses.stream()
                .filter(r -> r != null && r.response() != null && r.timingData().isPresent())
                .mapToLong(r -> r.timingData().get().timeBetweenRequestSentAndEndOfResponse().toMillis())
                .sum();
            long responseCount = responses.stream()
                .filter(r -> r != null && r.response() != null && r.timingData().isPresent())
                .count();
            stats.put("total_time_ms", totalTime);
            stats.put("average_time_ms", responseCount > 0 ? totalTime / responseCount : 0);
            result.set("statistics", stats);
            
            return McpUtils.createSuccessResponse(result.toString());
            
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return McpUtils.createErrorResponse("Failed to send parallel requests: " + e.getMessage());
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            String message = cause != null ? cause.getMessage() : e.getMessage();
            return McpUtils.createErrorResponse("Failed to send parallel requests: " + message);
        } catch (Exception e) {
            return McpUtils.createErrorResponse("Failed to send parallel requests: " + e.getMessage());
        }
    }

    /**
     * SEND_PIPELINED — write 2-20 raw HTTP/1.1 requests back-to-back on ONE TLS socket
     * and read the response stream. Required for request-smuggling labs (CL.0, TE.CL,
     * CL.TE, TE.0, 0.CL, connection-state attacks) where the desync depends on a
     * single TCP/TLS connection carrying multiple framed messages.
     *
     * Each request is sent verbatim. No Content-Length recomputation, no header
     * insertion, no reordering — the only normalization is LF -> CRLF.
     */
    private Object sendPipelined(JsonNode arguments) {
        if (!arguments.has("requests") || !arguments.get("requests").isArray()) {
            return McpUtils.createErrorResponse("requests array is required");
        }
        ArrayNode reqArr = (ArrayNode) arguments.get("requests");
        int n = reqArr.size();
        if (n < 2 || n > 20) {
            return McpUtils.createErrorResponse("SEND_PIPELINED requires 2-20 requests (got " + n + ")");
        }

        String overrideHost = McpUtils.getTrimmedStringParam(arguments, "target_host");
        Integer overridePortBoxed = null;
        if (arguments.has("target_port") && arguments.get("target_port").canConvertToInt()) {
            int p = arguments.get("target_port").asInt(0);
            if (p > 0 && p <= 65535) overridePortBoxed = p;
        }

        // Destination resolution: prefer target_host; otherwise pull the Host header
        // from requests[0]. Pipelined sends always run against the SAME destination
        // (one socket — the whole point) so we only inspect the first request.
        String host = overrideHost;
        Integer port = overridePortBoxed;
        if (host == null || host.isEmpty()) {
            String firstReq = reqArr.get(0).asText();
            for (String line : firstReq.split("\r?\n")) {
                if (line.toLowerCase().startsWith("host:")) {
                    String[] hp = parseHostPort(line.substring(5).trim());
                    host = hp[0];
                    if (hp[1] != null) {
                        try { port = Integer.parseInt(hp[1]); } catch (NumberFormatException ignored) {}
                    }
                    break;
                }
            }
        }
        if (host == null || host.isEmpty()) {
            return McpUtils.createErrorResponse("Cannot resolve destination: no target_host and no Host header in requests[0]");
        }
        int finalPort = port != null ? port : 443;

        String sni = McpUtils.getTrimmedStringParam(arguments, "server_name_indicator");
        if (sni == null || sni.isEmpty()) sni = host;

        int interDelay = 0;
        if (arguments.has("inter_request_delay_ms") && arguments.get("inter_request_delay_ms").canConvertToInt()) {
            interDelay = Math.min(10000, Math.max(0, arguments.get("inter_request_delay_ms").asInt(0)));
        }
        int expectResponses = n;
        if (arguments.has("expect_responses") && arguments.get("expect_responses").canConvertToInt()) {
            expectResponses = Math.min(50, Math.max(0, arguments.get("expect_responses").asInt(n)));
        }
        int readTimeoutMs = 5000;
        if (arguments.has("read_timeout_ms") && arguments.get("read_timeout_ms").canConvertToInt()) {
            readTimeoutMs = Math.min(60000, Math.max(100, arguments.get("read_timeout_ms").asInt(5000)));
        }
        boolean tlsVerify = arguments.has("upstream_tls_verification") && arguments.get("upstream_tls_verification").asBoolean(false);
        boolean addToSiteMap = McpUtils.getBooleanParam(arguments, "add_to_sitemap", true);

        // SEND_PIPELINED defaults to direct (no proxy) — Burp's proxy almost certainly
        // re-frames pipelined messages on its own upstream connections, breaking the
        // single-socket semantics that smuggling labs require. Caller can opt in if
        // they want history visibility and accept the risk.
        boolean routeViaProxy = resolveRouteViaProxy(arguments, false);
        if (routeViaProxy) {
            warnIgnoredOptionsOnProxyPath(arguments, "SEND_PIPELINED");
            api.logging().logToOutput("CustomHttpTool: SEND_PIPELINED route_via_proxy=true — " +
                "Burp's proxy may re-frame these requests on separate upstream connections, breaking smuggling semantics.");
        }

        // Build the concatenated byte stream (CRLF normalized).
        List<byte[]> reqBytes = new ArrayList<>(n);
        for (int i = 0; i < n; i++) {
            String raw = normalizeRequestLineEndings(reqArr.get(i).asText());
            reqBytes.add(raw.getBytes(StandardCharsets.ISO_8859_1));
        }

        String groupId = UUID.randomUUID().toString().substring(0, 8);
        api.logging().logToOutput("CustomHttpTool: SEND_PIPELINED group=" + groupId +
            " host=" + host + ":" + finalPort + " sni=" + sni +
            " requests=" + n + " expect=" + expectResponses +
            " inter_delay=" + interDelay + "ms tls_verify=" + tlsVerify);

        long startMs = System.currentTimeMillis();
        SSLSocket sock = null;
        try {
            if (routeViaProxy) {
                // Tunnel through Burp's proxy: CONNECT host:port, then TLS inside the tunnel.
                ProxyTunnelConfig cfg = new ProxyTunnelConfig(
                    proxyHostOf(arguments), proxyPortOf(arguments),
                    host, finalPort, true, sni, tlsVerify, readTimeoutMs);
                sock = (SSLSocket) openTunneledSocket(cfg);
            } else {
                SSLSocketFactory factory;
                if (tlsVerify) {
                    factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
                } else {
                    SSLContext ctx = SSLContext.getInstance("TLS");
                    ctx.init(null, new TrustManager[]{TRUST_ALL}, new java.security.SecureRandom());
                    factory = ctx.getSocketFactory();
                }
                sock = (SSLSocket) factory.createSocket();
                sock.connect(new InetSocketAddress(host, finalPort), readTimeoutMs);
                sock.setSoTimeout(readTimeoutMs);

                // SNI + ALPN: force HTTP/1.1 (v1 scope; H2 pipelining is a follow-up).
                // TODO(h2-multiplex): To support H2-track smuggling labs (H2.CL, H2.TE,
                // H2 response-queue poisoning, H2 request tunnelling) we need ONE persistent
                // H2 connection with multiple streams dispatched at different wall-clock
                // times. Recommended path: persistent worker thread keyed by connection_id
                // that holds the H2 socket open and dispatches per-stream sends. Out of
                // scope for v1 — raw Python with the h2 library is the current fallback.
                SSLParameters params = sock.getSSLParameters();
                params.setServerNames(java.util.Collections.singletonList(new javax.net.ssl.SNIHostName(sni)));
                params.setApplicationProtocols(new String[]{"http/1.1"});
                sock.setSSLParameters(params);
                sock.startHandshake();
            }

            String tlsVersion = sock.getSession().getProtocol();
            String negotiatedProto = sock.getApplicationProtocol();
            if (negotiatedProto != null && !negotiatedProto.isEmpty() && !"http/1.1".equalsIgnoreCase(negotiatedProto)) {
                return McpUtils.createErrorResponse("Server negotiated " + negotiatedProto +
                    " via ALPN; SEND_PIPELINED v1 only supports HTTP/1.1 (H2 pipelining is a follow-up).");
            }

            // Per-request write tracking. bytesWritten[i] is "0 until proven written",
            // and gets set to reqBytes[i].length once that request's full slice has
            // been handed to the OutputStream. Lets callers distinguish
            //   responses_received < expect_responses because the bytes never went out
            // from
            //   responses_received < expect_responses because the server closed after responding to N.
            int[] bytesWritten = new int[n];
            String writeError = null;
            OutputStream out = sock.getOutputStream();
            try {
                if (interDelay == 0) {
                    // Concatenated single write (the spec's preferred behavior). Either
                    // the bulk write returns and all requests are on the wire, or it
                    // throws — in which case we conservatively report 0 for everything,
                    // since the kernel may have partially flushed but we can't observe
                    // the split point.
                    ByteArrayOutputStream all = new ByteArrayOutputStream();
                    for (byte[] b : reqBytes) all.write(b);
                    out.write(all.toByteArray());
                    out.flush();
                    for (int i = 0; i < n; i++) bytesWritten[i] = reqBytes.get(i).length;
                } else {
                    for (int i = 0; i < n; i++) {
                        out.write(reqBytes.get(i));
                        out.flush();
                        bytesWritten[i] = reqBytes.get(i).length;
                        if (i < n - 1) Thread.sleep(interDelay);
                    }
                }
            } catch (Exception we) {
                writeError = we.getClass().getSimpleName() + ": " + we.getMessage();
                api.logging().logToError("SEND_PIPELINED group=" + groupId + " write failed: " + writeError);
            }

            InputStream in = sock.getInputStream();
            List<ParsedResponse> parsed = parseResponseStream(in, expectResponses, readTimeoutMs);

            // Drain any trailing bytes after expected responses (response queue poisoning).
            byte[] trailing = drainTrailing(in, readTimeoutMs);

            long totalMs = System.currentTimeMillis() - startMs;

            // Optional sitemap publish — synthesize HttpRequestResponse per pair.
            // Skip when routed through proxy (Burp's proxy already logs to HTTP history).
            int addedToMap = 0;
            if (addToSiteMap && !routeViaProxy) {
                HttpService svc = HttpService.httpService(host, finalPort, true);
                for (int i = 0; i < parsed.size() && i < n; i++) {
                    try {
                        HttpRequest req = HttpRequest.httpRequest(svc, ByteArray.byteArray(reqBytes.get(i)));
                        ParsedResponse pr = parsed.get(i);
                        burp.api.montoya.http.message.responses.HttpResponse resp =
                            burp.api.montoya.http.message.responses.HttpResponse.httpResponse(
                                ByteArray.byteArray(pr.rawBytes));
                        HttpRequestResponse hrr = HttpRequestResponse.httpRequestResponse(req, resp)
                            .withAnnotations(Annotations.annotations(
                                "MCP: pipelined group=" + groupId + " idx=" + i));
                        api.siteMap().add(hrr);
                        addedToMap++;
                    } catch (Exception e) {
                        api.logging().logToError("SEND_PIPELINED: failed to add idx=" + i + " to site map: " + e.getMessage());
                    }
                }
            }

            ObjectNode result = mapper.createObjectNode();
            result.put("success", true);
            result.put("group_id", groupId);
            result.put("routed_via_proxy", routeViaProxy);
            if (routeViaProxy) {
                result.put("proxy", proxyHostOf(arguments) + ":" + proxyPortOf(arguments));
            }
            ObjectNode conn = mapper.createObjectNode();
            conn.put("host", host);
            conn.put("port", finalPort);
            conn.put("sni", sni);
            conn.put("http_version", "HTTP/1.1");
            conn.put("tls_version", tlsVersion);
            conn.put("alpn", negotiatedProto != null ? negotiatedProto : "");
            result.set("connection", conn);
            result.put("requests_sent", n);
            result.put("responses_received", parsed.size());
            result.put("added_to_sitemap", addedToMap);
            result.put("total_time_ms", totalMs);
            if (writeError != null) {
                result.put("write_error", writeError);
            }
            // Hint: if fewer responses came back than expected AND all bytes left the
            // socket, the server likely closed the connection after responding to N
            // (e.g. Connection: close on response 1). Common in smuggling labs.
            boolean allBytesWritten = writeError == null;
            if (allBytesWritten && parsed.size() < expectResponses && parsed.size() > 0) {
                result.put("connection_closed_early", true);
                result.put("closed_after_response", parsed.size() - 1);
            }

            // Per-request dispatch view — present for all N inputs regardless of how
            // many responses came back. Lets callers tell "never sent" from
            // "sent but no response".
            ArrayNode reqStats = mapper.createArrayNode();
            for (int i = 0; i < n; i++) {
                ObjectNode r = mapper.createObjectNode();
                r.put("index", i);
                r.put("bytes_total", reqBytes.get(i).length);
                r.put("bytes_written", bytesWritten[i]);
                r.put("dispatched", bytesWritten[i] == reqBytes.get(i).length);
                reqStats.add(r);
            }
            result.set("requests", reqStats);

            ArrayNode respArr = mapper.createArrayNode();
            for (int i = 0; i < parsed.size(); i++) {
                ParsedResponse pr = parsed.get(i);
                ObjectNode r = mapper.createObjectNode();
                r.put("index", i);
                if (pr.parseError != null) {
                    r.put("parse_error", pr.parseError);
                } else {
                    r.put("status_code", pr.statusCode);
                    r.put("reason_phrase", pr.reasonPhrase);
                    r.put("http_version", pr.httpVersion);
                    ArrayNode hdrs = mapper.createArrayNode();
                    for (Map.Entry<String, String> e : pr.headers.entrySet()) {
                        ObjectNode h = mapper.createObjectNode();
                        h.put("name", e.getKey());
                        h.put("value", e.getValue());
                        hdrs.add(h);
                    }
                    r.set("headers", hdrs);
                    r.put("body_length", pr.body.length);
                    // Keep body as best-effort text for readability; raw_bytes has the truth.
                    r.put("body", new String(pr.body, StandardCharsets.ISO_8859_1));
                }
                r.put("raw_bytes", Base64.getEncoder().encodeToString(pr.rawBytes));
                respArr.add(r);
            }
            result.set("responses", respArr);
            result.put("trailing_bytes",
                trailing.length == 0 ? "" : Base64.getEncoder().encodeToString(trailing));
            result.put("trailing_bytes_length", trailing.length);

            return McpUtils.createSuccessResponse(result.toString());
        } catch (Exception e) {
            api.logging().logToError("SEND_PIPELINED group=" + groupId + " failed: " + e.getMessage());
            return McpUtils.createErrorResponse("SEND_PIPELINED failed: " + e.getMessage());
        } finally {
            if (sock != null) {
                try { sock.close(); } catch (Exception ignored) {}
            }
        }
    }

    /**
     * Resolved proxy-tunnel configuration: where to CONNECT to, where the real target is,
     * whether to wrap the tunnel in TLS, and an SNI override (used when target_host is an
     * IP but we still want a particular SNI inside the tunnel).
     */
    private static final class ProxyTunnelConfig {
        final String proxyHost;
        final int proxyPort;
        final String targetHost;
        final int targetPort;
        final boolean secure;       // wrap tunnel in TLS?
        final String sni;            // null = use targetHost
        final boolean tlsVerify;
        final int readTimeoutMs;
        ProxyTunnelConfig(String proxyHost, int proxyPort, String targetHost, int targetPort,
                          boolean secure, String sni, boolean tlsVerify, int readTimeoutMs) {
            this.proxyHost = proxyHost;
            this.proxyPort = proxyPort;
            this.targetHost = targetHost;
            this.targetPort = targetPort;
            this.secure = secure;
            this.sni = sni;
            this.tlsVerify = tlsVerify;
            this.readTimeoutMs = readTimeoutMs;
        }
    }

    /**
     * Resolve route_via_proxy + proxy_host + proxy_port from arguments, with action-aware
     * defaults: SEND_REQUEST defaults TRUE; SEND_PARALLEL / SEND_PIPELINED default FALSE.
     */
    private boolean resolveRouteViaProxy(JsonNode arguments, boolean defaultValue) {
        if (arguments != null && arguments.has("route_via_proxy") && !arguments.get("route_via_proxy").isNull()) {
            return arguments.get("route_via_proxy").asBoolean(defaultValue);
        }
        return defaultValue;
    }

    private String proxyHostOf(JsonNode arguments) {
        String h = McpUtils.getTrimmedStringParam(arguments, "proxy_host");
        return (h == null || h.isEmpty()) ? "127.0.0.1" : h;
    }

    private int proxyPortOf(JsonNode arguments) {
        if (arguments != null && arguments.has("proxy_port") && arguments.get("proxy_port").canConvertToInt()) {
            int p = arguments.get("proxy_port").asInt(8080);
            if (p > 0 && p <= 65535) return p;
        }
        return 8080;
    }

    /**
     * Open a connection to the real target via Burp's proxy listener.
     *
     * For HTTPS targets: CONNECT host:port → 200 → TLS handshake inside the tunnel
     * (SNI + ALPN forced to http/1.1, server cert trusted-all unless tlsVerify=true).
     *
     * For HTTP cleartext targets: just open TCP to the proxy. The CALLER is responsible
     * for rewriting the request line to absolute-form (`GET http://host:port/path …`) —
     * that's the standard HTTP-proxy wire format that lets Burp parse, log, and forward
     * the inner request. We deliberately do NOT use CONNECT for cleartext targets,
     * because the inner plain HTTP traffic inside a CONNECT tunnel is opaque to Burp
     * (it just blind-forwards bytes) and would skip Proxy → HTTP history.
     */
    private java.net.Socket openTunneledSocket(ProxyTunnelConfig cfg) throws Exception {
        java.net.Socket raw = new java.net.Socket();
        raw.connect(new InetSocketAddress(cfg.proxyHost, cfg.proxyPort), cfg.readTimeoutMs);
        raw.setSoTimeout(cfg.readTimeoutMs);

        if (!cfg.secure) {
            // HTTP cleartext: no CONNECT. Caller writes absolute-form request directly.
            return raw;
        }

        // HTTPS path — send CONNECT and verify 200. The Host header should mirror the
        // request-line authority — some proxies are picky.
        String authority = cfg.targetHost + ":" + cfg.targetPort;
        String connect = "CONNECT " + authority + " HTTP/1.1\r\n"
            + "Host: " + authority + "\r\n"
            + "Proxy-Connection: keep-alive\r\n"
            + "\r\n";
        OutputStream pout = raw.getOutputStream();
        pout.write(connect.getBytes(StandardCharsets.ISO_8859_1));
        pout.flush();

        // Read CONNECT response status line + headers until blank line.
        InputStream pin = raw.getInputStream();
        ByteArrayOutputStream hdr = new ByteArrayOutputStream();
        int prev1 = -1, prev2 = -1, prev3 = -1;
        while (true) {
            int b = pin.read();
            if (b == -1) {
                raw.close();
                throw new java.io.IOException("Proxy closed connection during CONNECT (proxy=" + cfg.proxyHost + ":" + cfg.proxyPort + ")");
            }
            hdr.write(b);
            if (prev3 == '\r' && prev2 == '\n' && prev1 == '\r' && b == '\n') break;
            prev3 = prev2; prev2 = prev1; prev1 = b;
            if (hdr.size() > 16384) {
                raw.close();
                throw new java.io.IOException("CONNECT response exceeded 16KB without terminator");
            }
        }
        String connectResp = hdr.toString(StandardCharsets.ISO_8859_1);
        String firstLine = connectResp.split("\r?\n", 2)[0];
        if (!firstLine.matches("HTTP/1\\.[01] 200 .*") && !firstLine.matches("HTTP/1\\.[01] 200")) {
            raw.close();
            throw new java.io.IOException("Proxy CONNECT failed: " + firstLine + " (proxy=" + cfg.proxyHost + ":" + cfg.proxyPort + ")");
        }

        // Wrap in TLS.
        SSLSocketFactory factory;
        if (cfg.tlsVerify) {
            factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        } else {
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, new TrustManager[]{TRUST_ALL}, new java.security.SecureRandom());
            factory = ctx.getSocketFactory();
        }
        String sni = (cfg.sni == null || cfg.sni.isEmpty()) ? cfg.targetHost : cfg.sni;
        SSLSocket ssl = (SSLSocket) factory.createSocket(raw, sni, cfg.targetPort, true);
        SSLParameters params = ssl.getSSLParameters();
        params.setServerNames(java.util.Collections.singletonList(new javax.net.ssl.SNIHostName(sni)));
        params.setApplicationProtocols(new String[]{"http/1.1"});
        ssl.setSSLParameters(params);
        ssl.setSoTimeout(cfg.readTimeoutMs);
        ssl.startHandshake();
        return ssl;
    }

    /**
     * Send a single request through Burp's proxy (CONNECT+TLS for HTTPS, absolute-form
     * for cleartext) and parse one response. Used by SEND_REQUEST and SEND_PARALLEL when
     * route_via_proxy=true.
     */
    private ParsedResponse sendOneViaTunnel(byte[] requestBytes, ProxyTunnelConfig cfg) throws Exception {
        java.net.Socket sock = openTunneledSocket(cfg);
        try {
            // For cleartext targets we did NOT CONNECT — the proxy needs an absolute-URI
            // request line (`GET http://host:port/path HTTP/1.1`) to know where to forward.
            byte[] toSend = cfg.secure
                ? requestBytes
                : rewriteRequestLineToAbsoluteForm(requestBytes, cfg.targetHost, cfg.targetPort);
            OutputStream out = sock.getOutputStream();
            out.write(toSend);
            out.flush();
            InputStream in = sock.getInputStream();
            // Single-shot socket — we close right after this response, so EOF framing is
            // safe for unframed responses (Burp/CF sometimes serve without Content-Length).
            List<ParsedResponse> parsed = parseResponseStream(in, 1, cfg.readTimeoutMs, true);
            if (parsed.isEmpty()) {
                ParsedResponse pr = new ParsedResponse();
                pr.parseError = "no response from proxy tunnel";
                return pr;
            }
            return parsed.get(0);
        } finally {
            try { sock.close(); } catch (Exception ignored) {}
        }
    }

    /**
     * Rewrite the request line from origin-form (`GET /path HTTP/1.1`) to absolute-form
     * (`GET http://host:port/path HTTP/1.1`) so HTTP proxies can route it without CONNECT.
     * Leaves the bytes alone if the request line is already absolute-form (raw_request).
     */
    private byte[] rewriteRequestLineToAbsoluteForm(byte[] bytes, String host, int port) {
        // Find end of first line.
        int eol = -1;
        for (int i = 0; i < bytes.length - 1; i++) {
            if (bytes[i] == '\r' && bytes[i + 1] == '\n') { eol = i; break; }
        }
        if (eol < 0) return bytes;
        String reqLine = new String(bytes, 0, eol, StandardCharsets.ISO_8859_1);
        String[] parts = reqLine.split(" ", 3);
        if (parts.length < 2 || parts[1].isEmpty()) return bytes;
        String path = parts[1];
        if (path.startsWith("http://") || path.startsWith("https://")) {
            // Already absolute-form (raw_request mode or similar) — leave it.
            return bytes;
        }
        if (!path.startsWith("/")) path = "/" + path;
        String newPath = "http://" + host + ":" + port + path;
        String newLine = parts[0] + " " + newPath + (parts.length == 3 ? " " + parts[2] : "");
        byte[] newHead = newLine.getBytes(StandardCharsets.ISO_8859_1);
        byte[] out = new byte[newHead.length + (bytes.length - eol)];
        System.arraycopy(newHead, 0, out, 0, newHead.length);
        System.arraycopy(bytes, eol, out, newHead.length, bytes.length - eol);
        return out;
    }

    /**
     * Permissive trust manager — used when upstream_tls_verification=false (the default,
     * matching the rest of burp_custom_http). Smuggling labs typically use real certs
     * so this rarely matters, but Burp's own MITM cert / self-signed targets need it.
     */
    private static final X509TrustManager TRUST_ALL = new X509TrustManager() {
        public void checkClientTrusted(X509Certificate[] xcs, String s) {}
        public void checkServerTrusted(X509Certificate[] xcs, String s) {}
        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    };

    /**
     * Parsed HTTP/1.1 response — minimal representation we hand back to the caller.
     */
    private static final class ParsedResponse {
        String httpVersion;
        int statusCode;
        String reasonPhrase;
        Map<String, String> headers = new LinkedHashMap<>();
        byte[] body = new byte[0];
        byte[] rawBytes = new byte[0];
        String parseError;
    }

    /**
     * Read up to {@code expected} HTTP/1.1 responses from the stream, framing each by
     * Content-Length / Transfer-Encoding: chunked / connection-close. Stops early if
     * the socket closes. Returns whatever it parsed.
     */
    private List<ParsedResponse> parseResponseStream(InputStream in, int expected, int readTimeoutMs) {
        return parseResponseStream(in, expected, readTimeoutMs, false);
    }

    /**
     * @param assumeCloseFraming pass true when the socket is single-shot (will be closed
     *     after this response) — lets the parser handle responses that omit Content-Length
     *     and Transfer-Encoding by reading to EOF. Set false on persistent / pipelined
     *     sockets so the parser strictly respects framing headers.
     */
    private List<ParsedResponse> parseResponseStream(InputStream in, int expected, int readTimeoutMs, boolean assumeCloseFraming) {
        List<ParsedResponse> out = new ArrayList<>();
        PushbackByteStream stream = new PushbackByteStream(in);
        for (int i = 0; i < expected; i++) {
            try {
                ParsedResponse pr = parseSingleResponse(stream, assumeCloseFraming);
                if (pr == null) break;
                out.add(pr);
                if (pr.parseError != null) break;
            } catch (java.net.SocketTimeoutException ste) {
                break;
            } catch (Exception e) {
                ParsedResponse err = new ParsedResponse();
                err.parseError = "parse error: " + e.getMessage();
                out.add(err);
                break;
            }
        }
        return out;
    }

    private ParsedResponse parseSingleResponse(PushbackByteStream in, boolean assumeCloseFraming) throws Exception {
        ByteArrayOutputStream raw = new ByteArrayOutputStream();

        // Status line.
        String statusLine = readLine(in, raw);
        if (statusLine == null) return null;
        // Skip leading blank lines (some servers send keep-alive whitespace).
        while (statusLine.isEmpty()) {
            statusLine = readLine(in, raw);
            if (statusLine == null) return null;
        }

        ParsedResponse pr = new ParsedResponse();
        String[] sp = statusLine.split(" ", 3);
        if (sp.length < 2 || !sp[0].startsWith("HTTP/")) {
            pr.parseError = "malformed status line: " + statusLine;
            pr.rawBytes = raw.toByteArray();
            return pr;
        }
        pr.httpVersion = sp[0];
        try {
            pr.statusCode = Integer.parseInt(sp[1]);
        } catch (NumberFormatException e) {
            pr.parseError = "non-numeric status code: " + sp[1];
            pr.rawBytes = raw.toByteArray();
            return pr;
        }
        pr.reasonPhrase = sp.length >= 3 ? sp[2] : "";

        // Headers.
        long contentLength = -1;
        boolean chunked = false;
        boolean connectionClose = false;
        while (true) {
            String line = readLine(in, raw);
            if (line == null || line.isEmpty()) break;
            int colon = line.indexOf(':');
            if (colon <= 0) continue;
            String name = line.substring(0, colon).trim();
            String value = line.substring(colon + 1).trim();
            pr.headers.put(name, value);
            String lower = name.toLowerCase();
            if (lower.equals("content-length")) {
                try { contentLength = Long.parseLong(value); } catch (NumberFormatException ignored) {}
            } else if (lower.equals("transfer-encoding") && value.toLowerCase().contains("chunked")) {
                chunked = true;
            } else if (lower.equals("connection") && value.toLowerCase().contains("close")) {
                connectionClose = true;
            }
        }

        // Body framing.
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        if (chunked) {
            while (true) {
                String sizeLine = readLine(in, raw);
                if (sizeLine == null) break;
                int semi = sizeLine.indexOf(';');
                String sizeStr = (semi >= 0 ? sizeLine.substring(0, semi) : sizeLine).trim();
                int size;
                try { size = Integer.parseInt(sizeStr, 16); }
                catch (NumberFormatException nfe) { pr.parseError = "bad chunk size: " + sizeStr; break; }
                if (size == 0) {
                    // trailers
                    while (true) {
                        String t = readLine(in, raw);
                        if (t == null || t.isEmpty()) break;
                    }
                    break;
                }
                byte[] chunk = readN(in, size, raw);
                if (chunk == null) break;
                body.write(chunk);
                readLine(in, raw); // trailing CRLF after chunk
            }
        } else if (contentLength >= 0) {
            if (contentLength > 0) {
                byte[] b = readN(in, (int) Math.min(contentLength, Integer.MAX_VALUE), raw);
                if (b != null) body.write(b);
            }
        } else if (pr.statusCode == 204 || pr.statusCode == 304 || (pr.statusCode >= 100 && pr.statusCode < 200)) {
            // No body for these statuses by spec.
        } else if (connectionClose
                || "HTTP/1.0".equalsIgnoreCase(pr.httpVersion)
                || assumeCloseFraming) {
            // EOF-framed body — read to socket close. Only safe when the server has
            // signalled close (Connection: close, HTTP/1.0 default) OR the caller has
            // told us this is a single-shot socket that will be closed after this
            // response (assumeCloseFraming, set by the SEND_REQUEST proxy path).
            // For keep-alive sockets (SEND_PIPELINED) we deliberately do NOT do this —
            // it would block until timeout and silently consume the next response's bytes.
            //
            // Read byte-by-byte into BOTH body and raw so a SocketTimeoutException
            // partway through still keeps everything we already received. (readAll()
            // only returns on EOF, so on timeout the partial bytes would be lost.)
            try {
                while (true) {
                    int b = in.read();
                    if (b == -1) break;
                    raw.write(b);
                    body.write(b);
                    if (body.size() > 50_000_000) break; // safety cap
                }
            } catch (java.net.SocketTimeoutException ste) {
                // Soft EOF — server held the connection open with no further framing.
                // Status + headers + partial body are still valid; bubbling would drop
                // everything parseSingleResponse just parsed.
            }
        }
        // Otherwise: no length, no chunked, persistent socket — return what we have
        // (status + headers); caller can inspect raw_bytes if they need more.

        pr.body = body.toByteArray();
        pr.rawBytes = raw.toByteArray();
        return pr;
    }

    private byte[] drainTrailing(InputStream in, int timeoutMs) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            byte[] buf = new byte[4096];
            long deadline = System.currentTimeMillis() + Math.min(timeoutMs, 2000);
            while (System.currentTimeMillis() < deadline) {
                if (in.available() <= 0) {
                    try { Thread.sleep(50); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); break; }
                    continue;
                }
                int n = in.read(buf);
                if (n <= 0) break;
                out.write(buf, 0, n);
                if (out.size() > 65536) break;
            }
        } catch (Exception ignored) {}
        return out.toByteArray();
    }

    // ─── Stream helpers (kept inline; only used by SEND_PIPELINED) ─────────────────

    private static final class PushbackByteStream {
        final InputStream in;
        PushbackByteStream(InputStream in) { this.in = in; }
        int read() throws Exception { return in.read(); }
    }

    private String readLine(PushbackByteStream s, ByteArrayOutputStream raw) throws Exception {
        ByteArrayOutputStream line = new ByteArrayOutputStream();
        int prev = -1;
        while (true) {
            int b = s.read();
            if (b == -1) {
                if (line.size() == 0) return null;
                return new String(line.toByteArray(), StandardCharsets.ISO_8859_1);
            }
            raw.write(b);
            if (prev == '\r' && b == '\n') {
                byte[] arr = line.toByteArray();
                // Strip the trailing \r we already accumulated.
                int len = arr.length > 0 && arr[arr.length - 1] == '\r' ? arr.length - 1 : arr.length;
                return new String(arr, 0, len, StandardCharsets.ISO_8859_1);
            }
            line.write(b);
            prev = b;
        }
    }

    private byte[] readN(PushbackByteStream s, int n, ByteArrayOutputStream raw) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream(n);
        for (int i = 0; i < n; i++) {
            int b = s.read();
            if (b == -1) return out.size() == 0 ? null : out.toByteArray();
            raw.write(b);
            out.write(b);
        }
        return out.toByteArray();
    }

    private HttpMode parseHttpMode(String mode) {
        if (mode == null) return HttpMode.AUTO;
        switch (mode.toUpperCase()) {
            case "HTTP_1":
                return HttpMode.HTTP_1;
            case "HTTP_2":
                return HttpMode.HTTP_2;
            case "HTTP_2_IGNORE_ALPN":
                return HttpMode.HTTP_2_IGNORE_ALPN;
            default:
                return HttpMode.AUTO;
        }
    }

    private RedirectionMode parseRedirectionMode(String mode) {
        if (mode == null) return RedirectionMode.NEVER;
        switch (mode.toUpperCase()) {
            case "ALWAYS":
                return RedirectionMode.ALWAYS;
            case "SAME_HOST":
                return RedirectionMode.SAME_HOST;
            case "IN_SCOPE":
                return RedirectionMode.IN_SCOPE;
            case "NEVER":
            default:
                return RedirectionMode.NEVER;
        }
    }
    
    private String getStackTraceString(Exception e) {
        java.io.StringWriter sw = new java.io.StringWriter();
        java.io.PrintWriter pw = new java.io.PrintWriter(sw);
        e.printStackTrace(pw);
        return sw.toString();
    }
    
    /**
     * Normalize HTTP request line endings to CRLF.
     * Handles requests that incorrectly use LF-only line endings.
     */
    private String normalizeRequestLineEndings(String requestStr) {
        if (requestStr == null || requestStr.isEmpty()) {
            return requestStr;
        }

        // Check if already properly formatted (contains CRLF)
        if (requestStr.contains("\r\n")) {
            // Already has CRLF, but might have mixed endings - normalize all
            // First, normalize any standalone \r to \r\n, then normalize \n to \r\n
            // But avoid creating \r\n\r\n from \r\n
            return requestStr
                .replace("\r\n", "\n")      // Temporarily convert CRLF to LF
                .replace("\r", "\n")         // Convert any standalone CR to LF
                .replace("\n", "\r\n");      // Convert all LF to CRLF
        }

        // Only has LF - convert to CRLF
        if (requestStr.contains("\n")) {
            String normalized = requestStr.replace("\n", "\r\n");
            api.logging().logToOutput("CustomHttpTool: Normalized request line endings (LF -> CRLF)");
            return normalized;
        }

        // No line endings found - return as is (single line)
        return requestStr;
    }

    private HttpRequest createHttpRequest(String requestStr, JsonNode arguments) throws Exception {
        // Normalize line endings to CRLF (handles agents that incorrectly use LF-only).
        // Always done — even in raw_request mode — per the spec.
        requestStr = normalizeRequestLineEndings(requestStr);

        boolean rawRequest = arguments != null && arguments.has("raw_request")
            && arguments.get("raw_request").asBoolean(false);
        String overrideHost = arguments != null
            ? McpUtils.getTrimmedStringParam(arguments, "target_host")
            : null;
        Integer overridePort = null;
        if (arguments != null && arguments.has("target_port") && !arguments.get("target_port").isNull()) {
            int p = arguments.get("target_port").asInt(0);
            if (p > 0 && p <= 65535) {
                overridePort = p;
            } else if (p != 0) {
                api.logging().logToError("CustomHttpTool: invalid target_port " + p + " (must be 1-65535); ignoring");
            }
        }

        String[] lines = requestStr.split("\r?\n", -1);

        // Extract Host header if present (informational; may not be used for destination)
        String hostHeader = null;
        for (String line : lines) {
            if (line.toLowerCase().startsWith("host:")) {
                hostHeader = line.substring(5).trim();
                break;
            }
        }

        // Default to HTTPS (secure=true) unless explicitly specified otherwise
        boolean secure = true;
        boolean schemeSpecified = false;
        boolean http2Requested = false;
        boolean allowH2c = arguments != null && arguments.has("allow_h2c") && arguments.get("allow_h2c").asBoolean(false);

        if (arguments != null && arguments.has("http_mode")) {
            String httpMode = McpUtils.getStringParam(arguments, "http_mode", "AUTO");
            http2Requested = httpMode != null && httpMode.contains("HTTP_2");
            if (http2Requested && allowH2c) {
                api.logging().logToOutput("CustomHttpTool: HTTP/2 cleartext (h2c) mode enabled");
            }
        }

        // Variables to potentially extract from absolute-form URL
        String urlHost = null;
        Integer urlPort = null;

        // Detect absolute-form URL in the request line. In raw_request mode we ONLY read
        // it (to learn scheme) — we do not rewrite the request line. In normal mode we
        // also rewrite to origin-form, matching legacy behavior.
        if (lines.length > 0) {
            String requestLine = lines[0];
            String[] parts = requestLine.split(" ", 3);
            if (parts.length >= 2) {
                String url = parts[1];
                String lowerUrl = url.toLowerCase();
                if (lowerUrl.startsWith("https://") || lowerUrl.startsWith("http://")) {
                    secure = lowerUrl.startsWith("https://");
                    schemeSpecified = true;
                    int schemeSeparator = url.indexOf("://");
                    String afterScheme = schemeSeparator >= 0 ? url.substring(schemeSeparator + 3) : url;
                    // Authority ends at the first of `/`, `?`, or `#`. The earlier
                    // version only split on `/`, which mis-parsed
                    // `http://example.com?x=1` as host="example.com?x=1" and dropped the
                    // query during the origin-form rewrite.
                    int authorityEnd = -1;
                    for (int i = 0; i < afterScheme.length(); i++) {
                        char c = afterScheme.charAt(i);
                        if (c == '/' || c == '?' || c == '#') { authorityEnd = i; break; }
                    }
                    String hostPortPart = authorityEnd >= 0 ? afterScheme.substring(0, authorityEnd) : afterScheme;
                    String pathAndAfter = authorityEnd >= 0 ? afterScheme.substring(authorityEnd) : "";

                    String[] urlHostPort = parseHostPort(hostPortPart);
                    urlHost = urlHostPort[0];
                    if (urlHostPort[1] != null) {
                        try {
                            urlPort = Integer.parseInt(urlHostPort[1]);
                        } catch (NumberFormatException e) {
                            api.logging().logToError("Invalid port in URL: " + urlHostPort[1]);
                        }
                    }

                    if (!rawRequest) {
                        // Legacy behavior: convert absolute-form to origin-form. Preserve
                        // query/fragment by prepending "/" only when the authority was
                        // followed by `?` or `#` (or by nothing at all).
                        if (pathAndAfter.isEmpty()) {
                            parts[1] = "/";
                        } else if (pathAndAfter.charAt(0) == '/') {
                            parts[1] = pathAndAfter;
                        } else {
                            parts[1] = "/" + pathAndAfter;
                        }
                        lines[0] = String.join(" ", parts);
                    }
                    // raw_request mode: leave parts[1] alone — the absolute URI travels on the wire verbatim.
                }
            }
        }

        // Determine TCP destination. Precedence:
        //   1. target_host (explicit override — decouples destination from Host header)
        //   2. Host header
        //   3. Absolute-URI authority (only when raw_request=false, since raw mode doesn't synthesize Host)
        String host;
        Integer port = null;

        if (overrideHost != null && !overrideHost.isEmpty()) {
            host = overrideHost;
            if (overridePort != null) {
                port = overridePort;
            }
        } else if (hostHeader != null) {
            String[] hostPort = parseHostPort(hostHeader);
            host = hostPort[0];
            if (hostPort[1] != null) {
                try {
                    port = Integer.parseInt(hostPort[1]);
                } catch (NumberFormatException e) {
                    api.logging().logToError("Invalid port in host header: " + hostPort[1] + ", using default port");
                }
            }
            if (port == null && urlPort != null && urlHost != null && urlHost.equalsIgnoreCase(host)) {
                port = urlPort;
            }
        } else if (urlHost != null) {
            host = urlHost;
            port = urlPort;
            if (!rawRequest) {
                // Synthesize a Host header from the absolute URI (legacy behavior).
                // In raw mode we deliberately skip this — caller controls the bytes.
                String hostHeaderValue = urlPort != null ? urlHost + ":" + urlPort : urlHost;
                if (urlHost.contains(":")) {
                    hostHeaderValue = urlPort != null ? "[" + urlHost + "]:" + urlPort : "[" + urlHost + "]";
                }
                List<String> lineList = new ArrayList<>(Arrays.asList(lines));
                lineList.add(1, "Host: " + hostHeaderValue);
                lines = lineList.toArray(new String[0]);
            }
        } else {
            throw new IllegalArgumentException(
                "Cannot determine TCP destination: no target_host, no Host header, no absolute-form URL");
        }

        // Port-based protocol detection - only if scheme was NOT explicitly specified
        if (!schemeSpecified && port != null) {
            if (port == 443) {
                secure = true;
            } else if (port == 80) {
                secure = false;
            }
        }

        if (port == null) {
            port = secure ? 443 : 80;
            if (secure && !schemeSpecified && overrideHost == null) {
                api.logging().logToOutput("CustomHttpTool: No port specified in Host header '" + hostHeader +
                    "' - defaulting to HTTPS (port 443). For HTTP, use 'Host: " + host + ":80' or 'http://' URL scheme.");
            }
        }

        if (http2Requested && !secure && !allowH2c) {
            if (!schemeSpecified && port == 443) {
                secure = true;
            } else {
                api.logging().logToOutput("CustomHttpTool: HTTP/2 requested but plaintext target detected; staying on cleartext. Set allow_h2c=true to override.");
            }
        }

        HttpService service = HttpService.httpService(host, port, secure);

        if (rawRequest) {
            // Send bytes verbatim. ISO-8859-1 is the 8-bit-clean transport encoding for
            // HTTP/1.1 framing; any body bytes survive the String round-trip.
            byte[] bytes = requestStr.getBytes(StandardCharsets.ISO_8859_1);
            return HttpRequest.httpRequest(service, ByteArray.byteArray(bytes));
        }

        requestStr = String.join("\r\n", Arrays.asList(lines));
        return HttpRequest.httpRequest(service, requestStr);
    }

    /**
     * Apply cookies from Burp's cookie jar to the request for the target domain.
     * Merges with any existing Cookie header in the request.
     */
    private HttpRequest applyCookiesFromJar(HttpRequest request, JsonNode arguments) {
        // raw_request promises byte-exact transmission. Cookie-jar merging would
        // rewrite the Cookie header and re-serialise the request, breaking that
        // contract. Default off when raw_request=true; the caller can force it back
        // on by setting use_cookie_jar=true explicitly.
        boolean rawRequest = arguments != null && arguments.has("raw_request")
            && arguments.get("raw_request").asBoolean(false);
        boolean defaultUseJar = !rawRequest;
        boolean useCookieJar = McpUtils.getBooleanParam(arguments, "use_cookie_jar", defaultUseJar);
        if (!useCookieJar) {
            return request;
        }

        try {
            String host = request.httpService().host();
            List<Cookie> cookies = api.http().cookieJar().cookies();

            // Filter cookies for this domain (including parent domains)
            List<String> matchingCookies = new ArrayList<>();
            for (Cookie cookie : cookies) {
                String cookieDomain = cookie.domain();
                // Match exact domain or parent domain (e.g., .example.com matches sub.example.com)
                if (host.equalsIgnoreCase(cookieDomain) ||
                    host.endsWith("." + cookieDomain) ||
                    (cookieDomain.startsWith(".") && host.endsWith(cookieDomain))) {
                    matchingCookies.add(cookie.name() + "=" + cookie.value());
                }
            }

            if (matchingCookies.isEmpty()) {
                api.logging().logToOutput("CustomHttpTool: No cookies in jar for domain: " + host);
                return request;
            }

            // Get existing Cookie header
            String existingCookies = request.headerValue("Cookie");
            Set<String> existingCookieNames = new HashSet<>();

            if (existingCookies != null && !existingCookies.isEmpty()) {
                // Parse existing cookie names to avoid duplicates
                for (String cookiePair : existingCookies.split(";")) {
                    String trimmed = cookiePair.trim();
                    int eqIdx = trimmed.indexOf('=');
                    if (eqIdx > 0) {
                        existingCookieNames.add(trimmed.substring(0, eqIdx).trim());
                    }
                }
            }

            // Add cookies from jar that aren't already in the request
            StringBuilder newCookieHeader = new StringBuilder();
            if (existingCookies != null && !existingCookies.isEmpty()) {
                newCookieHeader.append(existingCookies);
            }

            int addedCount = 0;
            for (String cookiePair : matchingCookies) {
                String cookieName = cookiePair.substring(0, cookiePair.indexOf('='));
                if (!existingCookieNames.contains(cookieName)) {
                    if (newCookieHeader.length() > 0) {
                        newCookieHeader.append("; ");
                    }
                    newCookieHeader.append(cookiePair);
                    addedCount++;
                }
            }

            if (addedCount > 0) {
                String finalCookieValue = newCookieHeader.toString();
                api.logging().logToOutput("CustomHttpTool: Applied " + addedCount + " cookie(s) from jar for: " + host);

                // Use withAddedHeader if no Cookie header exists, otherwise withUpdatedHeader
                if (existingCookies == null || existingCookies.isEmpty()) {
                    return request.withAddedHeader("Cookie", finalCookieValue);
                } else {
                    return request.withUpdatedHeader("Cookie", finalCookieValue);
                }
            }

            return request;
        } catch (Exception e) {
            api.logging().logToError("CustomHttpTool: Error applying cookies from jar: " + e.getMessage());
            return request;
        }
    }

    /**
     * Apply headers from the most recent proxy history entry for the same host.
     * Request headers take precedence - existing headers are not overwritten.
     */
    private HttpRequest applyHeadersFromProxyHistory(HttpRequest request, JsonNode arguments) {
        // Same logic as applyCookiesFromJar: raw_request must not be silently mutated.
        // Browser-style header injection would add Sec-*/User-Agent/etc that the
        // caller specifically didn't ask for. Default off when raw_request=true.
        boolean rawRequest = arguments != null && arguments.has("raw_request")
            && arguments.get("raw_request").asBoolean(false);
        boolean defaultUseProxyHeaders = !rawRequest;
        boolean useProxyHeaders = McpUtils.getBooleanParam(arguments, "use_proxy_headers", defaultUseProxyHeaders);
        if (!useProxyHeaders) {
            return request;
        }

        try {
            String targetHost = request.httpService().host();
            List<ProxyHttpRequestResponse> proxyHistory = api.proxy().history();

            // Find the most recent entry for the same host (iterate backwards)
            ProxyHttpRequestResponse matchingEntry = null;
            for (int i = proxyHistory.size() - 1; i >= 0; i--) {
                ProxyHttpRequestResponse entry = proxyHistory.get(i);
                HttpRequest proxyRequest = entry.request();
                if (proxyRequest != null && proxyRequest.httpService().host().equalsIgnoreCase(targetHost)) {
                    matchingEntry = entry;
                    break;
                }
            }

            if (matchingEntry == null) {
                api.logging().logToOutput("CustomHttpTool: No proxy history found for host: " + targetHost);
                return request;
            }

            HttpRequest proxyRequest = matchingEntry.request();

            // Headers to copy from proxy history (excluding Cookie which is handled separately)
            Set<String> headersToCopy = Set.of(
                "User-Agent", "Accept", "Accept-Language", "Accept-Encoding",
                "Sec-Ch-Ua", "Sec-Ch-Ua-Mobile", "Sec-Ch-Ua-Platform",
                "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-User", "Sec-Fetch-Dest",
                "Upgrade-Insecure-Requests", "Priority", "Cache-Control", "Pragma"
            );

            // Get existing header names (case-insensitive)
            Set<String> existingHeaders = new HashSet<>();
            for (HttpHeader header : request.headers()) {
                existingHeaders.add(header.name().toLowerCase());
            }

            int addedCount = 0;
            for (HttpHeader header : proxyRequest.headers()) {
                String headerName = header.name();
                String headerNameLower = headerName.toLowerCase();

                // Skip if header already exists in request, or if it's Cookie/Host/Content-Length/Content-Type
                if (existingHeaders.contains(headerNameLower) ||
                    headerNameLower.equals("cookie") ||
                    headerNameLower.equals("host") ||
                    headerNameLower.equals("content-length") ||
                    headerNameLower.equals("content-type") ||
                    headerNameLower.equals("connection")) {
                    continue;
                }

                // Only copy headers from our whitelist or Sec-* headers
                if (headersToCopy.contains(headerName) || headerNameLower.startsWith("sec-")) {
                    request = request.withAddedHeader(headerName, header.value());
                    existingHeaders.add(headerNameLower);
                    addedCount++;
                }
            }

            if (addedCount > 0) {
                api.logging().logToOutput("CustomHttpTool: Applied " + addedCount + " header(s) from proxy history for: " + targetHost);
            }

            return request;
        } catch (Exception e) {
            api.logging().logToError("CustomHttpTool: Error applying headers from proxy history: " + e.getMessage());
            return request;
        }
    }

    /**
     * Parse host and port from a host:port string, handling IPv6 literals.
     * Returns [host, port] where port may be null.
     */
    private String[] parseHostPort(String hostPort) {
        String host;
        String port = null;

        // Remove userinfo if present (user:pass@host)
        int atIndex = hostPort.lastIndexOf('@');
        if (atIndex >= 0) {
            hostPort = hostPort.substring(atIndex + 1);
        }

        if (hostPort.startsWith("[")) {
            // IPv6 literal
            int closingBracket = hostPort.indexOf(']');
            if (closingBracket < 0) {
                throw new IllegalArgumentException("Malformed IPv6 literal: missing closing bracket in '" + hostPort + "'");
            }
            host = hostPort.substring(1, closingBracket);
            if (closingBracket + 1 < hostPort.length() && hostPort.charAt(closingBracket + 1) == ':') {
                port = hostPort.substring(closingBracket + 2);
            }
        } else {
            // Regular host or IPv4
            int lastColon = hostPort.lastIndexOf(':');
            if (lastColon >= 0) {
                // Check if this looks like a port (all digits after colon)
                String potentialPort = hostPort.substring(lastColon + 1);
                if (potentialPort.matches("\\d+")) {
                    host = hostPort.substring(0, lastColon);
                    port = potentialPort;
                } else {
                    // Might be IPv6 without brackets (not standard but handle gracefully)
                    host = hostPort;
                }
            } else {
                host = hostPort;
            }
        }

        return new String[]{host, port};
    }

    private HttpRequestResponse sendSingleRequestWithOptions(HttpRequest request, JsonNode arguments) {
        try {
            // Log the HTTP mode being requested
            String httpModeParam = McpUtils.getTrimmedStringParam(arguments, "http_mode");
            String connectionId = McpUtils.getTrimmedStringParam(arguments, "connection_id");

            if (httpModeParam != null) {
                api.logging().logToOutput("CustomHttpTool: Requesting HTTP mode: " + httpModeParam);
            }
            if (connectionId != null && !connectionId.isEmpty()) {
                api.logging().logToOutput("CustomHttpTool: Using connection ID: " + connectionId);
            }

            // Try to use RequestOptions first (newer API)
            try {
                RequestOptions options = buildRequestOptions(arguments);
                if (options != null) {
                    api.logging().logToOutput("CustomHttpTool: Using RequestOptions API");
                    HttpRequestResponse response = api.http().sendRequest(request, options);

                    // Log the actual protocol used
                    if (response != null && response.response() != null) {
                        api.logging().logToOutput("CustomHttpTool: Response received with HTTP version: " + response.response().httpVersion());
                    }

                    return response;
                }
            } catch (NoSuchMethodError | NoClassDefFoundError e) {
                api.logging().logToOutput("CustomHttpTool: RequestOptions not available, falling back to legacy API");
            }

            // Fallback to legacy API
            if (arguments.has("http_mode") || arguments.has("connection_id")) {
                HttpMode mode = parseHttpMode(McpUtils.getStringParam(arguments, "http_mode", "AUTO"));
                api.logging().logToOutput("CustomHttpTool: Using legacy API with HttpMode: " + mode);

                if (connectionId != null && !connectionId.isEmpty()) {
                    // Check if connection is stale
                    Long lastUsed = connectionLastUsed.get(connectionId);
                    long currentTime = System.currentTimeMillis();

                    if (lastUsed != null && (currentTime - lastUsed) > CONNECTION_TIMEOUT_MS) {
                        api.logging().logToOutput("CustomHttpTool: Connection " + connectionId + " is stale, will create new connection");
                        connectionLastUsed.remove(connectionId);
                        // Append timestamp to create a new connection
                        connectionId = connectionId + "_" + currentTime;
                    }

                    // Connection ID requires HTTP/2
                    if (mode == HttpMode.AUTO) {
                        mode = HttpMode.HTTP_2;
                        api.logging().logToOutput("CustomHttpTool: Connection ID specified, forcing HTTP/2 mode");
                    }

                    // Use CompletableFuture with timeout to prevent hanging
                    final HttpMode finalMode = mode;
                    final String finalConnectionId = connectionId;
                    CompletableFuture<HttpRequestResponse> future = CompletableFuture.supplyAsync(() -> {
                        try {
                            api.logging().logToOutput("CustomHttpTool: Sending request with connection_id: " + finalConnectionId);
                            HttpRequestResponse resp = api.http().sendRequest(request, finalMode, finalConnectionId);
                            // Update last used time on success
                            connectionLastUsed.put(finalConnectionId, System.currentTimeMillis());
                            return resp;
                        } catch (Exception e) {
                            api.logging().logToError("CustomHttpTool: Error with connection_id: " + e.getMessage());
                            // Remove failed connection from tracking
                            connectionLastUsed.remove(finalConnectionId);
                            // If connection_id fails, try without it
                            return api.http().sendRequest(request, finalMode);
                        }
                    });

                    try {
                        // 5 second timeout for connection_id requests
                        HttpRequestResponse response = future.get(5, java.util.concurrent.TimeUnit.SECONDS);
                        if (response != null && response.response() != null) {
                            api.logging().logToOutput("CustomHttpTool: Response received with HTTP version: " + response.response().httpVersion());
                        }
                        return response;
                    } catch (java.util.concurrent.TimeoutException te) {
                        api.logging().logToError("CustomHttpTool: Timeout with connection_id, retrying without it");
                        future.cancel(true);
                        // Remove timed-out connection
                        connectionLastUsed.remove(finalConnectionId);
                        // Fallback to request without connection_id
                        return api.http().sendRequest(request, finalMode);
                    } catch (Exception e) {
                        api.logging().logToError("CustomHttpTool: Error with connection_id future: " + e.getMessage());
                        connectionLastUsed.remove(finalConnectionId);
                        return api.http().sendRequest(request, finalMode);
                    }
                }

                HttpRequestResponse response = api.http().sendRequest(request, mode);
                if (response != null && response.response() != null) {
                    api.logging().logToOutput("CustomHttpTool: Response received with HTTP version: " + response.response().httpVersion());
                }
                return response;
            }

            // Default sendRequest
            api.logging().logToOutput("CustomHttpTool: Using default sendRequest");
            return api.http().sendRequest(request);

        } catch (Exception e) {
            api.logging().logToError("CustomHttpTool: Error in sendSingleRequestWithOptions: " + e.getMessage());
            api.logging().logToError("CustomHttpTool: Stack trace: " + getStackTraceString(e));

            // Last resort fallback
            try {
                HttpMode fallbackMode = parseHttpMode(McpUtils.getStringParam(arguments, "http_mode", "AUTO"));
                api.logging().logToOutput("CustomHttpTool: Last resort fallback with mode: " + fallbackMode);
                return api.http().sendRequest(request, fallbackMode);
            } catch (Exception e2) {
                api.logging().logToError("CustomHttpTool: Even fallback failed: " + e2.getMessage());
                return null;
            }
        }
    }

    private List<HttpRequestResponse> sendBatchRequests(List<HttpRequest> requests, JsonNode arguments) throws ExecutionException, InterruptedException {
        // Bounded concurrency: prevents tail-of-batch drops caused by socket/thread-pool
        // exhaustion when too many requests are in flight simultaneously.
        int maxConcurrency = 10;
        if (arguments.has("max_concurrency") && arguments.get("max_concurrency").canConvertToInt()) {
            int v = arguments.get("max_concurrency").asInt(10);
            maxConcurrency = Math.min(50, Math.max(1, v));
        }
        int delayMs = 0;
        if (arguments.has("request_delay_ms") && arguments.get("request_delay_ms").canConvertToInt()) {
            int v = arguments.get("request_delay_ms").asInt(0);
            delayMs = Math.min(10000, Math.max(0, v));
        }

        int n = requests.size();
        int poolSize = Math.min(maxConcurrency, Math.max(1, n));
        ExecutorService exec = Executors.newFixedThreadPool(poolSize);
        Semaphore slots = new Semaphore(maxConcurrency);
        HttpRequestResponse[] results = new HttpRequestResponse[n];
        List<Future<?>> futures = new ArrayList<>(n);

        api.logging().logToOutput("CustomHttpTool: SEND_PARALLEL dispatching " + n +
            " requests with max_concurrency=" + maxConcurrency +
            (delayMs > 0 ? ", request_delay_ms=" + delayMs : ""));

        try {
            long lastDispatch = 0;
            for (int i = 0; i < n; i++) {
                final int idx = i;
                final HttpRequest req = requests.get(i);
                slots.acquire();
                if (delayMs > 0 && lastDispatch != 0) {
                    long wait = lastDispatch + delayMs - System.currentTimeMillis();
                    if (wait > 0) {
                        Thread.sleep(wait);
                    }
                }
                lastDispatch = System.currentTimeMillis();
                futures.add(exec.submit(() -> {
                    try {
                        results[idx] = sendSingleRequestWithOptions(req, arguments);
                    } catch (Exception e) {
                        api.logging().logToError("CustomHttpTool: request " + idx + " failed: " + e.getMessage());
                        results[idx] = null;
                    } finally {
                        slots.release();
                    }
                }));
            }
            for (Future<?> f : futures) {
                f.get();
            }
        } finally {
            exec.shutdown();
            try {
                if (!exec.awaitTermination(5, TimeUnit.SECONDS)) {
                    exec.shutdownNow();
                }
            } catch (InterruptedException e) {
                exec.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }

        // Preserve input order.
        return Arrays.asList(results);
    }

    private RequestOptions buildRequestOptions(JsonNode arguments) {
        RequestOptions options = RequestOptions.requestOptions();
        boolean modified = false;

        String httpModeParam = McpUtils.getTrimmedStringParam(arguments, "http_mode");
        if (httpModeParam != null) {
            options = options.withHttpMode(parseHttpMode(httpModeParam));
            modified = true;
        }

        String connectionId = McpUtils.getTrimmedStringParam(arguments, "connection_id");
        if (connectionId != null && !connectionId.isEmpty()) {
            options = options.withConnectionId(connectionId);
            modified = true;
        }

        if (arguments.has("upstream_tls_verification") && arguments.get("upstream_tls_verification").asBoolean(false)) {
            options = options.withUpstreamTLSVerification();
            modified = true;
        }

        String redirectionMode = McpUtils.getTrimmedStringParam(arguments, "redirection_mode");
        if (redirectionMode != null) {
            options = options.withRedirectionMode(parseRedirectionMode(redirectionMode));
            modified = true;
        } else if (arguments.has("follow_redirects")) {
            boolean follow = arguments.get("follow_redirects").asBoolean(false);
            options = options.withRedirectionMode(follow ? RedirectionMode.ALWAYS : RedirectionMode.NEVER);
            modified = true;
        }

        String sni = McpUtils.getTrimmedStringParam(arguments, "server_name_indicator");
        if (sni != null) {
            options = options.withServerNameIndicator(sni);
            modified = true;
        }

        if (arguments.has("response_timeout") && arguments.get("response_timeout").canConvertToLong()) {
            long timeout = arguments.get("response_timeout").asLong();
            if (timeout > 0) {
                options = options.withResponseTimeout(timeout);
                modified = true;
            }
        }

        return modified ? options : null;
    }

    /**
     * Toggle request method between GET and POST using HttpTransformation
     */
    private Object toggleRequestMethod(JsonNode arguments) {
        if (!arguments.has("request")) {
            return McpUtils.createErrorResponse("Request is required");
        }
        
        try {
            String requestStr = McpUtils.getStringParam(arguments, "request", "");
            HttpRequest request = createHttpRequest(requestStr, arguments);
            
            // Apply TOGGLE_METHOD transformation
            HttpRequest transformedRequest = request.withTransformationApplied(HttpTransformation.TOGGLE_METHOD);
            
            ObjectNode result = mapper.createObjectNode();
            result.put("success", true);
            result.put("original_method", request.method());
            result.put("transformed_method", transformedRequest.method());
            result.put("original_url", request.url());
            result.put("transformed_url", transformedRequest.url());
            
            // Include the transformed request
            result.put("transformed_request", transformedRequest.toString());
            
            // Show what changed
            ObjectNode changes = mapper.createObjectNode();
            changes.put("method_changed", !request.method().equals(transformedRequest.method()));
            changes.put("body_changed", !request.body().toString().equals(transformedRequest.body().toString()));
            changes.put("parameters_changed", request.parameters().size() != transformedRequest.parameters().size());
            result.set("changes", changes);
            
            return McpUtils.createSuccessResponse(result.toString());
            
        } catch (Exception e) {
            return McpUtils.createErrorResponse("Failed to toggle request method: " + e.getMessage());
        }
    }
    
    /**
     * Analyze protocol (HTTP vs HTTPS) from request or URL
     */
    private Object analyzeProtocol(JsonNode arguments) {
        try {
            ObjectNode result = mapper.createObjectNode();
            result.put("success", true);
            
            if (arguments.has("request")) {
                String requestStr = McpUtils.getStringParam(arguments, "request", "");
                HttpRequest request = createHttpRequest(requestStr, arguments);
                HttpService service = request.httpService();
                
                result.put("host", service.host());
                result.put("port", service.port());
                result.put("secure", service.secure());
                result.put("protocol", service.secure() ? "HTTPS" : "HTTP");
                result.put("url", request.url());
                
                // Check if IP address is available
                if (service.ipAddress() != null && !service.ipAddress().isEmpty()) {
                    result.put("ip_address", service.ipAddress());
                }
                
                // Analyze default ports
                boolean isDefaultPort = (service.secure() && service.port() == 443) || 
                                       (!service.secure() && service.port() == 80);
                result.put("uses_default_port", isDefaultPort);
                
            } else if (arguments.has("url")) {
                String url = McpUtils.getStringParam(arguments, "url", "");

                // Parse URL to determine protocol
                boolean isHttps = url.toLowerCase().startsWith("https://");
                String protocol = isHttps ? "HTTPS" : "HTTP";

                // Extract host and port from URL (handles IPv6, userinfo, etc.)
                String hostPart = url.replaceFirst("^https?://", "");
                // Remove path and query string
                int slashIdx = hostPart.indexOf('/');
                int queryIdx = hostPart.indexOf('?');
                int endIdx = hostPart.length();
                if (slashIdx >= 0 && slashIdx < endIdx) endIdx = slashIdx;
                if (queryIdx >= 0 && queryIdx < endIdx) endIdx = queryIdx;
                hostPart = hostPart.substring(0, endIdx);

                // Use shared parseHostPort method for proper IPv6 handling
                String[] hostPortParts = parseHostPort(hostPart);
                String host = hostPortParts[0];
                int port = isHttps ? 443 : 80;

                if (hostPortParts[1] != null) {
                    try {
                        port = Integer.parseInt(hostPortParts[1]);
                    } catch (NumberFormatException e) {
                        // Keep default port
                    }
                }

                result.put("host", host);
                result.put("port", port);
                result.put("secure", isHttps);
                result.put("protocol", protocol);
                result.put("url", url);

                // Create HttpService to check additional details
                HttpService service = HttpService.httpService(host, port, isHttps);
                if (service.ipAddress() != null && !service.ipAddress().isEmpty()) {
                    result.put("ip_address", service.ipAddress());
                }

                boolean isDefaultPort = (isHttps && port == 443) || (!isHttps && port == 80);
                result.put("uses_default_port", isDefaultPort);
                
            } else {
                return McpUtils.createErrorResponse("Either 'request' or 'url' parameter is required");
            }
            
            return McpUtils.createSuccessResponse(result.toString());
            
        } catch (Exception e) {
            return McpUtils.createErrorResponse("Failed to analyze protocol: " + e.getMessage());
        }
    }
}
