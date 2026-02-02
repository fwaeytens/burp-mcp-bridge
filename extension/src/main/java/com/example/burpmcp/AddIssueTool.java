package com.example.burpmcp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.util.*;
import java.util.Locale;

/**
 * Enhanced AddIssueTool with dynamic issue grouping.
 * Intelligently checks for existing issues and groups them automatically,
 * similar to Burp's native scanner but with improved flexibility.
 */
public class AddIssueTool implements McpTool {
    private final MontoyaApi api;
    private final ObjectMapper mapper = new ObjectMapper();
    
    // No static mappings needed - we use dynamic grouping!

    public AddIssueTool(MontoyaApi api) {
        this.api = api;
    }

    @Override
    public Map<String, Object> getToolInfo() {
        Map<String, Object> tool = new HashMap<>();
        tool.put("name", "burp_add_issue");
        tool.put("title", "Create Issue");
        tool.put("description", "Add custom audit issues to Burp Suite with intelligent dynamic grouping. " +
            "Use this to report security findings discovered through manual testing or external tools. " +
            "Automatically groups with existing issues of the same type. Supports detailed evidence including " +
            "request/response pairs, payloads, remediation guidance, and references. Issues appear in Burp's Target > Issues panel.");

        // MCP 2025-06-18 annotations
        Map<String, Object> annotations = new HashMap<>();
        annotations.put("readOnlyHint", false);
        annotations.put("destructiveHint", false);
        annotations.put("idempotentHint", false);
        annotations.put("openWorldHint", false);
        tool.put("annotations", annotations);
        
        Map<String, Object> inputSchema = new HashMap<>();
        inputSchema.put("type", "object");
        
        Map<String, Object> properties = new HashMap<>();
        
        // Issue type (for grouping)
        Map<String, Object> issueTypeProperty = new HashMap<>();
        issueTypeProperty.put("type", "string");
        issueTypeProperty.put("description", "Vulnerability type (e.g., 'SQL injection', 'Cross-site scripting'). The tool will automatically group with similar existing issues.");
        properties.put("issueType", issueTypeProperty);
        
        // Specific issue name (optional - for backward compatibility)
        Map<String, Object> nameProperty = new HashMap<>();
        nameProperty.put("type", "string");
        nameProperty.put("description", "Specific issue instance description (optional - will be added to detail if provided)");
        properties.put("name", nameProperty);
        
        Map<String, Object> urlProperty = new HashMap<>();
        urlProperty.put("type", "string");
        urlProperty.put("description", "URL where the issue was found");
        properties.put("url", urlProperty);
        
        Map<String, Object> severityProperty = new HashMap<>();
        severityProperty.put("type", "string");
        severityProperty.put("description", "Issue severity (HIGH, MEDIUM, LOW, INFORMATION)");
        severityProperty.put("enum", List.of("HIGH", "MEDIUM", "LOW", "INFORMATION"));
        severityProperty.put("default", "MEDIUM");
        properties.put("severity", severityProperty);
        
        Map<String, Object> confidenceProperty = new HashMap<>();
        confidenceProperty.put("type", "string");
        confidenceProperty.put("description", "Confidence level (CERTAIN, FIRM, TENTATIVE)");
        confidenceProperty.put("enum", List.of("CERTAIN", "FIRM", "TENTATIVE"));
        confidenceProperty.put("default", "FIRM");
        properties.put("confidence", confidenceProperty);
        
        Map<String, Object> detailProperty = new HashMap<>();
        detailProperty.put("type", "string");
        detailProperty.put("description", "Detailed description of this specific instance, including vulnerable parameters, payloads used, etc.");
        properties.put("detail", detailProperty);
        
        Map<String, Object> evidenceProperty = new HashMap<>();
        evidenceProperty.put("type", "string");
        evidenceProperty.put("description", "Specific evidence for this instance (request/response snippets, error messages, etc.)");
        properties.put("evidence", evidenceProperty);
        
        Map<String, Object> remediationProperty = new HashMap<>();
        remediationProperty.put("type", "string");
        remediationProperty.put("description", "Remediation guidance - how to fix this vulnerability (AI can generate this)");
        properties.put("remediation", remediationProperty);

        Map<String, Object> backgroundProperty = new HashMap<>();
        backgroundProperty.put("type", "string");
        backgroundProperty.put("description", "Technical background about this vulnerability type (AI can provide context)");
        properties.put("background", backgroundProperty);

        Map<String, Object> referencesProperty = new HashMap<>();
        referencesProperty.put("type", "string");
        referencesProperty.put("description", "References and links for further reading (OWASP, CWE, etc.)");
        properties.put("references", referencesProperty);
        
        Map<String, Object> parametersProperty = new HashMap<>();
        parametersProperty.put("type", "string");
        parametersProperty.put("description", "Affected parameters (e.g., 'username', 'id', 'search')");
        properties.put("parameters", parametersProperty);
        
        Map<String, Object> requestProperty = new HashMap<>();
        requestProperty.put("type", "string");
        requestProperty.put("description", "Raw HTTP request that triggered the issue (can also provide array via 'requests')");
        properties.put("request", requestProperty);
        
        Map<String, Object> responseProperty = new HashMap<>();
        responseProperty.put("type", "string");
        responseProperty.put("description", "Raw HTTP response showing the vulnerability (can also provide array via 'responses')");
        properties.put("response", responseProperty);
        
        Map<String, Object> requestsProperty = new HashMap<>();
        requestsProperty.put("type", "array");
        requestsProperty.put("description", "Evidence requests. Each entry can be a raw request string or an object (e.g. {\"raw\": \"...\"}).\n" +
            "Objects may also include metadata fields like 'id' or 'notes' – only 'raw'/'request' are required to build evidence.");
        requestsProperty.put("items", Map.of("type", "string"));
        properties.put("requests", requestsProperty);
        
        Map<String, Object> responsesProperty = new HashMap<>();
        responsesProperty.put("type", "array");
        responsesProperty.put("description", "Evidence responses matching the requests array. Accepts raw strings or objects with a 'raw'/'response' field.");
        responsesProperty.put("items", Map.of("type", "string"));
        properties.put("responses", responsesProperty);
        
        Map<String, Object> payloadProperty = new HashMap<>();
        payloadProperty.put("type", "string");
        payloadProperty.put("description", "The actual payload used in the attack (will be bolded in detail)");
        properties.put("payload", payloadProperty);

        Map<String, Object> filtersProperty = new HashMap<>();
        filtersProperty.put("type", "object");
        filtersProperty.put("description", "ProxyHistoryTool filters for finding request in proxy history (method, parameter, contains, etc.) - see burp_proxy_history for all options. Use when you want to match specific proxy history entries.");
        properties.put("filters", filtersProperty);

        inputSchema.put("properties", properties);
        inputSchema.put("required", List.of("url", "detail"));
        
        tool.put("inputSchema", inputSchema);
        
        return tool;
    }

    @Override
    public Object execute(JsonNode arguments) throws Exception {
        try {
            // Extract parameters
            String issueType = arguments.has("issueType") ? arguments.get("issueType").asText() : "";
            String specificName = arguments.has("name") ? arguments.get("name").asText() : "";
            String url = arguments.get("url").asText();
            String detail = arguments.get("detail").asText();
            String evidence = arguments.has("evidence") ? arguments.get("evidence").asText() : "";
            String remediation = arguments.has("remediation") ? arguments.get("remediation").asText() : "";
            String backgroundParam = arguments.has("background") ? arguments.get("background").asText() : "";
            String references = arguments.has("references") ? arguments.get("references").asText() : "";
            String parameters = arguments.has("parameters") ? arguments.get("parameters").asText() : "";
            String requestData = arguments.has("request") ? arguments.get("request").asText() : "";
            String responseData = arguments.has("response") ? arguments.get("response").asText() : "";
            String payload = arguments.has("payload") ? arguments.get("payload").asText() : "";

            // Support for proxy history filters
            JsonNode filters = null;
            if (arguments.has("filters")) {
                JsonNode filterNode = arguments.get("filters");
                if (filterNode.isTextual()) {
                    // If filters is a string, parse it as JSON
                    try {
                        filters = mapper.readTree(filterNode.asText());
                    } catch (Exception e) {
                        api.logging().logToError("Failed to parse filters JSON: " + e.getMessage());
                    }
                } else {
                    filters = filterNode;
                }
            }

            // Support for multiple requests/responses
            JsonNode requestsNode = arguments.has("requests") ? arguments.get("requests") : null;
            JsonNode responsesNode = arguments.has("responses") ? arguments.get("responses") : null;
            
            // Parse severity and confidence
            AuditIssueSeverity severity = parseSeverity(arguments.has("severity") ? arguments.get("severity").asText() : null);
            AuditIssueConfidence confidence = parseConfidence(arguments.has("confidence") ? arguments.get("confidence").asText() : null);
            
            // Determine the standard issue type for grouping (now with dynamic checking)
            String standardIssueType = determineStandardIssueType(issueType, specificName, url);
            
            // Build the issue detail in Burp's native format (no headers, inline bold tags)
            StringBuilder instanceDetail = new StringBuilder();
            
            // Format the main vulnerability description with parameter names in bold
            String formattedDetail = detail;
            if (!parameters.isEmpty()) {
                // Make parameter names bold in the detail text
                String[] paramNames = parameters.split(",\\s*");
                for (String param : paramNames) {
                    formattedDetail = formattedDetail.replaceAll(
                        "\\b" + param.trim() + "\\b",
                        "<b>" + param.trim() + "</b>"
                    );
                }
                // Start with "The <b>parameter</b> parameter appears to be vulnerable..."
                if (!formattedDetail.contains("<b>") && !formattedDetail.startsWith("The ")) {
                    instanceDetail.append("The <b>").append(parameters).append("</b> parameter appears to be vulnerable to ")
                                 .append(standardIssueType.toLowerCase()).append(". ");
                }
            }
            
            instanceDetail.append(formattedDetail);
            
            // Add payload information if provided
            if (!payload.isEmpty()) {
                instanceDetail.append("<br><br>The payload <b>").append(escapeHtml(payload))
                             .append("</b> was submitted in the ").append(!parameters.isEmpty() ? parameters : "request")
                             .append(" parameter.");
            }
            
            // Add evidence inline with bold tags for payloads/values
            if (!evidence.isEmpty()) {
                instanceDetail.append("<br><br>");
                
                // Format evidence - look for payloads or specific values
                String formattedEvidence = evidence;
                // Try to identify and bold any code/payload-like content
                if (evidence.contains("payload") || evidence.contains("Payload")) {
                    formattedEvidence = evidence.replaceAll(
                        "payload[:\\s]+([^\\s<]+)",
                        "payload <b>$1</b>"
                    );
                } else if (evidence.contains(":")) {
                    // Bold values after colons for key:value pairs
                    formattedEvidence = evidence.replaceAll(
                        ":\\s*([^,\\n]+)",
                        ": <b>$1</b>"
                    );
                }
                instanceDetail.append(formattedEvidence);
            }
            
            // If specific instance name differs from type, append it
            if (!specificName.isEmpty() && !specificName.equalsIgnoreCase(standardIssueType)) {
                instanceDetail.append("<br><br>").append(specificName);
            }
            
            // Use AI-provided remediation or generic fallback
            String finalRemediation = !remediation.isEmpty() ? remediation :
                "The AI agent did not provide specific remediation. Please review the vulnerability and implement appropriate fixes.";

            // Use AI-provided background or generic fallback
            String background = !backgroundParam.isEmpty() ? backgroundParam :
                "The AI agent did not provide specific background information for this vulnerability.";

            // Add references if provided
            if (!references.isEmpty()) {
                background += "<br><br><b>References:</b><br>" + escapeHtml(references).replace("\n", "<br>");
            }
            
            // Create proof-of-concept request/response pairs
            List<HttpRequestResponse> requestResponses = buildEvidencePairs(
                requestsNode,
                responsesNode,
                requestData,
                responseData,
                url
            );
            
            // Final fallback: attempt proxy history lookup when only URL was supplied
            if (requestResponses.isEmpty() && requestData.isEmpty() && requestsNode == null) {
                ProxyHttpRequestResponse proxyEntry = findInProxyHistory(url, null, filters);
                if (proxyEntry != null) {
                    requestResponses.add(HttpRequestResponse.httpRequestResponse(
                        proxyEntry.finalRequest(),
                        proxyEntry.response()
                    ));
                    api.logging().logToOutput("Using request/response from proxy history with filters");
                }
            }
            
            // Create the audit issue with standardized name for grouping
            AuditIssue auditIssue = AuditIssue.auditIssue(
                standardIssueType,  // Use standard name for grouping
                instanceDetail.toString(),  // Specific instance details
                finalRemediation,
                url,
                severity,
                confidence,
                background,
                "", // remediationBackground
                severity, // typicalSeverity
                requestResponses
            );
            
            // Add to site map - Burp will automatically group by issue name
            api.siteMap().add(auditIssue);
            
            // Log the action
            api.logging().logToOutput(String.format(
                "✅ Added %s issue at %s (grouped under '%s')",
                severity.name(),
                url,
                standardIssueType
            ));
            
            // Return success message
            Map<String, Object> result = new HashMap<>();
            result.put("success", true);
            result.put("issue_type", standardIssueType);
            result.put("url", url);
            result.put("severity", severity.name());
            result.put("confidence", confidence.name());
            result.put("message", String.format(
                "Successfully added issue:\n" +
                "Type: %s\n" +
                "URL: %s\n" +
                "Severity: %s\n" +
                "Confidence: %s\n\n" +
                "The issue will be grouped under '%s' in Burp's issue list.",
                standardIssueType,
                url,
                severity.name(),
                confidence.name(),
                standardIssueType
            ));

            try {
                String json = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(result);
                return McpUtils.createSuccessResponse(json);
            } catch (Exception jsonException) {
                return McpUtils.createSuccessResponse(result.get("message").toString());
            }
            
        } catch (Exception e) {
            api.logging().logToError("Error adding issue: " + e.getMessage());
            return McpUtils.createErrorResponse("Failed to add issue: " + e.getMessage());
        }
    }
    
    /**
     * Determine the standard issue type for grouping based on input.
     * First tries to find existing issue groups, then normalizes the type.
     */
    private String determineStandardIssueType(String issueType, String specificName, String url) {
        // Normalize the issue type
        String normalizedType = normalizeIssueType(issueType, specificName);

        // Try to find an existing issue group to add to
        String existingGroup = findExistingIssueGroup(normalizedType, url);
        if (existingGroup != null) {
            api.logging().logToOutput(String.format(
                "Found existing issue group '%s', will add new instance", existingGroup));
            return existingGroup;
        }

        api.logging().logToOutput(String.format(
            "No existing issue group found for '%s', creating new group", normalizedType));
        return normalizedType;
    }

    /**
     * Normalize issue type - just clean up the input
     */
    private String normalizeIssueType(String issueType, String specificName) {
        // Use the provided issue type if available
        if (issueType != null && !issueType.trim().isEmpty()) {
            return issueType.trim();
        }
        
        // Fall back to using the specific name if provided
        if (specificName != null && !specificName.trim().isEmpty()) {
            return specificName.trim();
        }
        
        // Default fallback
        return "Security vulnerability";
    }

    private AuditIssueSeverity parseSeverity(String value) {
        if (value == null || value.trim().isEmpty()) {
            return AuditIssueSeverity.MEDIUM;
        }

        String normalized = value.trim().toUpperCase(Locale.ROOT);

        // Handle common aliases and variations
        switch (normalized) {
            case "HIGH":
                return AuditIssueSeverity.HIGH;
            case "MEDIUM":
                return AuditIssueSeverity.MEDIUM;
            case "LOW":
                return AuditIssueSeverity.LOW;
            case "INFO":
            case "INFORMATION":
                return AuditIssueSeverity.INFORMATION;
            default:
                api.logging().logToOutput("Unknown severity '" + value + "', defaulting to MEDIUM");
                return AuditIssueSeverity.MEDIUM;
        }
    }

    private AuditIssueConfidence parseConfidence(String value) {
        if (value == null || value.trim().isEmpty()) {
            return AuditIssueConfidence.FIRM;
        }

        String normalized = value.trim().toUpperCase(Locale.ROOT);

        switch (normalized) {
            case "CERTAIN":
                return AuditIssueConfidence.CERTAIN;
            case "FIRM":
                return AuditIssueConfidence.FIRM;
            case "TENTATIVE":
                return AuditIssueConfidence.TENTATIVE;
            default:
                api.logging().logToOutput("Unknown confidence '" + value + "', defaulting to FIRM");
                return AuditIssueConfidence.FIRM;
        }
    }

    private HttpRequest buildHttpRequest(String rawRequest, String fallbackUrl) {
        if (rawRequest == null || rawRequest.isBlank()) {
            return null;
        }

        try {
            String canonicalRequest = normalizeRequestLine(rawRequest);
            String hostHeader = extractHostHeader(canonicalRequest);
            HttpService service = resolveHttpService(hostHeader, fallbackUrl);

            if (service != null) {
                return HttpRequest.httpRequest(service, canonicalRequest);
            }

            return HttpRequest.httpRequest(canonicalRequest);
        } catch (Exception e) {
            api.logging().logToOutput("Unable to construct HTTP request for PoC evidence: " + e.getMessage());
            return null;
        }
    }

    private String normalizeRequestLine(String rawRequest) {
        String[] lines = rawRequest.split("\r?\n", -1);
        if (lines.length == 0) {
            return rawRequest;
        }

        String requestLine = lines[0];
        String[] parts = requestLine.split(" ", 3);
        if (parts.length >= 2) {
            String target = parts[1];
            try {
                URI uri = new URI(target);
                if (uri.getScheme() != null && uri.getHost() != null) {
                    StringBuilder path = new StringBuilder();
                    if (uri.getRawPath() != null && !uri.getRawPath().isEmpty()) {
                        path.append(uri.getRawPath());
                    } else {
                        path.append('/');
                    }
                    if (uri.getRawQuery() != null && !uri.getRawQuery().isEmpty()) {
                        path.append('?').append(uri.getRawQuery());
                    }
                    if (uri.getRawFragment() != null && !uri.getRawFragment().isEmpty()) {
                        path.append('#').append(uri.getRawFragment());
                    }
                    parts[1] = path.toString();
                    lines[0] = String.join(" ", parts);
                    return String.join("\r\n", lines);
                }
            } catch (Exception ignored) {
                // Leave request line as provided
            }
        }
        return rawRequest;
    }

    private String extractHostHeader(String rawRequest) {
        String[] lines = rawRequest.split("\r?\n");
        for (String line : lines) {
            if (line.toLowerCase(Locale.ROOT).startsWith("host:")) {
                int colon = line.indexOf(':');
                if (colon >= 0 && colon + 1 < line.length()) {
                    return line.substring(colon + 1).trim();
                }
            }
        }
        return null;
    }

    private HttpService resolveHttpService(String hostHeader, String fallbackUrl) {
        try {
            String host = null;
            Integer port = null;
            Boolean secure = null;

            if (fallbackUrl != null && !fallbackUrl.isBlank()) {
                try {
                    URI uri = new URI(fallbackUrl);
                    if (uri.getHost() != null) {
                        host = uri.getHost();
                    }
                    if (uri.getPort() != -1) {
                        port = uri.getPort();
                    }
                    if (uri.getScheme() != null) {
                        secure = uri.getScheme().equalsIgnoreCase("https");
                    }
                } catch (Exception ignored) {
                    // Ignore URL parsing issues; we'll rely on Host header if available
                }
            }

            if (hostHeader != null && !hostHeader.isBlank()) {
                HostPort parsed = parseHostHeader(hostHeader);
                if (parsed.host != null) {
                    host = parsed.host;
                }
                if (parsed.port != null) {
                    port = parsed.port;
                }
                if (parsed.secure != null) {
                    secure = parsed.secure;
                }
            }

            if (host == null) {
                return null;
            }

            if (port == null) {
                port = Boolean.TRUE.equals(secure) ? 443 : 80;
            }

            if (secure == null) {
                secure = port == 443;
            }

            return HttpService.httpService(host, port, secure);
        } catch (Exception e) {
            api.logging().logToOutput("Failed to resolve HttpService from request: " + e.getMessage());
            return null;
        }
    }

    private HostPort parseHostHeader(String hostHeader) {
        HostPort result = new HostPort();
        if (hostHeader == null || hostHeader.isBlank()) {
            return result;
        }

        String trimmed = hostHeader.trim();

        try {
            if (trimmed.startsWith("[")) {
                int close = trimmed.indexOf(']');
                if (close > 0) {
                    result.host = trimmed.substring(1, close);
                    if (close + 1 < trimmed.length() && trimmed.charAt(close + 1) == ':') {
                        String portPart = trimmed.substring(close + 2).trim();
                        result.port = safeParsePort(portPart);
                    }
                } else {
                    result.host = trimmed;
                }
            } else {
                int colon = trimmed.indexOf(':');
                if (colon > 0 && trimmed.indexOf(':', colon + 1) == -1) {
                    result.host = trimmed.substring(0, colon).trim();
                    result.port = safeParsePort(trimmed.substring(colon + 1).trim());
                } else {
                    result.host = trimmed;
                }
            }

            if (result.port != null) {
                if (result.port == 443) {
                    result.secure = true;
                } else if (result.port == 80) {
                    result.secure = false;
                }
            }
        } catch (Exception e) {
            api.logging().logToOutput("Failed to parse Host header '" + hostHeader + "': " + e.getMessage());
        }

        return result;
    }

    private Integer safeParsePort(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            int parsed = Integer.parseInt(value);
            if (parsed > 0 && parsed <= 65535) {
                return parsed;
            }
        } catch (NumberFormatException ignored) {
            api.logging().logToOutput("Ignoring invalid port value '" + value + "'");
        }
        return null;
    }
    
    
    /**
     * Find matching request in proxy history
     */
    /**
     * Find an existing HttpRequestResponse in proxy history using filters or simple URL match
     */
    private ProxyHttpRequestResponse findInProxyHistory(String targetUrl, String requestData, JsonNode filters) {
        // If filters are provided, use ProxyHistoryTool's advanced filtering
        if (filters != null && filters.isObject()) {
            try {
                // Build the filter object for ProxyHistoryTool
                com.fasterxml.jackson.databind.node.ObjectNode filterArgs = mapper.createObjectNode();

                // Add the URL as a filter
                if (targetUrl != null && !targetUrl.isEmpty()) {
                    try {
                        java.net.URL url = new java.net.URL(targetUrl);
                        filterArgs.put("hostname", url.getHost());
                        String path = url.getPath();
                        if (path != null && !path.isEmpty() && !path.equals("/")) {
                            filterArgs.put("path", path.substring(1)); // Remove leading /
                        }
                    } catch (Exception e) {
                        api.logging().logToError("Could not parse URL: " + targetUrl);
                    }
                }

                // Add all other filters
                filters.fields().forEachRemaining(entry -> {
                    filterArgs.set(entry.getKey(), entry.getValue());
                });

                api.logging().logToOutput("AddIssueTool: Applying filters: " + filterArgs.toString());

                // Use ProxyHistoryTool to get filtered results
                ProxyHistoryTool proxyTool = new ProxyHistoryTool(api);
                ProxyHistoryTool.FilteredResults results = proxyTool.applyFilters(filterArgs);

                List<ProxyHttpRequestResponse> filteredEntries = results.getEntries();
                List<Integer> originalIds = results.getOriginalIndices();

                if (!filteredEntries.isEmpty()) {
                    ProxyHttpRequestResponse item = filteredEntries.get(0);
                    int originalId = originalIds.get(0);

                    api.logging().logToOutput("Found match using ProxyHistoryTool filtering: Entry #" + originalId +
                        " - " + item.finalRequest().method() + " " + item.finalRequest().url());
                    return item;
                }

                api.logging().logToOutput("No entries found matching filters");

            } catch (Exception e) {
                api.logging().logToError("Error using ProxyHistoryTool for filtering: " + e.getMessage());
            }

            return null;
        }

        // Fallback to simple URL matching
        try {
            List<ProxyHttpRequestResponse> history = api.proxy().history();

            // First try exact URL match (allowing minor normalisation)
            for (ProxyHttpRequestResponse item : history) {
                if (item.finalRequest() != null && urlsEquivalent(targetUrl, item.finalRequest().url())) {
                    return item;
                }
            }

            // If request data provided, try to match by method and path
            if (requestData != null && !requestData.isBlank() && requestData.contains(" ")) {
                String[] parts = requestData.split(" ");
                if (parts.length >= 2) {
                    String method = parts[0];
                    String path = parts[1].split("\\?")[0]; // Remove query string

                    for (ProxyHttpRequestResponse item : history) {
                        if (item.finalRequest() != null &&
                            method.equalsIgnoreCase(item.finalRequest().method()) &&
                            normalizePath(item.finalRequest().path()).equals(normalizePath(path))) {
                            return item;
                        }
                    }
                }
            }

        } catch (Exception e) {
            api.logging().logToOutput("Error searching proxy history: " + e.getMessage());
        }

        return null;
    }

    // Overload for backward compatibility
    private ProxyHttpRequestResponse findInProxyHistory(String url, String requestData) {
        return findInProxyHistory(url, requestData, null);
    }

    private static class HostPort {
        String host;
        Integer port;
        Boolean secure;
    }

    private List<HttpRequestResponse> buildEvidencePairs(
        JsonNode requestsNode,
        JsonNode responsesNode,
        String singleRequest,
        String singleResponse,
        String fallbackUrl
    ) {
        List<HttpRequestResponse> pairs = new ArrayList<>();

        List<String> requestStrings = new ArrayList<>();
        List<String> responseStrings = new ArrayList<>();

        extractEvidenceStrings(requestsNode, requestStrings);
        extractEvidenceStrings(responsesNode, responseStrings);

        if (singleRequest != null && !singleRequest.isBlank()) {
            requestStrings.add(singleRequest);
            if (singleResponse != null && !singleResponse.isBlank()) {
                responseStrings.add(singleResponse);
            }
        }

        for (int i = 0; i < requestStrings.size(); i++) {
            String rawRequest = requestStrings.get(i);
            if (rawRequest == null || rawRequest.isBlank()) {
                continue;
            }

            HttpRequest request = buildHttpRequest(rawRequest, fallbackUrl);
            if (request == null) {
                api.logging().logToOutput("Skipping evidence request due to missing host information");
                continue;
            }

            HttpResponse response = null;
            if (i < responseStrings.size()) {
                String rawResponse = responseStrings.get(i);
                if (rawResponse != null && !rawResponse.isBlank()) {
                    try {
                        response = HttpResponse.httpResponse(rawResponse);
                    } catch (Exception ex) {
                        api.logging().logToOutput("Error parsing evidence response: " + ex.getMessage());
                    }
                }
            }

            if (response != null) {
                pairs.add(HttpRequestResponse.httpRequestResponse(request, response));
                continue;
            }

            ProxyHttpRequestResponse proxyEntry = findInProxyHistory(request.url(), rawRequest);
            if (proxyEntry != null) {
                pairs.add(HttpRequestResponse.httpRequestResponse(proxyEntry.finalRequest(), proxyEntry.response()));
            } else {
                api.logging().logToOutput("Could not find matching response for evidence request; skipping");
            }
        }

        return pairs;
    }

    private void extractEvidenceStrings(JsonNode node, List<String> collector) {
        if (node == null || node.isNull()) {
            return;
        }

        if (node.isArray()) {
            for (JsonNode item : node) {
                collectSingleEvidence(item, collector);
            }
            return;
        }

        // Accept single object (legacy usage)
        collectSingleEvidence(node, collector);
    }

    private void collectSingleEvidence(JsonNode node, List<String> collector) {
        if (node == null || node.isNull()) {
            return;
        }

        if (node.isTextual()) {
            collector.add(node.asText());
            return;
        }

        if (node.isObject()) {
            for (String key : List.of("raw", "request", "response", "content")) {
                JsonNode value = node.get(key);
                if (value != null && value.isTextual()) {
                    collector.add(value.asText());
                    return;
                }
            }

            JsonNode body = node.get("body");
            if (body != null && body.isTextual()) {
                collector.add(body.asText());
            }
        }
    }

    private String normalizePath(String path) {
        if (path == null || path.isBlank()) {
            return "/";
        }
        return path.endsWith("/") && path.length() > 1 ? path.substring(0, path.length() - 1) : path;
    }

    private boolean urlsEquivalent(String targetUrl, String candidateUrl) {
        if (targetUrl == null || candidateUrl == null) {
            return false;
        }

        try {
            URI target = new URI(targetUrl);
            URI candidate = new URI(candidateUrl);

            if (target.getHost() == null || candidate.getHost() == null) {
                return targetUrl.equals(candidateUrl);
            }

            int targetPort = target.getPort();
            if (targetPort == -1) {
                targetPort = "https".equalsIgnoreCase(target.getScheme()) ? 443 : 80;
            }

            int candidatePort = candidate.getPort();
            if (candidatePort == -1) {
                candidatePort = "https".equalsIgnoreCase(candidate.getScheme()) ? 443 : 80;
            }

            return target.getHost().equalsIgnoreCase(candidate.getHost()) &&
                   targetPort == candidatePort &&
                   normalizePath(target.getPath()).equals(normalizePath(candidate.getPath()));

        } catch (Exception e) {
            return targetUrl.equals(candidateUrl);
        }
    }

    /**
     * Find an existing issue group that matches this vulnerability type
     */
    private String findExistingIssueGroup(String normalizedType, String url) {
        try {
            // Get all existing issues
            List<AuditIssue> existingIssues = api.siteMap().issues();

            // Extract the host from the URL for better matching
            String targetHost = extractHost(url);

            // Look for exact matches first
            for (AuditIssue issue : existingIssues) {
                String issueName = issue.name();

                // Exact match
                if (issueName.equalsIgnoreCase(normalizedType)) {
                    return issueName;
                }
            }

            // Look for similar issues on the same host
            for (AuditIssue issue : existingIssues) {
                String issueName = issue.name();
                String issueHost = extractHost(issue.baseUrl());

                // Check if it's the same host and similar vulnerability type
                if (targetHost.equals(issueHost) && areSimilarIssueTypes(normalizedType, issueName)) {
                    return issueName;
                }
            }

            // Look for similar issues regardless of host
            for (AuditIssue issue : existingIssues) {
                String issueName = issue.name();

                // Check if they're similar vulnerability types
                if (areSimilarIssueTypes(normalizedType, issueName)) {
                    return issueName;
                }
            }

        } catch (Exception e) {
            api.logging().logToOutput("Error checking existing issues: " + e.getMessage());
        }

        return null;
    }

    /**
     * Check if two issue types are similar enough to group together
     */
    private boolean areSimilarIssueTypes(String type1, String type2) {
        if (type1 == null || type2 == null) {
            return false;
        }

        // Normalize for comparison
        String norm1 = type1.toLowerCase().trim();
        String norm2 = type2.toLowerCase().trim();

        // Exact match
        if (norm1.equals(norm2)) {
            return true;
        }

        // Remove common prefixes/suffixes for better matching
        norm1 = norm1.replaceAll("(vulnerability|vuln|issue|flaw|weakness)$", "").trim();
        norm2 = norm2.replaceAll("(vulnerability|vuln|issue|flaw|weakness)$", "").trim();

        if (norm1.equals(norm2)) {
            return true;
        }

        // Check for common vulnerability type keywords
        String[] commonTypes = {"injection", "scripting", "xss", "sql", "command", "traversal",
                                "xxe", "ssrf", "csrf", "authentication", "authorization",
                                "session", "clickjacking", "redirect"};

        for (String keyword : commonTypes) {
            if (norm1.contains(keyword) && norm2.contains(keyword)) {
                return true;
            }
        }

        // Check string similarity (simple approach)
        if (calculateSimilarity(norm1, norm2) > 0.8) {
            return true;
        }

        return false;
    }

    /**
     * Calculate string similarity using a simple algorithm
     */
    private double calculateSimilarity(String s1, String s2) {
        if (s1 == null || s2 == null) {
            return 0.0;
        }

        int maxLength = Math.max(s1.length(), s2.length());
        if (maxLength == 0) {
            return 1.0;
        }

        int commonChars = 0;
        for (int i = 0; i < Math.min(s1.length(), s2.length()); i++) {
            if (s1.charAt(i) == s2.charAt(i)) {
                commonChars++;
            }
        }

        return (double) commonChars / maxLength;
    }

    /**
     * Extract host from URL
     */
    private String extractHost(String url) {
        try {
            URI uri = new URI(url);
            return uri.getHost() != null ? uri.getHost() : "";
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * Escape HTML special characters
     */
    private String escapeHtml(String input) {
        if (input == null) return "";
        return input.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\"", "&quot;")
                   .replace("'", "&#39;");
    }
}
