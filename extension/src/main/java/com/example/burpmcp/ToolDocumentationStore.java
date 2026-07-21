package com.example.burpmcp;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Singleton store for all tool documentation
 */
public class ToolDocumentationStore {
    private static ToolDocumentationStore instance;
    private final Map<String, ToolDocumentation> documentation;
    private final Map<String, List<String>> categories;
    private static final Set<String> SCHEMA_SYNC_EXCLUSIONS = Set.of(
        "burp_help"
    );

    private ToolDocumentationStore() {
        this.documentation = new LinkedHashMap<>();
        this.categories = new LinkedHashMap<>();
        populateRegistryMetadata();
        populateEnhancedMetadata();
    }

    /**
     * Seed documentation from the ordered registry. Live descriptions and schemas are
     * overlaid later by syncWithToolSchemas().
     */
    private void populateRegistryMetadata() {
        for (ToolDescriptor descriptor : ToolRegistry.documentationDescriptors()) {
            ToolDocumentation.Builder builder = new ToolDocumentation.Builder(descriptor.getName())
                .category(descriptor.getCategory())
                .description("");
            for (String keyword : descriptor.getKeywords()) {
                builder.addKeyword(keyword);
            }
            for (String capability : descriptor.getCapabilities()) {
                builder.addCapability(capability);
            }
            ToolDocumentation doc = builder.build();
            doc.setActionRequirements(descriptor.getActionRequirements());
            documentation.put(descriptor.getName(), doc);
        }
    }
    
    public static synchronized ToolDocumentationStore getInstance() {
        if (instance == null) {
            instance = new ToolDocumentationStore();
        }
        return instance;
    }
    
    public ToolDocumentation getDocumentation(String toolName) {
        return documentation.get(toolName);
    }
    
    public Collection<ToolDocumentation> getAllDocumentation() {
        return documentation.values();
    }
    
    public List<String> getAllToolNames() {
        return new ArrayList<>(documentation.keySet());
    }
    
    public Map<String, List<String>> getCategorizedTools() {
        Map<String, List<String>> copy = new LinkedHashMap<>();
        categories.forEach((category, tools) -> copy.put(category, new ArrayList<>(tools)));
        return copy;
    }
    
    public List<String> getCategories() {
        return new ArrayList<>(categories.keySet());
    }
    
    public List<Map<String, Object>> getAllSummaries() {
        List<Map<String, Object>> summaries = new ArrayList<>();
        for (ToolDocumentation doc : documentation.values()) {
            Map<String, Object> summary = new HashMap<>();
            summary.put("name", doc.getName());
            summary.put("category", doc.getCategory());
            summary.put("description", doc.getDescription());
            summaries.add(summary);
        }
        return summaries;
    }
    
    public List<Map<String, Object>> getAllParameters() {
        List<Map<String, Object>> allParams = new ArrayList<>();
        for (ToolDocumentation doc : documentation.values()) {
            Map<String, Object> toolParams = new HashMap<>();
            toolParams.put("tool", doc.getName());
            toolParams.put("parameters", doc.getParameters());
            allParams.add(toolParams);
        }
        return allParams;
    }
    
    public List<Map<String, Object>> getAllExamples() {
        List<Map<String, Object>> allExamples = new ArrayList<>();
        for (ToolDocumentation doc : documentation.values()) {
            if (!doc.getExamples().isEmpty()) {
                Map<String, Object> toolExamples = new HashMap<>();
                toolExamples.put("tool", doc.getName());
                toolExamples.put("examples", doc.getExamples());
                allExamples.add(toolExamples);
            }
        }
        return allExamples;
    }

    public void syncWithToolSchemas(Map<String, McpTool> toolInstances) {
        // Clear categories and rebuild from scratch to prune stale entries
        categories.clear();

        for (Map.Entry<String, McpTool> entry : toolInstances.entrySet()) {
            String toolName = entry.getKey();
            if (SCHEMA_SYNC_EXCLUSIONS.contains(toolName)) {
                continue;
            }

            McpTool tool = entry.getValue();
            Map<String, Object> toolInfo;
            try {
                toolInfo = tool.getToolInfo();
            } catch (Exception e) {
                // Skip tools that fail to provide metadata
                continue;
            }
            if (toolInfo == null) {
                continue;
            }

            ToolDocumentation doc = documentation.get(toolName);
            if (doc == null) {
                String description = (String) toolInfo.getOrDefault("description", "");
                doc = new ToolDocumentation.Builder(toolName)
                    .category("Uncategorized")
                    .description(description)
                    .build();
                documentation.put(toolName, doc);
            } else {
                doc.setDescription((String) toolInfo.get("description"));
            }

            Object inputSchemaObj = toolInfo.get("inputSchema");
            if (inputSchemaObj instanceof Map<?, ?> schemaMap) {
                @SuppressWarnings("unchecked")
                Map<String, Object> inputSchema = (Map<String, Object>) schemaMap;
                doc.replaceParameters(extractParameters(inputSchema));
            } else {
                doc.replaceParameters(Collections.emptyList());
            }

            Object outputSchemaObj = toolInfo.get("outputSchema");
            if (outputSchemaObj instanceof Map<?, ?> outputSchema) {
                @SuppressWarnings("unchecked")
                Map<String, Object> returns = (Map<String, Object>) outputSchema;
                doc.setReturns(returns);
            }

            // Update categories map - add tool to its category
            String category = doc.getCategory();
            categories.computeIfAbsent(category, k -> new ArrayList<>()).add(toolName);
        }
    }

    private List<Map<String, Object>> extractParameters(Map<String, Object> inputSchema) {
        Map<String, Object> properties = safeMap(inputSchema.get("properties"));
        List<Map<String, Object>> parameters = new ArrayList<>();
        if (properties == null || properties.isEmpty()) {
            return parameters;
        }

        Set<String> required = new LinkedHashSet<>();
        Object requiredObj = inputSchema.get("required");
        if (requiredObj instanceof Collection<?> requiredCollection) {
            for (Object item : requiredCollection) {
                if (item != null) {
                    required.add(item.toString());
                }
            }
        }

        // Extract conditional requirements from allOf/if-then blocks
        Map<String, List<String>> conditionalRequired = extractConditionalRequired(inputSchema);

        for (Map.Entry<String, Object> entry : properties.entrySet()) {
            String paramName = entry.getKey();
            Map<String, Object> property = safeMap(entry.getValue());
            if (property == null) {
                continue;
            }

            Map<String, Object> param = new LinkedHashMap<>();
            param.put("name", paramName);
            param.put("type", property.getOrDefault("type", "object"));
            param.put("required", required.contains(paramName));

            // Add conditional requirement info (e.g., "required_when": {"action": ["START_SCAN", "CRAWL_ONLY"]})
            List<String> requiredByActions = new ArrayList<>();
            for (Map.Entry<String, List<String>> cond : conditionalRequired.entrySet()) {
                if (cond.getValue().contains(paramName)) {
                    requiredByActions.add(cond.getKey());
                }
            }
            if (!requiredByActions.isEmpty()) {
                param.put("required_when", Map.of("action", requiredByActions));
            }

            if (property.containsKey("description")) {
                param.put("description", property.get("description"));
            }
            if (property.containsKey("default")) {
                param.put("default", property.get("default"));
            }
            if (property.containsKey("enum")) {
                param.put("enum", property.get("enum"));
            }
            if (property.containsKey("items")) {
                param.put("items", property.get("items"));
            }
            if (property.containsKey("properties")) {
                param.put("properties", property.get("properties"));
            }
            copyIfPresent(property, param, "minimum");
            copyIfPresent(property, param, "maximum");
            copyIfPresent(property, param, "minItems");
            copyIfPresent(property, param, "maxItems");
            copyIfPresent(property, param, "pattern");
            copyIfPresent(property, param, "format");
            copyIfPresent(property, param, "minLength");
            copyIfPresent(property, param, "maxLength");

            parameters.add(param);
        }

        return parameters;
    }

    /**
     * Extract conditional required fields from allOf/if-then blocks.
     * Returns map of action_value -> list of required param names.
     */
    @SuppressWarnings("unchecked")
    private Map<String, List<String>> extractConditionalRequired(Map<String, Object> inputSchema) {
        Map<String, List<String>> result = new LinkedHashMap<>();
        Object allOfObj = inputSchema.get("allOf");
        if (!(allOfObj instanceof List<?>)) return result;

        for (Object item : (List<?>) allOfObj) {
            if (!(item instanceof Map<?, ?>)) continue;
            Map<String, Object> rule = (Map<String, Object>) item;

            // Extract action value from if block
            Map<String, Object> ifBlock = safeMap(rule.get("if"));
            if (ifBlock == null) continue;
            Map<String, Object> ifProps = safeMap(ifBlock.get("properties"));
            if (ifProps == null) continue;
            Map<String, Object> actionConstraint = safeMap(ifProps.get("action"));
            if (actionConstraint == null || !actionConstraint.containsKey("const")) continue;
            String actionValue = actionConstraint.get("const").toString();

            // Extract required fields from then block
            Map<String, Object> thenBlock = safeMap(rule.get("then"));
            if (thenBlock == null) continue;
            Object thenRequired = thenBlock.get("required");
            if (thenRequired instanceof Collection<?> reqList) {
                List<String> fields = new ArrayList<>();
                for (Object r : reqList) {
                    if (r != null) fields.add(r.toString());
                }
                result.put(actionValue, fields);
            }
        }
        return result;
    }

    private void copyIfPresent(Map<String, Object> source, Map<String, Object> target, String key) {
        if (source.containsKey(key)) {
            target.put(key, source.get(key));
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> safeMap(Object value) {
        if (value instanceof Map<?, ?> map) {
            return (Map<String, Object>) map;
        }
        return null;
    }

    private void addToolEnhancements(String toolName,
                                     List<String> relatedTools,
                                     List<Map<String, Object>> examples,
                                     List<String> bestPractices) {
        ToolDescriptor descriptor = ToolRegistry.get(toolName);
        String effectiveCategory = descriptor != null ? descriptor.getCategory() : "Uncategorized";
        List<String> effectiveKeywords = descriptor != null ? descriptor.getKeywords() : List.of();
        List<String> effectiveCapabilities = descriptor != null ? descriptor.getCapabilities() : List.of();

        ToolDocumentation doc = documentation.get(toolName);
        if (doc == null) {
            // Create new documentation entry
            doc = new ToolDocumentation.Builder(toolName)
                .category(effectiveCategory)
                .description("") // Will be populated by syncWithToolSchemas
                .build();
            documentation.put(toolName, doc);
        }

        // Rebuild with all metadata
        ToolDocumentation.Builder builder = new ToolDocumentation.Builder(toolName)
            .category(effectiveCategory)
            .description(doc.getDescription());

        // Add keywords and capabilities
        for (String keyword : effectiveKeywords) {
            builder.addKeyword(keyword);
        }
        for (String capability : effectiveCapabilities) {
            builder.addCapability(capability);
        }

        // Add related tools
        for (String related : relatedTools) {
            builder.addRelatedTool(related);
        }

        // Add examples
        for (Map<String, Object> example : examples) {
            builder.addExample(
                (String) example.get("title"),
                safeMap(example.get("input")),
                safeMap(example.get("output")),
                (String) example.get("explanation")
            );
        }

        // Add best practices
        for (String practice : bestPractices) {
            builder.addBestPractice(practice);
        }

        ToolDocumentation updated = builder.build();
        updated.setActionRequirements(descriptor != null
            ? descriptor.getActionRequirements()
            : doc.getActionRequirements());
        documentation.put(toolName, updated);
    }

    /**
     * Populate curated metadata with examples, related tools, and best practices
     */
    private void populateEnhancedMetadata() {
        // burp_custom_http - PRIMARY HTTP tool with examples
        addToolEnhancements("burp_custom_http",
            List.of("burp_response_analyzer", "burp_session_management", "burp_proxy_history"),
            List.of(
                Map.of(
                    "title", "Send HTTPS GET request",
                    "input", Map.of("action", "SEND_REQUEST",
                        "request", "GET / HTTP/1.1\\r\\nHost: example.com:443\\r\\n\\r\\n"),
                    "output", Map.of("status_code", 200, "body", "..."),
                    "explanation", "Use port 443 in Host header for HTTPS"
                ),
                Map.of(
                    "title", "Send HTTPS via URL scheme",
                    "input", Map.of("action", "SEND_REQUEST",
                        "request", "GET https://example.com/api HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n"),
                    "output", Map.of("status_code", 200),
                    "explanation", "Alternative: use https:// in request line"
                ),
                Map.of(
                    "title", "Throttled sweep (default for SEND_PARALLEL)",
                    "input", Map.of("action", "SEND_PARALLEL",
                        "requests", List.of("GET /a HTTP/1.1\\r\\nHost: example.com:443\\r\\n\\r\\n",
                                            "GET /b HTTP/1.1\\r\\nHost: example.com:443\\r\\n\\r\\n"),
                        "max_concurrency", 10),
                    "output", Map.of("responses", "array in input order"),
                    "explanation", "Default max_concurrency=10 prevents tail-of-batch drops on large sweeps. Use this for SSRF/host-header/sitemap sweeps."
                ),
                Map.of(
                    "title", "Race condition test (fire all at once)",
                    "input", Map.of("action", "SEND_PARALLEL",
                        "requests", List.of("POST /transfer HTTP/1.1\\r\\nHost: bank.com:443\\r\\n\\r\\namount=100"),
                        "max_concurrency", 50),
                    "output", Map.of("responses", "array of responses"),
                    "explanation", "Set max_concurrency=50 to opt back into fire-all-at-once behavior. Required for race-condition testing where simultaneity matters."
                ),
                Map.of(
                    "title", "Host-header SSRF (lie in Host, hit real front-end)",
                    "input", Map.of("action", "SEND_REQUEST",
                        "request", "GET /admin HTTP/1.1\\r\\nHost: 192.168.0.1\\r\\n\\r\\n",
                        "target_host", "LAB-ID.web-security-academy.net",
                        "target_port", 443),
                    "output", Map.of("status_code", 200, "body", "admin panel HTML"),
                    "explanation", "TCP socket goes to target_host:target_port; Host header (192.168.0.1) is sent verbatim. Use this for host-header SSRF / virtual-host confusion / cache-poisoning labs."
                ),
                Map.of(
                    "title", "Request smuggling / parser discrepancy (preserve absolute-URI)",
                    "input", Map.of("action", "SEND_REQUEST",
                        "request", "GET https://LAB-ID.web-security-academy.net/admin HTTP/1.1\\r\\nHost: 192.168.0.1\\r\\n\\r\\n",
                        "target_host", "LAB-ID.web-security-academy.net",
                        "target_port", 443,
                        "raw_request", true),
                    "output", Map.of("status_code", 200, "body", "admin panel HTML"),
                    "explanation", "raw_request=true sends bytes verbatim — the absolute-URI request line is preserved on the wire (no rewrite to origin-form), so front-end and back-end can disagree on routing."
                ),
                Map.of(
                    "title", "CL.0 request smuggling (SEND_PIPELINED on one TLS socket)",
                    "input", Map.of("action", "SEND_PIPELINED",
                        "requests", List.of(
                            "POST /vulnerable HTTP/1.1\\r\\nHost: lab.example\\r\\nContent-Type: text/plain\\r\\nContent-Length: 50\\r\\nConnection: keep-alive\\r\\n\\r\\nGET /admin/delete?username=carlos HTTP/1.1\\r\\nFoo: x",
                            "GET / HTTP/1.1\\r\\nHost: lab.example\\r\\nConnection: close\\r\\n\\r\\n"),
                        "target_host", "lab.example",
                        "target_port", 443),
                    "output", Map.of("responses", "[{status_code:200,...},{status_code:302,...}]", "trailing_bytes_length", 0),
                    "explanation", "Two requests on ONE TCP/TLS connection — the back-end interprets the smuggled GET in request 1's body. Required for CL.0/TE.CL/CL.TE/TE.0/0.CL and connection-state attacks; SEND_REQUEST/SEND_PARALLEL open separate sockets and cannot trigger the desync."
                ),
                Map.of(
                    "title", "Visible in HTTP history (default for SEND_REQUEST)",
                    "input", Map.of("action", "SEND_REQUEST",
                        "request", "GET /admin HTTP/1.1\\r\\nHost: example.com:443\\r\\nConnection: close\\r\\n\\r\\n"),
                    "output", Map.of("routed_via_proxy", true, "proxy", "127.0.0.1:8080", "status_code", 200),
                    "explanation", "route_via_proxy defaults to TRUE for SEND_REQUEST: the request CONNECTs through Burp's local proxy listener, so it appears in Proxy → HTTP history alongside browser traffic."
                ),
                Map.of(
                    "title", "Bypass the proxy for byte-exact smuggling tests",
                    "input", Map.of("action", "SEND_REQUEST",
                        "request", "GET https://LAB-ID.web-security-academy.net/admin HTTP/1.1\\r\\nHost: 192.168.0.1\\r\\n\\r\\n",
                        "target_host", "LAB-ID.web-security-academy.net",
                        "target_port", 443,
                        "raw_request", true,
                        "route_via_proxy", false),
                    "output", Map.of("status_code", 200),
                    "explanation", "Setting route_via_proxy=false skips the proxy so Burp's match/replace and proxy parsing don't rewrite the absolute-URI request line. Required for raw_request smuggling tests."
                ),
                Map.of(
                    "title", "SEND_PARALLEL with history visibility (opt-in)",
                    "input", Map.of("action", "SEND_PARALLEL",
                        "requests", List.of("GET /a HTTP/1.1\\r\\nHost: example.com:443\\r\\n\\r\\n",
                                             "GET /b HTTP/1.1\\r\\nHost: example.com:443\\r\\n\\r\\n"),
                        "route_via_proxy", true),
                    "output", Map.of("routed_via_proxy", true, "responses", "[{index:0,...},{index:1,...}]"),
                    "explanation", "SEND_PARALLEL defaults route_via_proxy=false. Opt in when you want each request logged in HTTP history; expect slightly slower throughput (extra CONNECT+TLS per worker) and no proxy-bypass of match/replace rules."
                )
            ),
            List.of(
                "Always use port 443 or https:// for HTTPS - Host header alone uses HTTP",
                "Content-Length is auto-calculated - don't worry about getting it right",
                "Use SEND_PARALLEL for race condition testing, not burp_intruder",
                "Check response status_code to verify request was successful",
                "Use target_host/target_port when Host header must lie (host-header SSRF, routing-based attacks)",
                "Use raw_request=true to preserve absolute-URI request lines verbatim (parser-discrepancy / request-smuggling)",
                "SEND_PARALLEL defaults to max_concurrency=10 (prevents silent tail-of-batch drops); pass 50 for race conditions",
                "Use request_delay_ms to pace dispatch on rate-limited targets",
                "SEND_PARALLEL responses come back in INPUT ORDER; .index field always matches the requests[] position",
                "SEND_PIPELINED writes 2-20 requests on ONE TLS socket — required for ALL request-smuggling labs (CL.0, TE.CL, etc.); SEND_REQUEST/SEND_PARALLEL open separate sockets and cannot trigger desync",
                "SEND_PIPELINED responses include raw_bytes (base64) so callers can inspect malformed/smuggled responses the parser truncated",
                "route_via_proxy makes requests appear in Proxy → HTTP history by tunnelling through Burp's local proxy listener (default 127.0.0.1:8080)",
                "route_via_proxy defaults: TRUE for SEND_REQUEST, FALSE for SEND_PARALLEL/SEND_PIPELINED (proxy may serialise/re-frame and break those workflows)",
                "Turn route_via_proxy OFF when you need byte-exact wire fidelity (raw_request smuggling, host-header lies that match/replace would clobber)",
                "Turn route_via_proxy ON for SEND_PARALLEL when you want each request visible in HTTP history (extra CONNECT+TLS per worker, no rate-limit benefit)",
                "When route_via_proxy=true: http_mode is forced to HTTP/1.1, redirection_mode and connection_id are ignored, match/replace rules apply"
            ));

        // burp_scanner with examples
        addToolEnhancements("burp_scanner",
            List.of("burp_add_issue", "burp_scope", "burp_proxy_history"),
            List.of(
                Map.of(
                    "title", "Start vulnerability scan",
                    "input", Map.of("action", "START_SCAN", "urls", List.of("https://example.com")),
                    "output", Map.of("scanId", "scan_123"),
                    "explanation", "Initiates active scanning on target URLs"
                ),
                Map.of(
                    "title", "Check scan progress",
                    "input", Map.of("action", "GET_STATUS", "scanId", "scan_123"),
                    "output", Map.of("progress", 75, "issues_found", 3),
                    "explanation", "Monitor scan progress and issue count"
                ),
                Map.of(
                    "title", "Get discovered issues",
                    "input", Map.of("action", "GET_ISSUES"),
                    "output", Map.of("issues", "array of vulnerabilities"),
                    "explanation", "Retrieve all vulnerabilities found by scanner"
                ),
                Map.of(
                    "title", "Scan specific parameter (like 'Scan selected insertion point')",
                    "input", Map.of("action", "SCAN_SPECIFIC_REQUEST",
                        "request", "GET /search?q=test HTTP/1.1\\r\\nHost: target.com:443\\r\\n\\r\\n",
                        "useHttps", true,
                        "insertionPointParams", List.of("q")),
                    "output", Map.of("scanId", "scan_456", "insertionPoints", 1),
                    "explanation", "Scans only the 'q' parameter, auto-resolving byte offsets"
                ),
                Map.of(
                    "title", "Scan specific value in request",
                    "input", Map.of("action", "SCAN_SPECIFIC_REQUEST",
                        "request", "GET /api?token=abc123 HTTP/1.1\\r\\nHost: target.com:443\\r\\n\\r\\n",
                        "useHttps", true,
                        "insertionPointValues", List.of("abc123")),
                    "output", Map.of("scanId", "scan_789", "insertionPoints", 1),
                    "explanation", "Finds 'abc123' in the request and scans only that position"
                )
            ),
            List.of(
                "Start with PASSIVE mode before ACTIVE to avoid disruption",
                "Use GET_STATUS to monitor scan progress",
                "Filter issues by severity with FILTER_ISSUES action",
                "Use insertionPointParams to scan specific parameters by name (preferred over manual byte offsets)",
                "Use insertionPointValues to scan specific values found anywhere in the request"
            ));

        // burp_proxy_history with examples
        addToolEnhancements("burp_proxy_history",
            List.of("burp_custom_http", "burp_scope", "burp_response_analyzer"),
            List.of(
                Map.of(
                    "title", "List recent requests",
                    "input", Map.of("action", "list", "limit", 10),
                    "output", Map.of("entries", "array of URLs"),
                    "explanation", "Get list of recent proxy history entries"
                ),
                Map.of(
                    "title", "Filter by hostname",
                    "input", Map.of("action", "list", "hostname", "api.example.com"),
                    "output", Map.of("entries", "filtered results"),
                    "explanation", "Filter history to specific host"
                ),
                Map.of(
                    "title", "Get full request details",
                    "input", Map.of("action", "detail", "entryIds", List.of(1, 5, 10)),
                    "output", Map.of("requests", "full request/response data"),
                    "explanation", "Retrieve complete request and response for specific entries"
                )
            ),
            List.of(
                "Use 'list' action first to find entry IDs, then 'detail' for full content",
                "Filter by hostname or path to reduce results",
                "Use afterTime parameter for recent requests only"
            ));

        // burp_repeater - UI only warning
        addToolEnhancements("burp_repeater",
            List.of("burp_custom_http"),
            List.of(
                Map.of(
                    "title", "⚠️ This tool only creates UI tabs",
                    "input", Map.of("action", "SEND_TO_REPEATER", "url", "https://example.com"),
                    "output", Map.of("message", "Tab created - manual send required"),
                    "explanation", "Creates Repeater tab but does NOT send request. Use burp_custom_http to actually send requests."
                )
            ),
            List.of(
                "⚠️ This tool CANNOT send requests - use burp_custom_http instead",
                "Only use when you need to prepare requests for human manual testing"
            ));

        // burp_intruder - UI only warning
        addToolEnhancements("burp_intruder",
            List.of("burp_custom_http"),
            List.of(
                Map.of(
                    "title", "⚠️ This tool only configures UI",
                    "input", Map.of("action", "SEND_WITH_POSITIONS", "url", "https://example.com",
                        "body", "user=§admin§&pass=§test§"),
                    "output", Map.of("message", "Positions marked - manual attack required"),
                    "explanation", "Configures Intruder but does NOT run attack. Use burp_custom_http with loop for automated fuzzing."
                )
            ),
            List.of(
                "⚠️ This tool CANNOT execute attacks - use burp_custom_http for automated testing",
                "Only use when setting up complex attacks for manual execution in Burp UI"
            ));

        // burp_collaborator with examples
        addToolEnhancements("burp_collaborator",
            List.of("burp_custom_http", "burp_scanner"),
            List.of(
                Map.of(
                    "title", "Generate OOB payload",
                    "input", Map.of("action", "GENERATE_PAYLOAD", "payloadType", "HOSTNAME"),
                    "output", Map.of("payload", "abc123.burpcollaborator.net"),
                    "explanation", "Generate unique payload for out-of-band testing"
                ),
                Map.of(
                    "title", "Check for interactions",
                    "input", Map.of("action", "CHECK_INTERACTIONS"),
                    "output", Map.of("interactions", "array of DNS/HTTP callbacks"),
                    "explanation", "Check if any payloads triggered callbacks"
                )
            ),
            List.of(
                "Generate payloads, inject them via burp_custom_http, then check interactions",
                "Use different payload types (HOSTNAME, HTTP_URL, EMAIL) for different injection points"
            ));

        // burp_sitemap_analysis with examples
        addToolEnhancements("burp_sitemap_analysis",
            List.of("burp_proxy_history", "burp_scanner", "burp_scope"),
            List.of(
                Map.of(
                    "title", "Get response statistics",
                    "input", Map.of("action", "RESPONSE_STATS", "target", "https://example.com"),
                    "output", Map.of("statusCodes", Map.of("200", 45, "302", 12), "topMimeTypes", Map.of("HTML", 30, "JSON", 15)),
                    "explanation", "Returns status code distribution, MIME types, and response size stats for all captured traffic to the target"
                ),
                Map.of(
                    "title", "Map attack surface",
                    "input", Map.of("action", "MAP_ATTACK_SURFACE", "target", "https://example.com"),
                    "output", Map.of("parameterNames", List.of("id", "search"), "contentTypes", List.of("application/json")),
                    "explanation", "Identifies all input points: parameters, content types, HTTP methods, form actions, file uploads, and API endpoints"
                ),
                Map.of(
                    "title", "Detect technology stack",
                    "input", Map.of("action", "DETECT_TECHNOLOGY", "target", "https://example.com"),
                    "output", Map.of("frameworks", List.of("WordPress", "jQuery"), "servers", List.of("nginx")),
                    "explanation", "Fingerprints server software, frameworks, and languages from response headers and content patterns"
                ),
                Map.of(
                    "title", "Full analysis",
                    "input", Map.of("action", "FULL_ANALYSIS", "target", "https://example.com"),
                    "output", Map.of("structure", "...", "technology", "...", "attackSurface", "...", "stats", "..."),
                    "explanation", "Runs all analysis types at once: structure, technology, attack surface, content analysis, and response stats"
                )
            ),
            List.of(
                "Always specify a target URL to filter results to a specific site",
                "Run RESPONSE_STATS first for a quick overview, then drill down with specific actions",
                "Use FULL_ANALYSIS for comprehensive results in a single call",
                "Use includeSubdomains: true to include subdomains in the analysis"
            ));

        // burp_response_analyzer with examples
        addToolEnhancements("burp_response_analyzer",
            List.of("burp_proxy_history", "burp_custom_http", "burp_scanner"),
            List.of(
                Map.of(
                    "title", "Find reflection points for XSS",
                    "input", Map.of("action", "reflection", "hostname", "example.com", "parameter", "search", "value", "test123"),
                    "output", Map.of("reflections", "list of URLs where input is reflected in response"),
                    "explanation", "Identifies where user input appears in responses - essential for XSS testing"
                ),
                Map.of(
                    "title", "Search for security keywords",
                    "input", Map.of("action", "keywords", "hostname", "example.com"),
                    "output", Map.of("keywords", Map.of("password", 3, "token", 7, "admin", 2)),
                    "explanation", "Scans responses for security-relevant keywords like password, token, admin, error, etc."
                ),
                Map.of(
                    "title", "Rank anomalous responses",
                    "input", Map.of("action", "rank_anomalies", "limit", 100, "topN", 10),
                    "output", Map.of("ranked", "top 10 most unusual responses with anomaly scores 0-100"),
                    "explanation", "Uses Burp's RankingUtils to find responses that differ from the norm - great after fuzzing to find interesting results"
                ),
                Map.of(
                    "title", "Regex pattern search",
                    "input", Map.of("action", "pattern", "hostname", "example.com", "pattern", "api[_-]?key[\"']?\\s*[:=]"),
                    "output", Map.of("matches", "list of pattern matches with URLs"),
                    "explanation", "Search response bodies with regex - useful for finding API keys, secrets, or specific patterns"
                )
            ),
            List.of(
                "Use 'rank_anomalies' after fuzzing to quickly find interesting responses",
                "Use 'reflection' before crafting XSS payloads to find where input is reflected",
                "Use 'all' action for a complete analysis combining keywords, variations, reflection, and patterns",
                "Filter by hostname to focus analysis on a specific target"
            ));

        // burp_scope with examples
        addToolEnhancements("burp_scope",
            List.of("burp_proxy_history", "burp_scanner", "burp_sitemap_analysis"),
            List.of(
                Map.of(
                    "title", "Add target to scope",
                    "input", Map.of("action", "add", "url", "https://example.com"),
                    "output", Map.of("success", true, "message", "URL added to scope"),
                    "explanation", "Adds a URL to Burp's target scope. All paths under this URL are included."
                ),
                Map.of(
                    "title", "Check if URL is in scope",
                    "input", Map.of("action", "check", "url", "https://example.com/api/users"),
                    "output", Map.of("inScope", true),
                    "explanation", "Verify whether a specific URL falls within the defined scope"
                ),
                Map.of(
                    "title", "View current scope",
                    "input", Map.of("action", "view"),
                    "output", Map.of("includeRules", "list of included URLs", "excludeRules", "list of excluded URLs"),
                    "explanation", "Shows all include and exclude rules with scope coverage statistics"
                )
            ),
            List.of(
                "Set scope before scanning to limit testing to authorized targets",
                "Use 'analyze' action to see what percentage of proxy traffic is in scope",
                "Use bulk_add with a list of URLs for multiple targets",
                "includeSubdomains=true (default) matches the domain and all subdomains — the UI 'Include subdomains' checkbox"
            ));

        // burp_config - project/user options as JSON
        addToolEnhancements("burp_config",
            List.of("burp_scope", "burp_session_management", "burp_global_interceptor"),
            List.of(
                Map.of(
                    "title", "Export a settings subtree",
                    "input", Map.of("action", "GET_PROJECT_OPTIONS", "path", "target.scope"),
                    "output", Map.of("json", "{\"target\":{\"scope\":{\"advanced_mode\":true,\"include\":[...]}}}", "length", 330),
                    "explanation", "Pass 'path' (e.g. target.scope, proxy, project_options.connections) to export just that subtree. Omit path to export EVERYTHING (large)."
                ),
                Map.of(
                    "title", "Include-subdomains scope via round-trip",
                    "input", Map.of("action", "SET_PROJECT_OPTIONS",
                        "json", "{\"target\":{\"scope\":{\"advanced_mode\":true,\"include\":[{\"enabled\":true,\"protocol\":\"any\",\"host\":\"^(?:.*\\\\.)?example\\\\.com$\"}]}}}"),
                    "output", Map.of("success", true, "importedTopLevelKeys", List.of("target")),
                    "explanation", "GET target.scope first, append the host-regex rule to include[], then SET — importing an array REPLACES it, so preserve existing rules. (burp_scope add includeSubdomains=true does this for you.)"
                ),
                Map.of(
                    "title", "Reset target scope to default (empty)",
                    "input", Map.of("action", "RESET_PROJECT_OPTIONS", "path", "target.scope"),
                    "output", Map.of("success", true, "reset", "target.scope"),
                    "explanation", "Restores a known-default for supported paths (currently target.scope → advanced_mode:false, empty include/exclude)."
                ),
                Map.of(
                    "title", "Read user options (⚠️ may contain cleartext secrets)",
                    "input", Map.of("action", "GET_USER_OPTIONS", "path", "user_options.connections"),
                    "output", Map.of("json", "{\"user_options\":{\"connections\":{\"platform_authentication\":{...}}}}"),
                    "explanation", "USER paths must be rooted at 'user_options.' — a bare 'connections' falls through to the FULL dump. User options include stored platform-auth credentials / proxy passwords in cleartext; don't paste full dumps into untrusted places."
                ),
                Map.of(
                    "title", "Dump the full config for troubleshooting",
                    "input", Map.of("action", "GET_PROJECT_OPTIONS"),
                    "output", Map.of("json", "{...every project setting at its current value, incl. defaults...}"),
                    "explanation", "Omit 'path' to get the complete current config (not just modified settings). Do the same with GET_USER_OPTIONS for user-level settings. Large output — use for troubleshooting/backup."
                ),
                Map.of(
                    "title", "Add a proxy match/replace rule (Tools/Proxy)",
                    "input", Map.of("action", "SET_PROJECT_OPTIONS",
                        "json", "{\"proxy\":{...GET 'proxy' first..., \"match_replace_rules\":[<existing rules>, {\"category\":\"regex\",\"comment\":\"my rule\",\"enabled\":true,\"rule_type\":\"request_header\",\"string_match\":\"^User-Agent.*$\",\"string_replace\":\"User-Agent: x\"}]}}"),
                    "output", Map.of("success", true, "importedTopLevelKeys", List.of("proxy")),
                    "explanation", "Proxy config lives at ROOT 'proxy' (not project_options.proxy). GET 'proxy', append to match_replace_rules[], SET the whole subtree back. ⚠️ Preserve request_listeners exactly or you can disrupt the proxy listener you're testing through."
                )
            ),
            List.of(
                "Always GET the subtree, modify it, then SET the whole modified subtree back (SET replaces arrays) — capture the original first so you can restore it",
                "Changes apply live — no extension reload needed",
                "Common paths: target.scope; proxy (listeners/intercept/match-replace); project_options.connections (network/upstream/platform-auth); project_options.sessions (session rules/macros/cookie jar); project_options.ssl (TLS/client certs); user_options.* (global)",
                "Omit 'path' for a full config dump (troubleshooting/backup); scope with a correctly-rooted 'path' otherwise",
                "PROJECT roots: target, proxy, project_options; USER root: user_options — a wrong path falls through to the full dump (which can include cleartext secrets)",
                "When SETting 'proxy', preserve request_listeners exactly — altering it can restart the proxy you're testing through",
                "For simple scope add/remove/check use burp_scope; use burp_config for advanced/bulk config",
                "Use RESET_PROJECT_OPTIONS path=target.scope to clear scope back to default"
            ));

        // burp_session_management with examples
        addToolEnhancements("burp_session_management",
            List.of("burp_custom_http", "burp_proxy_history", "burp_scope"),
            List.of(
                Map.of(
                    "title", "List all cookies",
                    "input", Map.of("action", "COOKIE_JAR_LIST"),
                    "output", Map.of("cookies", "list of domain/name/value entries"),
                    "explanation", "Shows all cookies in Burp's cookie jar, grouped by domain"
                ),
                Map.of(
                    "title", "Set a cookie",
                    "input", Map.of("action", "COOKIE_JAR_SET", "domain", "example.com", "tokenName", "session", "tokenValue", "abc123"),
                    "output", Map.of("success", true),
                    "explanation", "Adds or updates a cookie in Burp's jar - subsequent burp_custom_http requests will use it"
                ),
                Map.of(
                    "title", "Extract session tokens",
                    "input", Map.of("action", "EXTRACT_TOKENS", "hostname", "example.com"),
                    "output", Map.of("tokens", List.of("JSESSIONID=abc", "csrf_token=xyz")),
                    "explanation", "Finds session tokens from proxy history and cookie jar for a target"
                ),
                Map.of(
                    "title", "Enable auto-session refresh",
                    "input", Map.of("action", "ENABLE_AUTO_SESSION", "hostname", "example.com", "loginUrl", "https://example.com/login"),
                    "output", Map.of("enabled", true),
                    "explanation", "Automatically re-authenticates when a 401/403 response is detected"
                )
            ),
            List.of(
                "Use COOKIE_JAR_LIST to see what cookies burp_custom_http will send",
                "Use EXTRACT_TOKENS to find session cookies before testing access control",
                "Enable AUTO_SESSION for long-running scans that need to stay authenticated"
            ));

        // burp_global_interceptor with examples
        addToolEnhancements("burp_global_interceptor",
            List.of("burp_proxy_interceptor", "burp_custom_http", "burp_scanner"),
            List.of(
                Map.of(
                    "title", "Step 1 — Enable (rules apply automatically, no queue, no blocking)",
                    "input", Map.of("action", "enable"),
                    "output", Map.of("enabled", true, "requestRules", 0),
                    "explanation", "Turns on inline transform-and-forward for traffic from ALL tools + the Playwright browser. Unlike burp_proxy_interceptor it never holds traffic, so normal browser_click/navigate works."
                ),
                Map.of(
                    "title", "Inject a bearer token across ALL traffic (set_auth)",
                    "input", Map.of("action", "set_auth", "auth_type", "bearer", "auth_value", "eyJ..."),
                    "output", Map.of("success", true, "authHeader", "Authorization"),
                    "explanation", "auth_type: bearer|basic|api_key|custom. bearer/basic build the Authorization header; api_key/custom take an optional header_name. Applies to browser + Scanner + Repeater + custom_http-via-proxy."
                ),
                Map.of(
                    "title", "Match/replace in the request BODY (verified — solves price tampering)",
                    "input", Map.of("action", "add_request_rule", "rule_id", "lower_price",
                        "rule", Map.of("url_pattern", "/cart", "body_search", "price=133700", "body_replace", "price=1")),
                    "output", Map.of("type", "request", "success", true, "ruleId", "lower_price"),
                    "explanation", "rule keys: url_pattern (substring; regex if use_regex on the rule), body_search/body_replace, add_headers {name:value}, remove_headers [names], change_method, change_path. Then a normal browser add-to-cart is rewritten inline."
                ),
                Map.of(
                    "title", "Add a static header to all tools (add_header)",
                    "input", Map.of("action", "add_header", "header_name", "X-Forwarded-For", "header_value", "127.0.0.1"),
                    "output", Map.of("success", true),
                    "explanation", "Simpler than a rule for a fixed header (e.g. WAF-bypass headers). Inspect/clean up with list_rules, list_headers, remove_rule, remove_header."
                )
            ),
            List.of(
                "VERIFIED: a /cart body match/replace rule rewrote quantity/price inline during a normal Playwright click — no queue, no deadlock.",
                "Enable first, then add rules (set_auth/add_header/add_request_rule); they apply automatically to all subsequent traffic.",
                "Set rules BEFORE driving the Playwright browser (proxied through Burp) so navigated pages are transformed transparently.",
                "Use set_tool_filter to scope which tools a rule applies to; use this to add auth to Scanner — it cannot authenticate on its own.",
                "Prefer this over burp_proxy_interceptor for inject/rewrite jobs; use the proxy interceptor only when you need a true per-request breakpoint."
            ));

        // burp_annotate with examples
        addToolEnhancements("burp_annotate",
            List.of("burp_proxy_history", "burp_organizer"),
            List.of(
                Map.of(
                    "title", "Annotate a proxy entry",
                    "input", Map.of("action", "ANNOTATE_PROXY", "url", "https://example.com/api/users?id=1",
                        "notes", "Possible IDOR - test with different user IDs", "highlightColor", "RED"),
                    "output", Map.of("success", true),
                    "explanation", "Adds a note and red highlight to the matching proxy history entry"
                ),
                Map.of(
                    "title", "Bulk annotate by pattern",
                    "input", Map.of("action", "ANNOTATE_BY_PATTERN", "pattern", "/api/admin",
                        "notes", "Admin endpoint", "color", "ORANGE"),
                    "output", Map.of("annotated", 5),
                    "explanation", "Highlights all entries matching a URL pattern"
                ),
                Map.of(
                    "title", "Search by annotation",
                    "input", Map.of("action", "SEARCH_BY_ANNOTATION", "searchQuery", "IDOR"),
                    "output", Map.of("entries", "list of annotated entries matching query"),
                    "explanation", "Find previously annotated entries by note content"
                )
            ),
            List.of(
                "Use RED for high-severity findings, ORANGE for medium, YELLOW for low",
                "Add notes during testing to track what you've already checked",
                "Use ANNOTATE_BY_PATTERN to bulk-mark admin or API endpoints"
            ));

        // burp_bambda with examples
        addToolEnhancements("burp_bambda",
            List.of("burp_proxy_history", "burp_sitemap_analysis"),
            List.of(
                Map.of(
                    "title", "Apply preset filter",
                    "input", Map.of("action", "APPLY_FILTER", "preset", "error_responses"),
                    "output", Map.of("success", true, "filtered", "proxy history filtered to 4xx/5xx responses"),
                    "explanation", "Applies a built-in filter to show only error responses in proxy history"
                ),
                Map.of(
                    "title", "List available presets",
                    "input", Map.of("action", "LIST_PRESETS"),
                    "output", Map.of("presets", List.of("authenticated_requests", "api_endpoints", "error_responses", "sql_injection_candidates", "xss_candidates")),
                    "explanation", "Shows all built-in filter presets"
                ),
                Map.of(
                    "title", "Create custom Java filter",
                    "input", Map.of("action", "CREATE_CUSTOM",
                        "script", "return requestResponse.request().url().contains(\"/api/\") && requestResponse.hasResponse() && requestResponse.response().statusCode() == 200;",
                        "location", "PROXY_HTTP_HISTORY"),
                    "output", Map.of("success", true),
                    "explanation", "Write a Java Bambda expression to create complex custom filters"
                )
            ),
            List.of(
                "Use LIST_PRESETS first to see available built-in filters",
                "Custom Bambdas use Java syntax with access to the requestResponse object",
                "Supported locations: PROXY_HTTP_HISTORY, PROXY_WS_HISTORY, SITEMAP, LOGGER"
            ));

        // burp_comparer with examples
        addToolEnhancements("burp_comparer",
            List.of("burp_proxy_history", "burp_custom_http"),
            List.of(
                Map.of(
                    "title", "Compare two proxy entries",
                    "input", Map.of("action", "COMPARE_PROXY_ENTRIES", "entryId1", 1, "entryId2", 5),
                    "output", Map.of("differences", "list of diffs between the two responses"),
                    "explanation", "Compares two proxy history entries to find differences - useful for access control testing"
                ),
                Map.of(
                    "title", "Compare two responses",
                    "input", Map.of("action", "COMPARE_RESPONSES", "response1", "HTTP/1.1 200 OK...", "response2", "HTTP/1.1 200 OK..."),
                    "output", Map.of("differences", "word-level diff output"),
                    "explanation", "Compare arbitrary response strings to find subtle differences"
                ),
                Map.of(
                    "title", "Compare text strings",
                    "input", Map.of("action", "COMPARE_TEXT", "text1", "admin=true", "text2", "admin=false"),
                    "output", Map.of("differences", "character-level diff"),
                    "explanation", "General-purpose text comparison"
                )
            ),
            List.of(
                "Compare responses as admin vs regular user to find authorization issues",
                "Use COMPARE_PROXY_ENTRIES with entry IDs from burp_proxy_history",
                "Set ignoreWhitespace: true for cleaner diffs"
            ));

        // burp_utilities with examples
        addToolEnhancements("burp_utilities",
            List.of("burp_custom_http"),
            List.of(
                Map.of(
                    "title", "Base64 encode a payload",
                    "input", Map.of("action", "base64_encode", "input", "<script>alert(1)</script>"),
                    "output", Map.of("output", "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="),
                    "explanation", "Encode payload for injection in base64-encoded parameters"
                ),
                Map.of(
                    "title", "URL encode",
                    "input", Map.of("action", "url_encode", "input", "admin' OR 1=1--"),
                    "output", Map.of("output", "admin%27+OR+1%3D1--"),
                    "explanation", "URL-encode special characters for parameter injection"
                ),
                Map.of(
                    "title", "Generate hash",
                    "input", Map.of("action", "hash", "input", "password123", "algorithm", "SHA256"),
                    "output", Map.of("output", "ef92b778..."),
                    "explanation", "Generate MD5, SHA1, SHA256, SHA384, or SHA512 hash"
                ),
                Map.of(
                    "title", "Execute shell command",
                    "input", Map.of("action", "shell_execute", "commandArgs", List.of("nmap", "-sV", "example.com")),
                    "output", Map.of("output", "command output", "mode", "safe"),
                    "explanation", "Run external tools from Burp's context. shell_execute REQUIRES commandArgs[] (argv, no shell). Disabled by default — set BURP_MCP_SHELL_ENABLED=true to enable. Use shell_execute_dangerous with 'command' when you need shell features."
                )
            ),
            List.of(
                "Use encoding tools to craft payloads for burp_custom_http",
                "Shell execution is OFF by default (BURP_MCP_SHELL_ENABLED=true to enable). shell_execute requires commandArgs[] (safe argv); shell_execute_dangerous takes a shell-interpreted 'command' string (pipes/redirects; injection risk)",
                "json_path supports read/add/update/remove operations on JSON data"
            ));

        // burp_organizer with examples
        addToolEnhancements("burp_organizer",
            List.of("burp_proxy_history", "burp_annotate"),
            List.of(
                Map.of(
                    "title", "Send request to organizer",
                    "input", Map.of("action", "SEND_TO_ORGANIZER",
                        "request", "GET /admin HTTP/1.1\r\nHost: example.com:443\r\n\r\n"),
                    "output", Map.of("success", true, "itemId", 1),
                    "explanation", "Bookmark an interesting request for later review"
                ),
                Map.of(
                    "title", "List organized items",
                    "input", Map.of("action", "LIST_ITEMS"),
                    "output", Map.of("items", "list of organized requests with status"),
                    "explanation", "View all bookmarked requests with their testing status"
                ),
                Map.of(
                    "title", "Update item status",
                    "input", Map.of("action", "GET_ITEM_STATUS", "itemId", 1),
                    "output", Map.of("status", "NEW"),
                    "explanation", "Check the status of an organized item (NEW, IN_PROGRESS, POSTPONED, DONE, IGNORED)"
                )
            ),
            List.of(
                "Use SEND_TO_ORGANIZER to bookmark requests that need further testing",
                "Track testing progress with status types: NEW, IN_PROGRESS, POSTPONED, DONE, IGNORED"
            ));

        // burp_logs with examples
        addToolEnhancements("burp_logs",
            List.of(),
            List.of(
                Map.of(
                    "title", "Get extension logs",
                    "input", Map.of("action", "GET_LOGS", "type", "output", "limit", 50),
                    "output", Map.of("logs", "array of recent log entries"),
                    "explanation", "Retrieve output or error logs from the extension"
                ),
                Map.of(
                    "title", "Write a log entry",
                    "input", Map.of("action", "WRITE_LOG", "message", "Starting scan of admin panel", "level", "info"),
                    "output", Map.of("success", true),
                    "explanation", "Add a custom log entry for tracking test progress"
                )
            ),
            List.of(
                "Check error logs (type: 'error') when a tool call fails unexpectedly",
                "Use WRITE_LOG to create an audit trail of testing activities"
            ));

        // burp_websocket with examples
        addToolEnhancements("burp_websocket",
            List.of("burp_websocket_interceptor", "burp_proxy_history"),
            List.of(
                Map.of(
                    "title", "View WebSocket history",
                    "input", Map.of("action", "proxy_history"),
                    "output", Map.of("messages", "list of captured WebSocket messages"),
                    "explanation", "View all WebSocket messages captured by Burp's proxy"
                ),
                Map.of(
                    "title", "Create WebSocket connection",
                    "input", Map.of("action", "create", "url", "wss://example.com/ws"),
                    "output", Map.of("connectionId", "ws_1"),
                    "explanation", "Open a new WebSocket connection through Burp for testing"
                ),
                Map.of(
                    "title", "Send WebSocket message",
                    "input", Map.of("action", "send", "connectionId", "ws_1", "message", "{\"type\":\"ping\"}"),
                    "output", Map.of("success", true),
                    "explanation", "Send a text message on an open WebSocket connection"
                )
            ),
            List.of(
                "Use proxy_history to review captured WebSocket traffic before crafting payloads",
                "Create connections through Burp to have traffic visible in proxy history",
                "Close connections when done to avoid resource leaks"
            ));

        // burp_websocket_interceptor with examples
        addToolEnhancements("burp_websocket_interceptor",
            List.of("burp_websocket", "burp_proxy_interceptor"),
            List.of(
                Map.of(
                    "title", "Enable WebSocket interception",
                    "input", Map.of("action", "enable"),
                    "output", Map.of("enabled", true),
                    "explanation", "Start intercepting WebSocket messages for inspection and modification"
                ),
                Map.of(
                    "title", "Add auto-modify rule",
                    "input", Map.of("action", "add_auto_modify", "match", "user_role", "replace", "admin"),
                    "output", Map.of("ruleId", "rule_1"),
                    "explanation", "Automatically replace text in WebSocket messages - useful for privilege escalation testing"
                ),
                Map.of(
                    "title", "Get intercepted message queue",
                    "input", Map.of("action", "get_queue"),
                    "output", Map.of("messages", "list of pending WebSocket messages"),
                    "explanation", "View messages waiting for forward/drop/modify decision"
                )
            ),
            List.of(
                "Enable interception, then use get_queue to see pending messages",
                "Use add_auto_modify for match/replace rules that apply automatically",
                "Supports both text and binary WebSocket messages"
            ));

        // burp_proxy_interceptor with examples
        addToolEnhancements("burp_proxy_interceptor",
            List.of("burp_global_interceptor", "burp_custom_http"),
            List.of(
                Map.of(
                    "title", "Step 1 — Enable with a SCOPED hold filter (so the page stays usable)",
                    "input", Map.of("action", "enable", "filter_path", "/cart", "filter_method", "POST"),
                    "output", Map.of("enabled", true, "holdFilter", "method=POST url~/cart"),
                    "explanation", "Only POST requests whose URL contains /cart are held; all other requests (images, JS, navigation) pass through. Without a filter, EVERY request is held."
                ),
                Map.of(
                    "title", "Step 2 — Trigger the request NON-BLOCKING (critical — avoids deadlock)",
                    "input", Map.of("note", "this is a Playwright call, not a burp tool",
                        "tool", "mcp__playwright__browser_evaluate",
                        "function", "() => { fetch('/cart', {method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:'productId=1&redir=PRODUCT&quantity=1&price=133700'}); return 'dispatched'; }"),
                    "output", Map.of("result", "dispatched"),
                    "explanation", "Fire-and-forget (un-awaited) fetch returns immediately so the agent stays free to poll. A blocking browser_click/browser_navigate would deadlock — the caller waits on the held request and can never reach get_queue."
                ),
                Map.of(
                    "title", "Step 3 — Read the held request",
                    "input", Map.of("action", "get_queue"),
                    "output", Map.of("queueSize", 1, "queue", List.of(Map.of("requestId", "dabadf02-...", "method", "POST", "url", ".../cart"))),
                    "explanation", "Returns held requests and their request_id (needed to modify/forward). Each is auto-forwarded unmodified after 30s, so act promptly."
                ),
                Map.of(
                    "title", "Step 4 — Modify the body and forward",
                    "input", Map.of("action", "modify_request", "request_id", "dabadf02-...",
                        "modifications", Map.of("replace_body", "productId=1&redir=PRODUCT&quantity=1&price=1")),
                    "output", Map.of("success", true),
                    "explanation", "modify_request applies the change AND forwards in one call. modifications keys: replace_body, add_headers {name:value}, remove_headers [names], method, path. (Use forward_request to send unmodified, drop_request to drop.)"
                ),
                Map.of(
                    "title", "Step 5 — Disable when done",
                    "input", Map.of("action", "disable"),
                    "output", Map.of("enabled", false),
                    "explanation", "Always disable afterwards (also clears the filter), otherwise the next held request will hang the browser."
                )
            ),
            List.of(
                "VERIFIED end-to-end: this 5-step pattern solved the PortSwigger 'Excessive trust in client-side controls' lab (rewrote price=133700 -> price=1).",
                "ALWAYS scope the hold with filter_path/filter_method/filter_host on enable — an unfiltered enable holds every request and hangs the browser.",
                "ALWAYS trigger held traffic non-blocking (un-awaited fetch via browser_evaluate, or a background curl through 127.0.0.1:8080). Never trigger it with a blocking browser_click/navigate.",
                "For AUTOMATIC match/replace with no queue/blocking, use burp_global_interceptor instead — better for inject-auth/rewrite-everything jobs."
            ));

        // burp_add_issue with examples
        addToolEnhancements("burp_add_issue",
            List.of("burp_scanner", "burp_proxy_history"),
            List.of(
                Map.of(
                    "title", "Create SQL injection issue",
                    "input", Map.of("url", "https://example.com/search",
                        "issueType", "SQL injection",
                        "severity", "HIGH",
                        "confidence", "CERTAIN",
                        "detail", "The search parameter is vulnerable to SQL injection. Payload: ' OR 1=1--"),
                    "output", Map.of("success", true),
                    "explanation", "Creates a custom issue with full details"
                )
            ),
            List.of(
                "Include request/response evidence when possible",
                "Use issueType for automatic grouping with similar issues",
                "Add remediation guidance to help fix the vulnerability"
            ));
    }
}
