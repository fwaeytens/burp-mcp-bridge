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
        this.documentation = new HashMap<>();
        this.categories = new HashMap<>();
        // Documentation is now fully dynamic via syncWithToolSchemas()
        // But we populate curated metadata (keywords/capabilities/examples) here
        populateCuratedMetadata();
        // Then enhance with examples, related tools, and best practices
        populateEnhancedMetadata();
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
        return new HashMap<>(categories);
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

    /**
     * Populate curated metadata (keywords, capabilities, examples) for tools
     * This fixes the search functionality in burp_help
     */
    private void populateCuratedMetadata() {
        // burp_scanner
        addToolMetadata("burp_scanner", "Scanning & Analysis",
            List.of("scan", "vulnerability", "active", "passive", "audit", "inject", "xss", "sqli", "security"),
            List.of("scan for vulnerabilities", "detect security issues", "audit endpoints", "find SQL injection",
                    "discover XSS", "security testing", "automated scanning", "vulnerability assessment"));

        // burp_custom_http
        addToolMetadata("burp_custom_http", "Core HTTP/Proxy",
            List.of("http", "request", "send", "post", "get", "parallel", "race", "http2", "redirect"),
            List.of("send HTTP requests", "test race conditions", "modify requests", "HTTP/2 support",
                    "parallel requests", "custom headers", "SNI configuration"));

        // burp_proxy_history
        addToolMetadata("burp_proxy_history", "Core HTTP/Proxy",
            List.of("history", "traffic", "filter", "search", "proxy", "log", "requests"),
            List.of("view proxy traffic", "search requests", "filter by host", "analyze traffic",
                    "inspect requests", "query history"));

        // burp_proxy_interceptor
        addToolMetadata("burp_proxy_interceptor", "Core HTTP/Proxy",
            List.of("intercept", "modify", "block", "tamper", "real-time", "proxy"),
            List.of("intercept requests", "modify in real-time", "block requests", "tamper traffic",
                    "real-time modification", "request filtering"));

        // burp_global_interceptor
        addToolMetadata("burp_global_interceptor", "Core HTTP/Proxy",
            List.of("global", "intercept", "all-tools", "auth", "header", "inject"),
            List.of("intercept all tools", "add authentication", "inject headers globally",
                    "modify scanner requests", "global request modification"));

        // burp_intruder
        addToolMetadata("burp_intruder", "Scanning & Analysis",
            List.of("fuzz", "brute", "payload", "attack", "parameter", "wordlist"),
            List.of("configure fuzzing", "setup attacks", "parameter fuzzing", "payload positions",
                    "brute force setup"));

        // burp_repeater
        addToolMetadata("burp_repeater", "Core HTTP/Proxy",
            List.of("manual", "test", "ui", "tab", "workspace"),
            List.of("send to repeater", "manual testing", "create repeater tab"));

        // burp_collaborator
        addToolMetadata("burp_collaborator", "Analysis & Comparison",
            List.of("oob", "out-of-band", "dns", "http", "payload", "external", "callback"),
            List.of("generate payloads", "monitor out-of-band", "DNS interactions", "HTTP callbacks",
                    "external interaction detection"));

        // burp_websocket
        addToolMetadata("burp_websocket", "WebSocket Support",
            List.of("websocket", "ws", "wss", "real-time", "bidirectional"),
            List.of("view websocket traffic", "create websocket connections", "send websocket messages",
                    "websocket history"));

        // burp_websocket_interceptor
        addToolMetadata("burp_websocket_interceptor", "WebSocket Support",
            List.of("websocket", "intercept", "modify", "ws", "binary", "text"),
            List.of("intercept websockets", "modify websocket messages", "websocket interception",
                    "binary message handling"));

        // burp_session_management
        addToolMetadata("burp_session_management", "Session Management",
            List.of("cookie", "session", "auth", "token", "jwt", "csrf"),
            List.of("manage cookies", "extract tokens", "session handling", "JWT analysis",
                    "cookie jar operations", "automatic session handling"));

        // burp_scope
        addToolMetadata("burp_scope", "Configuration & Utilities",
            List.of("scope", "target", "include", "exclude", "filter", "domain"),
            List.of("manage scope", "add to scope", "check scope", "filter targets",
                    "scope configuration"));

        // burp_add_issue
        addToolMetadata("burp_add_issue", "Issue Management",
            List.of("issue", "finding", "vulnerability", "report", "create", "custom"),
            List.of("create issues", "add findings", "custom vulnerabilities", "report issues",
                    "issue grouping"));

        // burp_response_analyzer
        addToolMetadata("burp_response_analyzer", "Response Analysis",
            List.of("analyze", "response", "keywords", "variations", "reflection", "xss", "pattern"),
            List.of("analyze responses", "detect variations", "find reflections", "keyword search",
                    "response patterns", "anomaly detection"));

        // burp_utilities
        addToolMetadata("burp_utilities", "Utilities",
            List.of("encode", "decode", "base64", "url", "hash", "md5", "sha", "compress", "json",
                    "shell", "execute", "command", "process"),
            List.of("encode data", "decode base64", "URL encoding", "hash generation",
                    "JSON operations", "compression", "hex conversion",
                    "shell execution", "run commands", "execute processes"));

        // burp_bambda
        addToolMetadata("burp_bambda", "Advanced Filtering",
            List.of("filter", "bambda", "query", "search", "advanced", "java", "scripting"),
            List.of("apply filters", "bambda scripting", "advanced filtering", "custom queries",
                    "traffic filtering"));

        // burp_sitemap_analysis
        addToolMetadata("burp_sitemap_analysis", "Site Map Analysis",
            List.of("sitemap", "structure", "technology", "fingerprint", "attack-surface", "endpoints"),
            List.of("analyze site structure", "detect technology stack", "map attack surface",
                    "technology fingerprinting", "endpoint discovery"));

        // burp_annotate
        addToolMetadata("burp_annotate", "Configuration & Utilities",
            List.of("annotate", "note", "comment", "highlight", "color", "organize"),
            List.of("add annotations", "highlight entries", "add notes", "color code",
                    "organize findings"));

        // burp_organizer
        addToolMetadata("burp_organizer", "Configuration & Utilities",
            List.of("organize", "manage", "track", "status", "workflow"),
            List.of("organize requests", "track progress", "manage workflow", "status tracking"));

        // burp_comparer
        addToolMetadata("burp_comparer", "Analysis & Comparison",
            List.of("compare", "diff", "difference", "analyze", "side-by-side"),
            List.of("compare responses", "find differences", "diff requests", "side-by-side comparison"));

        // burp_logs
        addToolMetadata("burp_logs", "Documentation & Logging",
            List.of("logs", "debug", "errors", "output", "diagnostics", "events"),
            List.of("view logs", "debug extension", "check errors", "diagnostic information"));
    }

    private void addToolMetadata(String toolName, String category, List<String> keywords, List<String> capabilities) {
        addToolMetadata(toolName, category, keywords, capabilities, List.of(), List.of(), List.of());
    }

    private void addToolMetadata(String toolName, String category, List<String> keywords, List<String> capabilities,
                                  List<String> relatedTools, List<Map<String, Object>> examples, List<String> bestPractices) {
        ToolDocumentation doc = documentation.get(toolName);
        if (doc == null) {
            // Create new documentation entry
            doc = new ToolDocumentation.Builder(toolName)
                .category(category)
                .description("") // Will be populated by syncWithToolSchemas
                .build();
            documentation.put(toolName, doc);
        }

        // Rebuild with all metadata
        ToolDocumentation.Builder builder = new ToolDocumentation.Builder(toolName)
            .category(category)
            .description(doc.getDescription());

        // Add keywords and capabilities
        for (String keyword : keywords) {
            builder.addKeyword(keyword);
        }
        for (String capability : capabilities) {
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

        documentation.put(toolName, builder.build());
    }

    /**
     * Populate curated metadata with examples, related tools, and best practices
     */
    private void populateEnhancedMetadata() {
        // burp_custom_http - PRIMARY HTTP tool with examples
        addToolMetadata("burp_custom_http", "Core HTTP/Proxy",
            List.of("http", "request", "send", "post", "get", "parallel", "race", "http2", "redirect"),
            List.of("send HTTP requests", "test race conditions", "modify requests", "HTTP/2 support",
                    "parallel requests", "custom headers", "SNI configuration"),
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
                    "title", "Race condition test",
                    "input", Map.of("action", "SEND_PARALLEL",
                        "requests", List.of("POST /transfer HTTP/1.1\\r\\nHost: bank.com:443\\r\\n\\r\\namount=100")),
                    "output", Map.of("responses", "array of responses"),
                    "explanation", "Send multiple requests simultaneously for race condition testing"
                )
            ),
            List.of(
                "Always use port 443 or https:// for HTTPS - Host header alone uses HTTP",
                "Content-Length is auto-calculated - don't worry about getting it right",
                "Use SEND_PARALLEL for race condition testing, not burp_intruder",
                "Check response status_code to verify request was successful"
            ));

        // burp_scanner with examples
        addToolMetadata("burp_scanner", "Scanning & Analysis",
            List.of("scan", "vulnerability", "active", "passive", "audit", "inject", "xss", "sqli", "security"),
            List.of("scan for vulnerabilities", "detect security issues", "audit endpoints", "find SQL injection",
                    "discover XSS", "security testing", "automated scanning", "vulnerability assessment"),
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
                )
            ),
            List.of(
                "Start with PASSIVE mode before ACTIVE to avoid disruption",
                "Use GET_STATUS to monitor scan progress",
                "Filter issues by severity with FILTER_ISSUES action"
            ));

        // burp_proxy_history with examples
        addToolMetadata("burp_proxy_history", "Core HTTP/Proxy",
            List.of("history", "traffic", "filter", "search", "proxy", "log", "requests"),
            List.of("view proxy traffic", "search requests", "filter by host", "analyze traffic",
                    "inspect requests", "query history"),
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
        addToolMetadata("burp_repeater", "Core HTTP/Proxy",
            List.of("manual", "test", "ui", "tab", "workspace"),
            List.of("send to repeater", "manual testing", "create repeater tab"),
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
        addToolMetadata("burp_intruder", "Scanning & Analysis",
            List.of("fuzz", "brute", "payload", "attack", "parameter", "wordlist"),
            List.of("configure fuzzing", "setup attacks", "parameter fuzzing", "payload positions",
                    "brute force setup"),
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
        addToolMetadata("burp_collaborator", "Analysis & Comparison",
            List.of("oob", "out-of-band", "dns", "http", "payload", "external", "callback"),
            List.of("generate payloads", "monitor out-of-band", "DNS interactions", "HTTP callbacks",
                    "external interaction detection"),
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
        addToolMetadata("burp_sitemap_analysis", "Site Map Analysis",
            List.of("sitemap", "structure", "technology", "fingerprint", "attack-surface", "endpoints"),
            List.of("analyze site structure", "detect technology stack", "map attack surface",
                    "technology fingerprinting", "endpoint discovery"),
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
        addToolMetadata("burp_response_analyzer", "Response Analysis",
            List.of("response", "analyze", "keywords", "variations", "reflection", "xss", "anomaly", "pattern"),
            List.of("analyze responses", "detect variations", "find reflections", "keyword search",
                    "response patterns", "anomaly detection"),
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
        addToolMetadata("burp_scope", "Configuration & Utilities",
            List.of("scope", "target", "filter", "include", "exclude", "url"),
            List.of("manage scope", "add to scope", "check scope", "filter targets", "scope configuration"),
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
                "Use bulk_add with a list of URLs for multiple targets"
            ));

        // burp_session_management with examples
        addToolMetadata("burp_session_management", "Session Management",
            List.of("session", "cookie", "token", "jwt", "auth", "login", "credential"),
            List.of("manage cookies", "extract tokens", "session handling", "JWT analysis",
                    "cookie jar operations", "automatic session handling"),
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
        addToolMetadata("burp_global_interceptor", "Core HTTP/Proxy",
            List.of("intercept", "global", "modify", "header", "auth", "inject", "rule", "scanner", "all-tools"),
            List.of("intercept all tools", "add authentication", "inject headers globally",
                    "modify scanner requests", "global request modification"),
            List.of("burp_proxy_interceptor", "burp_custom_http", "burp_scanner"),
            List.of(
                Map.of(
                    "title", "Add auth header to all tools",
                    "input", Map.of("action", "add_request_rule", "rule_id", "auth_rule",
                        "rule", Map.of("name", "Add Bearer Token",
                            "add_headers", Map.of("Authorization", "Bearer eyJ..."))),
                    "output", Map.of("success", true),
                    "explanation", "Injects Authorization header into ALL Burp tools (Scanner, Intruder, Repeater, etc.)"
                ),
                Map.of(
                    "title", "Enable automatic mode",
                    "input", Map.of("action", "set_mode", "mode", Map.of("type", "AUTOMATIC")),
                    "output", Map.of("intercepting", true),
                    "explanation", "Rules are applied automatically to all requests without manual intervention"
                ),
                Map.of(
                    "title", "List active rules",
                    "input", Map.of("action", "list_rules"),
                    "output", Map.of("rules", "array of active interception rules"),
                    "explanation", "Shows all configured request/response modification rules"
                )
            ),
            List.of(
                "Use this to add authentication to Scanner - it cannot authenticate on its own",
                "Use set_mode with type AUTOMATIC for hands-off header injection",
                "Add WAF bypass headers (X-Forwarded-For, X-Original-URL) globally for all tools"
            ));

        // burp_annotate with examples
        addToolMetadata("burp_annotate", "Configuration & Utilities",
            List.of("annotate", "note", "comment", "highlight", "color", "organize"),
            List.of("add annotations", "highlight entries", "add notes", "color code",
                    "organize findings"),
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
        addToolMetadata("burp_bambda", "Advanced Filtering",
            List.of("filter", "bambda", "query", "search", "advanced", "java", "scripting"),
            List.of("apply filters", "bambda scripting", "advanced filtering", "custom queries",
                    "traffic filtering"),
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
        addToolMetadata("burp_comparer", "Analysis & Comparison",
            List.of("compare", "diff", "difference", "analyze", "side-by-side"),
            List.of("compare responses", "find differences", "diff requests", "side-by-side comparison"),
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
        addToolMetadata("burp_utilities", "Utilities",
            List.of("encode", "decode", "base64", "url", "hash", "md5", "sha", "compress", "json",
                    "shell", "execute", "command", "process"),
            List.of("encode data", "decode base64", "URL encoding", "hash generation",
                    "JSON operations", "compression", "hex conversion",
                    "shell execution", "run commands", "execute processes"),
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
                    "input", Map.of("action", "shell_execute", "command", List.of("nmap", "-sV", "example.com")),
                    "output", Map.of("stdout", "command output", "exitCode", 0),
                    "explanation", "Run external tools from within Burp's context. Use shell_execute_dangerous for string commands."
                )
            ),
            List.of(
                "Use encoding tools to craft payloads for burp_custom_http",
                "shell_execute takes a command array (safe); shell_execute_dangerous takes a string (splits on whitespace)",
                "json_path supports read/add/update/remove operations on JSON data"
            ));

        // burp_organizer with examples
        addToolMetadata("burp_organizer", "Configuration & Utilities",
            List.of("organize", "manage", "track", "status", "workflow"),
            List.of("organize requests", "track progress", "manage workflow", "status tracking"),
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
        addToolMetadata("burp_logs", "Documentation & Logging",
            List.of("logs", "debug", "errors", "output", "diagnostics", "events"),
            List.of("view logs", "debug extension", "check errors", "diagnostic information"),
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
        addToolMetadata("burp_websocket", "WebSocket Support",
            List.of("websocket", "ws", "wss", "real-time", "bidirectional"),
            List.of("view websocket traffic", "create websocket connections", "send websocket messages",
                    "websocket history"),
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
        addToolMetadata("burp_websocket_interceptor", "WebSocket Support",
            List.of("websocket", "intercept", "modify", "ws", "binary", "text"),
            List.of("intercept websockets", "modify websocket messages", "websocket interception",
                    "binary message handling"),
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
        addToolMetadata("burp_proxy_interceptor", "Core HTTP/Proxy",
            List.of("intercept", "modify", "block", "tamper", "real-time", "proxy"),
            List.of("intercept requests", "modify in real-time", "block requests", "tamper traffic",
                    "real-time modification", "request filtering"),
            List.of("burp_global_interceptor", "burp_custom_http"),
            List.of(
                Map.of(
                    "title", "Enable request interception",
                    "input", Map.of("action", "enable"),
                    "output", Map.of("enabled", true),
                    "explanation", "Start intercepting proxy requests for MCP-based inspection and modification"
                ),
                Map.of(
                    "title", "Get pending requests",
                    "input", Map.of("action", "get_queue"),
                    "output", Map.of("requests", "list of intercepted requests awaiting decision"),
                    "explanation", "View requests held by the interceptor, waiting for forward/drop/modify"
                ),
                Map.of(
                    "title", "Modify and forward a request",
                    "input", Map.of("action", "modify_request", "request_id", "req_1",
                        "modifications", Map.of("add_headers", Map.of("X-Custom", "injected"), "replace_body", "modified=true")),
                    "output", Map.of("success", true),
                    "explanation", "Modify an intercepted request before forwarding it to the server"
                )
            ),
            List.of(
                "Enable interception, browse in Burp's browser, then use get_queue to see requests",
                "Use modify_request to change headers or body before forwarding",
                "For global interception across all tools (Scanner, etc.), use burp_global_interceptor instead"
            ));

        // burp_add_issue with examples
        addToolMetadata("burp_add_issue", "Issue Management",
            List.of("issue", "finding", "vulnerability", "report", "create", "custom"),
            List.of("create issues", "add findings", "custom vulnerabilities", "report issues",
                    "issue grouping"),
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
