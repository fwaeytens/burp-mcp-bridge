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
