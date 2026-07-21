package com.example.burpmcp;

import burp.api.montoya.MontoyaApi;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Ordered source of truth for tool construction and help metadata.
 */
public final class ToolRegistry {
    private static final List<ToolDescriptor> DESCRIPTORS = List.of(
        descriptor("burp_help", "Documentation & Discovery", BurpHelpTool::new,
            List.of("help", "documentation", "discover", "search"),
            List.of("discover tools", "search capabilities", "read tool documentation"),
            false),
        descriptor("burp_proxy_history", "Core HTTP/Proxy", ProxyHistoryTool::new,
            List.of("history", "traffic", "filter", "search", "proxy", "log", "requests"),
            List.of("view proxy traffic", "search requests", "filter by host", "analyze traffic",
                "inspect requests", "query history")),
        descriptor("burp_repeater", "Core HTTP/Proxy", RepeaterTool::new,
            List.of("manual", "test", "ui", "tab", "workspace"),
            List.of("send to repeater", "manual testing", "create repeater tab"),
            Map.of(
                "SEND_TO_REPEATER", List.of("url"),
                "SEND_FROM_PROXY", List.of("proxyUrl"))),
        descriptor("burp_proxy_interceptor", "Core HTTP/Proxy", ProxyInterceptorTool::new,
            List.of("intercept", "modify", "block", "tamper", "real-time", "proxy"),
            List.of("intercept requests", "modify in real-time", "block requests", "tamper traffic",
                "real-time modification", "request filtering")),
        descriptor("burp_scanner", "Scanning & Analysis", ScannerTool::new,
            List.of("scan", "vulnerability", "active", "passive", "audit", "inject", "xss", "sqli", "security"),
            List.of("scan for vulnerabilities", "detect security issues", "audit endpoints", "find SQL injection",
                "discover XSS", "security testing", "automated scanning", "vulnerability assessment"),
            Map.of(
                "START_SCAN", List.of("urls"),
                "CRAWL_ONLY", List.of("urls"),
                "GET_STATUS", List.of("scanId"),
                "GET_ISSUES", List.of("scanId"),
                "CANCEL_SCAN", List.of("scanId"),
                "ADD_TO_SCAN", List.of("scanId"),
                "GENERATE_REPORT", List.of("scanId"),
                "IMPORT_BCHECK", List.of("definition"),
                "SCAN_SPECIFIC_REQUEST", List.of("request", "useHttps"))),
        descriptor("burp_intruder", "Scanning & Analysis", IntruderTool::new,
            List.of("fuzz", "brute", "payload", "attack", "parameter", "wordlist"),
            List.of("configure fuzzing", "setup attacks", "parameter fuzzing", "payload positions",
                "brute force setup")),
        descriptor("burp_add_issue", "Issue Management", AddIssueTool::new,
            List.of("issue", "finding", "vulnerability", "report", "create", "custom"),
            List.of("create issues", "add findings", "custom vulnerabilities", "report issues",
                "issue grouping")),
        descriptor("burp_session_management", "Session Management", SessionManagementTool::new,
            List.of("session", "cookie", "token", "jwt", "auth", "login", "credential", "csrf"),
            List.of("manage cookies", "extract tokens", "session handling", "JWT analysis",
                "cookie jar operations", "automatic session handling"),
            Map.of(
                "SET_TOKEN", List.of("tokenName", "tokenValue"),
                "TEST_SESSION", List.of("url"),
                "COOKIE_JAR_SET", List.of("tokenName", "tokenValue", "domain"),
                "COOKIE_JAR_DELETE", List.of("tokenName", "domain"),
                "ANALYZE_SESSION_VALIDITY", List.of("url"))),
        descriptor("burp_comparer", "Analysis & Comparison", ComparerTool::new,
            List.of("compare", "diff", "difference", "analyze", "side-by-side"),
            List.of("compare responses", "find differences", "diff requests", "side-by-side comparison"),
            Map.of(
                "COMPARE_RESPONSES", List.of("url1", "url2"),
                "COMPARE_REQUESTS", List.of("url1", "url2"),
                "COMPARE_TEXT", List.of("text1", "text2"),
                "COMPARE_PROXY_ENTRIES", List.of("url1", "url2"))),
        descriptor("burp_collaborator", "Analysis & Comparison", CollaboratorTool::new,
            List.of("oob", "out-of-band", "dns", "http", "payload", "external", "callback"),
            List.of("generate payloads", "monitor out-of-band", "DNS interactions", "HTTP callbacks",
                "external interaction detection"),
            Map.of("RESTORE_CLIENT", List.of("secretKey"))),
        descriptor("burp_scope", "Configuration & Utilities", ScopeTool::new,
            List.of("scope", "target", "filter", "include", "exclude", "url", "domain"),
            List.of("manage scope", "add to scope", "check scope", "filter targets",
                "scope configuration")),
        descriptor("burp_config", "Configuration & Utilities", ConfigTool::new,
            List.of("config", "settings", "options", "project", "user", "import", "export", "json",
                "scope", "proxy", "upstream", "session-handling", "macro", "credentials", "reset"),
            List.of("read burp settings", "write burp settings", "export project options",
                "import project options", "export user options", "configure advanced scope",
                "configure upstream proxy", "configure platform auth", "reset scope"),
            Map.of(
                "SET_PROJECT_OPTIONS", List.of("json"),
                "SET_USER_OPTIONS", List.of("json"),
                "RESET_PROJECT_OPTIONS", List.of("path"))),
        descriptor("burp_organizer", "Configuration & Utilities", OrganizerTool::new,
            List.of("organize", "manage", "track", "status", "workflow"),
            List.of("organize requests", "track progress", "manage workflow", "status tracking"),
            Map.of(
                "GET_ITEM_BY_ID", List.of("itemId"),
                "GET_ITEM_STATUS", List.of("itemId"))),
        descriptor("burp_annotate", "Configuration & Utilities", AnnotateTool::new,
            List.of("annotate", "note", "comment", "highlight", "color", "organize"),
            List.of("add annotations", "highlight entries", "add notes", "color code",
                "organize findings"),
            Map.of(
                "ANNOTATE_PROXY", List.of("entryId|url"),
                "ANNOTATE_TARGET", List.of("entryId|url"),
                "ANNOTATE_ORGANIZER", List.of("url"),
                "ANNOTATE_REPEATER", List.of("url"),
                "ANNOTATE_INTRUDER", List.of("url"),
                "ANNOTATE_BY_PATTERN", List.of("pattern"))),
        descriptor("burp_sitemap_analysis", "Site Map Analysis", SiteMapAnalysisTool::new,
            List.of("sitemap", "structure", "technology", "fingerprint", "attack-surface", "endpoints"),
            List.of("analyze site structure", "detect technology stack", "map attack surface",
                "technology fingerprinting", "endpoint discovery")),
        descriptor("burp_bambda", "Advanced Filtering", BambdaTool::new,
            List.of("filter", "bambda", "query", "search", "advanced", "java", "scripting"),
            List.of("apply filters", "bambda scripting", "advanced filtering", "custom queries",
                "traffic filtering")),
        descriptor("burp_global_interceptor", "Core HTTP/Proxy", GlobalInterceptorTool::new,
            List.of("intercept", "global", "modify", "header", "auth", "inject", "rule", "scanner", "all-tools"),
            List.of("intercept all tools", "add authentication", "inject headers globally",
                "modify scanner requests", "global request modification")),
        descriptor("burp_custom_http", "Core HTTP/Proxy", CustomHttpTool::new,
            List.of("http", "request", "send", "post", "get", "parallel", "race", "http2", "redirect",
                "smuggling", "host-header", "ssrf", "raw", "target_host"),
            List.of("send HTTP requests", "test race conditions", "modify requests", "HTTP/2 support",
                "parallel requests", "custom headers", "SNI configuration", "host-header SSRF",
                "request smuggling", "parser discrepancy", "decouple TCP destination from Host header",
                "send raw verbatim bytes"),
            Map.of(
                "SEND_REQUEST", List.of("request"),
                "SEND_PARALLEL", List.of("requests"),
                "SEND_PIPELINED", List.of("requests"),
                "TOGGLE_REQUEST_METHOD", List.of("request|url"))),
        descriptor("burp_logs", "Documentation & Logging", LogsTool::new,
            List.of("logs", "debug", "errors", "output", "diagnostics", "events"),
            List.of("view logs", "debug extension", "check errors", "diagnostic information")),
        descriptor("burp_websocket", "WebSocket Support", WebSocketTool::new,
            List.of("websocket", "ws", "wss", "real-time", "bidirectional"),
            List.of("view websocket traffic", "create websocket connections", "send websocket messages",
                "websocket history")),
        descriptor("burp_websocket_interceptor", "WebSocket Support", WebSocketInterceptorTool::new,
            List.of("websocket", "intercept", "modify", "ws", "binary", "text"),
            List.of("intercept websockets", "modify websocket messages", "websocket interception",
                "binary message handling")),
        descriptor("burp_response_analyzer", "Response Analysis", ResponseAnalysisTool::new,
            List.of("response", "analyze", "keywords", "variations", "reflection", "xss", "anomaly", "pattern"),
            List.of("analyze responses", "detect variations", "find reflections", "keyword search",
                "response patterns", "anomaly detection")),
        descriptor("burp_utilities", "Utilities", UtilitiesTool::new,
            List.of("encode", "decode", "base64", "url", "hash", "md5", "sha", "compress", "json",
                "shell", "execute", "command", "process"),
            List.of("encode data", "decode base64", "URL encoding", "hash generation",
                "JSON operations", "compression", "hex conversion", "shell execution",
                "run commands", "execute processes"))
    );

    private static final Map<String, ToolDescriptor> BY_NAME = buildIndex();

    private ToolRegistry() {
    }

    public static List<ToolDescriptor> descriptors() {
        return new ArrayList<>(DESCRIPTORS);
    }

    public static List<ToolDescriptor> documentationDescriptors() {
        List<ToolDescriptor> descriptors = new ArrayList<>();
        for (ToolDescriptor descriptor : DESCRIPTORS) {
            if (descriptor.isIncludedInHelpDocs()) {
                descriptors.add(descriptor);
            }
        }
        return descriptors;
    }

    public static ToolDescriptor get(String name) {
        return BY_NAME.get(name);
    }

    public static McpTool createTool(String name, MontoyaApi api) {
        ToolDescriptor descriptor = get(name);
        return descriptor == null ? null : descriptor.create(api);
    }

    public static Map<String, McpTool> createTools(MontoyaApi api) {
        Map<String, McpTool> tools = new LinkedHashMap<>();
        for (ToolDescriptor descriptor : DESCRIPTORS) {
            tools.put(descriptor.getName(), descriptor.create(api));
        }
        return tools;
    }

    public static int toolCount() {
        return DESCRIPTORS.size();
    }

    private static Map<String, ToolDescriptor> buildIndex() {
        Map<String, ToolDescriptor> index = new LinkedHashMap<>();
        for (ToolDescriptor descriptor : DESCRIPTORS) {
            if (index.put(descriptor.getName(), descriptor) != null) {
                throw new IllegalStateException("Duplicate tool registration: " + descriptor.getName());
            }
        }
        return index;
    }

    private static ToolDescriptor descriptor(String name,
                                             String category,
                                             ToolDescriptor.Factory factory,
                                             List<String> keywords,
                                             List<String> capabilities) {
        return descriptor(name, category, factory, keywords, capabilities, Map.of(), true);
    }

    private static ToolDescriptor descriptor(String name,
                                             String category,
                                             ToolDescriptor.Factory factory,
                                             List<String> keywords,
                                             List<String> capabilities,
                                             Map<String, List<String>> actionRequirements) {
        return descriptor(name, category, factory, keywords, capabilities, actionRequirements, true);
    }

    private static ToolDescriptor descriptor(String name,
                                             String category,
                                             ToolDescriptor.Factory factory,
                                             List<String> keywords,
                                             List<String> capabilities,
                                             boolean includeInHelpDocs) {
        return descriptor(name, category, factory, keywords, capabilities, Map.of(), includeInHelpDocs);
    }

    private static ToolDescriptor descriptor(String name,
                                             String category,
                                             ToolDescriptor.Factory factory,
                                             List<String> keywords,
                                             List<String> capabilities,
                                             Map<String, List<String>> actionRequirements,
                                             boolean includeInHelpDocs) {
        return new ToolDescriptor(name, category, factory, keywords, capabilities, actionRequirements, includeInHelpDocs);
    }
}
