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
                "inspect requests", "query history"),
            Map.of("detail", List.of("entryIds"))),
        descriptor("burp_repeater", "Core HTTP/Proxy", RepeaterTool::new,
            List.of("manual", "test", "ui", "tab", "workspace"),
            List.of("send to repeater", "manual testing", "create repeater tab"),
            Map.of(
                "SEND_TO_REPEATER", List.of("url"),
                "SEND_FROM_PROXY", List.of("proxyUrl"))),
        descriptor("burp_proxy_interceptor", "Core HTTP/Proxy", ProxyInterceptorTool::new,
            List.of("intercept", "modify", "block", "tamper", "real-time", "proxy"),
            List.of("intercept requests", "modify in real-time", "block requests", "tamper traffic",
                "real-time modification", "request filtering"),
            Map.ofEntries(
                Map.entry("modify_request", List.of("request_id")),
                Map.entry("forward_request", List.of("request_id")),
                Map.entry("drop_request", List.of("request_id")),
                Map.entry("modify_response", List.of("response_id|request_id", "modifications")),
                Map.entry("forward_response", List.of("response_id|request_id")),
                Map.entry("drop_response", List.of("response_id|request_id")))),
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
                "brute force setup"),
            Map.of(
                "SEND_TO_INTRUDER", List.of("url"),
                "SEND_WITH_POSITIONS", List.of("url"))),
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
                "scope configuration"),
            Map.of(
                "add", List.of("url"),
                "remove", List.of("url"),
                "check", List.of("url"),
                "bulk_add", List.of("urls"),
                "bulk_check", List.of("urls"))),
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
                "SEND_TO_ORGANIZER", List.of("url"),
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
                "traffic filtering"),
            Map.of(
                "APPLY_FILTER", List.of("preset|customScript"),
                "CREATE_CUSTOM", List.of("customScript"))),
        descriptor("burp_global_interceptor", "Core HTTP/Proxy", GlobalInterceptorTool::new,
            List.of("intercept", "global", "modify", "header", "auth", "inject", "rule", "scanner", "all-tools"),
            List.of("intercept all tools", "add authentication", "inject headers globally",
                "modify scanner requests", "global request modification"),
            Map.ofEntries(
                Map.entry("set_auth", List.of("auth_type", "auth_value")),
                Map.entry("add_header", List.of("header_name", "header_value")),
                Map.entry("remove_header", List.of("header_name")),
                Map.entry("add_request_rule", List.of("rule_id", "rule")),
                Map.entry("add_response_rule", List.of("rule_id", "rule")),
                Map.entry("remove_rule", List.of("rule_id")),
                Map.entry("add_websocket_rule", List.of("rule_id", "rule")),
                Map.entry("remove_websocket_rule", List.of("rule_id")),
                Map.entry("set_mode", List.of("mode")),
                Map.entry("set_tool_filter", List.of("tools")),
                Map.entry("set_rate_limit", List.of("delay")),
                Map.entry("import_rules", List.of("rules_data")))),
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
                "TOGGLE_REQUEST_METHOD", List.of("request|url"),
                "ANALYZE_PROTOCOL", List.of("request|url"))),
        descriptor("burp_logs", "Documentation & Logging", LogsTool::new,
            List.of("logs", "debug", "errors", "output", "diagnostics", "events"),
            List.of("view logs", "debug extension", "check errors", "diagnostic information"),
            Map.of(
                "WRITE_LOG", List.of("message|object|exceptionMessage"),
                "RAISE_EVENT", List.of("message"))),
        descriptor("burp_websocket", "WebSocket Support", WebSocketTool::new,
            List.of("websocket", "ws", "wss", "real-time", "bidirectional"),
            List.of("view websocket traffic", "create websocket connections", "send websocket messages",
                "websocket history"),
            Map.of(
                "create", List.of("url"),
                "send", List.of("connectionId", "message"),
                "close", List.of("connectionId"))),
        descriptor("burp_websocket_interceptor", "WebSocket Support", WebSocketInterceptorTool::new,
            List.of("websocket", "intercept", "modify", "ws", "binary", "text"),
            List.of("intercept websockets", "modify websocket messages", "websocket interception",
                "binary message handling"),
            Map.ofEntries(
                Map.entry("forward", List.of("message_id")),
                Map.entry("drop", List.of("message_id")),
                Map.entry("modify", List.of("message_id", "new_payload")),
                Map.entry("add_filter", List.of("filter_name", "filter_pattern")),
                Map.entry("remove_filter", List.of("filter_name")),
                Map.entry("add_auto_modify", List.of("rule_name", "search_pattern")),
                Map.entry("remove_auto_modify", List.of("rule_name")))),
        descriptor("burp_response_analyzer", "Response Analysis", ResponseAnalysisTool::new,
            List.of("response", "analyze", "keywords", "variations", "reflection", "xss", "anomaly", "pattern"),
            List.of("analyze responses", "detect variations", "find reflections", "keyword search",
                "response patterns", "anomaly detection"),
            Map.of("pattern", List.of("pattern"))),
        descriptor("burp_utilities", "Utilities", UtilitiesTool::new,
            List.of("encode", "decode", "base64", "url", "hash", "md5", "sha", "compress", "json",
                "shell", "execute", "command", "process"),
            List.of("encode data", "decode base64", "URL encoding", "hash generation",
                "JSON operations", "compression", "hex conversion", "shell execution",
                "run commands", "execute processes"),
            Map.ofEntries(
                Map.entry("base64_encode", List.of("input")),
                Map.entry("base64_decode", List.of("input")),
                Map.entry("url_encode", List.of("input")),
                Map.entry("url_decode", List.of("input")),
                Map.entry("html_encode", List.of("input")),
                Map.entry("html_decode", List.of("input")),
                Map.entry("hash", List.of("input")),
                Map.entry("compress", List.of("input")),
                Map.entry("decompress", List.of("input")),
                Map.entry("json_beautify", List.of("input")),
                Map.entry("json_path", List.of("input", "jsonPath")),
                Map.entry("json_validate", List.of("input")),
                Map.entry("hex_to_ascii", List.of("input")),
                Map.entry("ascii_to_hex", List.of("input")),
                Map.entry("number_convert", List.of("input")),
                Map.entry("byte_search", List.of("input", "searchPattern")),
                Map.entry("shell_execute", List.of("commandArgs")),
                Map.entry("shell_execute_dangerous", List.of("command"))))
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
