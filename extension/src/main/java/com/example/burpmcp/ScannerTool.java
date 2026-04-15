package com.example.burpmcp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.Scanner;
import burp.api.montoya.scanner.Crawl;
import burp.api.montoya.scanner.CrawlConfiguration;
import burp.api.montoya.scanner.audit.Audit;
import burp.api.montoya.scanner.AuditConfiguration;
import burp.api.montoya.scanner.BuiltInAuditConfiguration;
import burp.api.montoya.scanner.ReportFormat;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.bchecks.BCheckImportResult;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.core.Range;
import com.fasterxml.jackson.databind.JsonNode;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

public class ScannerTool implements McpTool {
    private final MontoyaApi api;
    private static final List<String> SUPPORTED_ACTIONS = List.of(
        "START_SCAN",
        "CRAWL_ONLY",
        "GET_STATUS",
        "GET_ISSUES",
        "CANCEL_SCAN",
        "LIST_SCANS",
        "ADD_TO_SCAN",
        "GENERATE_REPORT",
        "IMPORT_BCHECK",
        "CLEAR_ISSUES",
        "SCAN_SPECIFIC_REQUEST",
        "SCAN_METRICS",
        "FILTER_ISSUES"
    );
    
    // Track active scan tasks
    private static final Map<String, Audit> activeAudits = new ConcurrentHashMap<>();
    private static final Map<String, Crawl> activeCrawls = new ConcurrentHashMap<>();
    private static final Map<String, ScanMetadata> scanMetadata = new ConcurrentHashMap<>();

    // Inner class to track scan metadata
    private static class ScanMetadata {
        String id;
        String type; // "AUDIT" or "CRAWL"
        String mode; // "ACTIVE" or "PASSIVE"
        String config;
        LocalDateTime startTime;
        List<String> urls;
        
        ScanMetadata(String id, String type, String mode, String config, List<String> urls) {
            this.id = id;
            this.type = type;
            this.mode = mode;
            this.config = config;
            this.startTime = LocalDateTime.now();
            this.urls = urls;
        }
    }

    public ScannerTool(MontoyaApi api) {
        this.api = api;
    }

    @Override
    public Map<String, Object> getToolInfo() {
        Map<String, Object> tool = new HashMap<>();
        tool.put("name", "burp_scanner");
        tool.put("title", "Vulnerability Scanner");
        tool.put("description", "Comprehensive vulnerability scanner and crawler with full automation. " +
            "Use this to scan targets for security vulnerabilities, discover content via crawling, and retrieve scan results. " +
            "Actions: START_SCAN (scan with optional crawl), CRAWL_ONLY (content discovery), GET_STATUS (check progress), " +
            "GET_ISSUES (retrieve vulnerabilities), CANCEL_SCAN, LIST_SCANS, ADD_TO_SCAN, GENERATE_REPORT, " +
            "IMPORT_BCHECK (custom checks), CLEAR_ISSUES, SCAN_SPECIFIC_REQUEST, SCAN_METRICS, FILTER_ISSUES. " +
            "Supports authenticated scanning via headers/cookies parameters. " +
            "For targeted scanning use insertionPointParams (by parameter name) or insertionPointValues (by value string) " +
            "to scan only specific insertion points, like Burp UI's 'Scan selected insertion point'." +
            " START_SCAN with crawl:false only scans the provided URLs without traversal — set crawl:true to spider+scan. By default uses authenticated session from proxy history (useProxySession:true).");

        // MCP 2025-06-18 annotations
        Map<String, Object> annotations = new HashMap<>();
        annotations.put("readOnlyHint", false);
        annotations.put("destructiveHint", false);
        annotations.put("idempotentHint", false);
        annotations.put("openWorldHint", true);
        annotations.put("title", "Vulnerability Scanner");
        tool.put("annotations", annotations);

        Map<String, Object> meta = new HashMap<>();
        meta.put("anthropic/searchHint", "scan vulnerabilities active passive crawl audit");
        tool.put("_meta", meta);

        Map<String, Object> inputSchema = new HashMap<>();
        inputSchema.put("type", "object");

        Map<String, Object> properties = new HashMap<>();
        
        // Action property
        Map<String, Object> actionProperty = new HashMap<>();
        actionProperty.put("type", "string");
        actionProperty.put("description", "Scanner action. START_SCAN: scan URLs from scratch (urls[]). SCAN_SPECIFIC_REQUEST: scan one raw request (use insertionPointParams/Values for targeted scanning). ADD_TO_SCAN: add to existing scan (scanId). CRAWL_ONLY: discover URLs without scanning. GET_STATUS/GET_ISSUES/CANCEL_SCAN/LIST_SCANS: track active scans. FILTER_ISSUES/SCAN_METRICS/CLEAR_ISSUES: manage results. GENERATE_REPORT: HTML/XML export. IMPORT_BCHECK: load custom check definition.");
        actionProperty.put("enum", SUPPORTED_ACTIONS);
        properties.put("action", actionProperty);
        
        // URLs for START_SCAN
        Map<String, Object> urlsProperty = new HashMap<>();
        urlsProperty.put("type", "array");
        urlsProperty.put("description", "URLs to scan (for START_SCAN)");
        Map<String, Object> urlItems = new HashMap<>();
        urlItems.put("type", "string");
        urlsProperty.put("items", urlItems);
        properties.put("urls", urlsProperty);
        
        // Scan ID for operations
        Map<String, Object> scanIdProperty = new HashMap<>();
        scanIdProperty.put("type", "string");
        scanIdProperty.put("description", "Scan ID for status/cancel/add operations");
        properties.put("scanId", scanIdProperty);
        
        // Mode property
        Map<String, Object> modeProperty = new HashMap<>();
        modeProperty.put("type", "string");
        modeProperty.put("description", "Scan mode: ACTIVE or PASSIVE");
        modeProperty.put("default", "ACTIVE");
        modeProperty.put("enum", new String[]{"ACTIVE", "PASSIVE"});
        properties.put("mode", modeProperty);
        
        // Config property
        Map<String, Object> configProperty = new HashMap<>();
        configProperty.put("type", "string");
        configProperty.put("description", "Scan configuration: LIGHT, MEDIUM, or THOROUGH");
        configProperty.put("default", "MEDIUM");
        configProperty.put("enum", new String[]{"LIGHT", "MEDIUM", "THOROUGH"});
        properties.put("config", configProperty);
        
        // Crawl property
        Map<String, Object> crawlProperty = new HashMap<>();
        crawlProperty.put("type", "boolean");
        crawlProperty.put("description", "Also perform crawling");
        crawlProperty.put("default", false);
        properties.put("crawl", crawlProperty);
        
        // Request for ADD_TO_SCAN
        Map<String, Object> requestProperty = new HashMap<>();
        requestProperty.put("type", "string");
        requestProperty.put("description", "HTTP request to add to scan. IMPORTANT: include port in Host header (example.com:443 for HTTPS, example.com:80 for HTTP) — without explicit port, parsing falls back to defaults that may not match useHttps.");
        properties.put("request", requestProperty);
        
        // Insertion points for ADD_TO_SCAN
        Map<String, Object> insertionPointsProperty = new HashMap<>();
        insertionPointsProperty.put("type", "array");
        insertionPointsProperty.put("description", "Insertion point ranges [{start: int, end: int}]");
        properties.put("insertionPoints", insertionPointsProperty);

        // Friendly insertion point helpers - auto-calculate byte offsets
        Map<String, Object> insertionPointValuesProperty = new HashMap<>();
        insertionPointValuesProperty.put("type", "array");
        insertionPointValuesProperty.put("items", Map.of("type", "string"));
        insertionPointValuesProperty.put("description",
            "Values to scan in the request - auto-finds byte offsets. " +
            "E.g. [\"admin\", \"secret\"] finds those strings in the request and creates insertion points for them.");
        properties.put("insertionPointValues", insertionPointValuesProperty);

        Map<String, Object> insertionPointParamsProperty = new HashMap<>();
        insertionPointParamsProperty.put("type", "array");
        insertionPointParamsProperty.put("items", Map.of("type", "string"));
        insertionPointParamsProperty.put("description",
            "Parameter names to scan - auto-finds their values and creates insertion points. " +
            "Works with URL query params (name=value), form body params, and JSON values (\"name\": \"value\"). " +
            "E.g. [\"username\", \"password\"] finds the values of those parameters.");
        properties.put("insertionPointParams", insertionPointParamsProperty);
        
        // Report format
        Map<String, Object> formatProperty = new HashMap<>();
        formatProperty.put("type", "string");
        formatProperty.put("description", "Report format: HTML or XML");
        formatProperty.put("enum", new String[]{"HTML", "XML"});
        formatProperty.put("default", "HTML");
        properties.put("format", formatProperty);
        
        // Output path
        Map<String, Object> outputPathProperty = new HashMap<>();
        outputPathProperty.put("type", "string");
        outputPathProperty.put("description", "Path to save report");
        properties.put("outputPath", outputPathProperty);

        Map<String, Object> verboseProperty = new HashMap<>();
        verboseProperty.put("type", "boolean");
        verboseProperty.put("default", false);
        verboseProperty.put("description", "Return decorated markdown (for human debugging). Default returns compact JSON.");
        properties.put("verbose", verboseProperty);
        
        // BCheck definition
        Map<String, Object> bcheckProperty = new HashMap<>();
        bcheckProperty.put("type", "string");
        bcheckProperty.put("description", "BCheck definition YAML");
        properties.put("definition", bcheckProperty);
        
        // Auto-enable for BCheck
        Map<String, Object> autoEnableProperty = new HashMap<>();
        autoEnableProperty.put("type", "boolean");
        autoEnableProperty.put("description", "Auto-enable imported BCheck");
        
        // Properties for SCAN_SPECIFIC_REQUEST and ADD_TO_SCAN (raw request)
        Map<String, Object> hostProperty = new HashMap<>();
        hostProperty.put("type", "string");
        hostProperty.put("description", "Target host (for SCAN_SPECIFIC_REQUEST, or ADD_TO_SCAN with raw request). If omitted, parsed from Host header.");
        properties.put("host", hostProperty);

        Map<String, Object> portProperty = new HashMap<>();
        portProperty.put("type", "integer");
        portProperty.put("description", "Target port. If omitted, parsed from Host header (default: 443 for HTTPS, 80 for HTTP)");
        properties.put("port", portProperty);

        Map<String, Object> useHttpsProperty = new HashMap<>();
        useHttpsProperty.put("type", "boolean");
        useHttpsProperty.put("description", "Required for SCAN_SPECIFIC_REQUEST and ADD_TO_SCAN actions. true=HTTPS:443, false=HTTP:80 (port can be overridden via 'port' parameter or Host header). If omitted, parsing falls back to URL/Host header — explicit is safer.");
        properties.put("useHttps", useHttpsProperty);
        autoEnableProperty.put("default", true);
        properties.put("autoEnable", autoEnableProperty);

        // Parameters for FILTER_ISSUES
        Map<String, Object> severityProperty = new HashMap<>();
        severityProperty.put("type", "string");
        severityProperty.put("description", "Filter by severity (for FILTER_ISSUES/GET_ISSUES)");
        severityProperty.put("enum", new String[]{"HIGH", "MEDIUM", "LOW", "INFORMATION", "FALSE_POSITIVE"});
        properties.put("severity", severityProperty);

        Map<String, Object> urlFilterProperty = new HashMap<>();
        urlFilterProperty.put("type", "string");
        urlFilterProperty.put("description", "URL pattern filter with wildcards (for FILTER_ISSUES/GET_ISSUES)");
        properties.put("urlFilter", urlFilterProperty);

        // Pagination parameters for GET_ISSUES/FILTER_ISSUES
        Map<String, Object> limitProperty = new HashMap<>();
        limitProperty.put("type", "integer");
        limitProperty.put("description", "Max issues to return in summary mode (default: 50)");
        limitProperty.put("default", 50);
        properties.put("limit", limitProperty);

        Map<String, Object> offsetProperty = new HashMap<>();
        offsetProperty.put("type", "integer");
        offsetProperty.put("description", "Number of issues to skip in summary mode (default: 0)");
        offsetProperty.put("default", 0);
        properties.put("offset", offsetProperty);

        Map<String, Object> issueIndexProperty = new HashMap<>();
        issueIndexProperty.put("type", "array");
        issueIndexProperty.put("description", "1-based issue indices for detail mode (e.g., [1, 3, 5]). Omit for summary mode.");
        issueIndexProperty.put("items", Map.of("type", "integer"));
        properties.put("issueIndex", issueIndexProperty);

        // Parameters for headers and cookies (START_SCAN, CRAWL_ONLY)
        Map<String, Object> headersProperty = new HashMap<>();
        headersProperty.put("type", "object");
        headersProperty.put("description", "Additional HTTP headers to include (e.g., {\"Cookie\": \"session=abc123\", \"Authorization\": \"Bearer token\"})");
        properties.put("headers", headersProperty);

        Map<String, Object> cookiesProperty = new HashMap<>();
        cookiesProperty.put("type", "object");
        cookiesProperty.put("description", "Cookies to include as key-value pairs (e.g., {\"sessionid\": \"abc123\", \"token\": \"xyz\"})");
        properties.put("cookies", cookiesProperty);

        Map<String, Object> useProxySessionProperty = new HashMap<>();
        useProxySessionProperty.put("type", "boolean");
        useProxySessionProperty.put("description", "Automatically use authenticated session from proxy history (default: true). " +
            "Finds the most recent valid request to the target URL and extracts all headers/cookies. " +
            "Set to false to use basic unauthenticated requests.");
        useProxySessionProperty.put("default", true);
        properties.put("useProxySession", useProxySessionProperty);

        inputSchema.put("properties", properties);
        inputSchema.put("required", List.of("action"));

        // Action-specific required parameters validated at runtime (allOf removed for Claude API compatibility)

        tool.put("inputSchema", inputSchema);

        // Output schema
        Map<String, Object> outputProps = new HashMap<>();
        outputProps.put("scanId", SchemaHelper.stringProp("Scan identifier for tracking"));
        outputProps.put("status", SchemaHelper.stringProp("Scan status (running, completed, cancelled)"));
        outputProps.put("progress", SchemaHelper.intProp("Scan progress percentage"));
        outputProps.put("issues", SchemaHelper.objectProp("Array of discovered vulnerabilities"));
        tool.put("outputSchema", SchemaHelper.outputSchema(outputProps));

        return tool;
    }

    @Override
    public Object execute(JsonNode arguments) throws Exception {
        McpUtils.ActionResolution actionResolution = McpUtils.resolveAction(arguments, SUPPORTED_ACTIONS);
        if (actionResolution.hasError()) {
            return createErrorResponse(actionResolution.getErrorMessage());
        }

        String action = actionResolution.getAction();
        
        try {
            Scanner scanner = api.scanner();
            if (scanner == null) {
                return createErrorResponse("Scanner functionality is not available. Requires Burp Suite Professional.");
            }
            
            switch (action) {
                case "START_SCAN":
                    return startScan(arguments, scanner);

                case "CRAWL_ONLY":
                    return crawlOnly(arguments, scanner);

                case "GET_STATUS":
                    return getScanStatus(arguments);
                
                case "GET_ISSUES":
                    return getScanIssues(arguments);
                
                case "CANCEL_SCAN":
                    return cancelScan(arguments);
                
                case "LIST_SCANS":
                    return listActiveScans(arguments);
                
                case "ADD_TO_SCAN":
                    return addToScan(arguments);
                
                case "GENERATE_REPORT":
                    return generateReport(arguments, scanner);
                
                case "IMPORT_BCHECK":
                    return importBCheck(arguments, scanner);
                
                case "CLEAR_ISSUES":
                    return clearScanIssues(arguments);
                
                case "SCAN_SPECIFIC_REQUEST":
                    return scanSpecificRequest(arguments, scanner);

                case "SCAN_METRICS":
                    return getScanMetrics(arguments);

                case "FILTER_ISSUES":
                    return getFilteredIssues(arguments);

                default:
                    return createErrorResponse("Unknown action: " + action);
            }
            
        } catch (Exception e) {
            api.logging().logToError("Scanner tool error: " + e.getMessage());
            e.printStackTrace();
            return createErrorResponse("Scanner error: " + e.getMessage());
        }
    }
    
    private Object startScan(JsonNode arguments, Scanner scanner) {
        JsonNode urlsNode = arguments.get("urls");
        if (urlsNode == null || !urlsNode.isArray() || urlsNode.size() == 0) {
            return createErrorResponse("URLs array is required for START_SCAN");
        }
        
        String mode = arguments.has("mode") ? arguments.get("mode").asText().toUpperCase() : "ACTIVE";
        String config = arguments.has("config") ? arguments.get("config").asText().toUpperCase() : "MEDIUM";
        boolean doCrawl = arguments.has("crawl") && arguments.get("crawl").asBoolean();
        
        // Convert URLs to list
        List<String> urls = new ArrayList<>();
        for (JsonNode urlNode : urlsNode) {
            urls.add(urlNode.asText());
        }
        
        // Generate scan ID
        String scanId = UUID.randomUUID().toString();
        
        // Select appropriate configuration
        BuiltInAuditConfiguration builtInConfig;
        if ("PASSIVE".equals(mode)) {
            builtInConfig = BuiltInAuditConfiguration.LEGACY_PASSIVE_AUDIT_CHECKS;
        } else {
            // For now, we only have LEGACY configs available
            // In future Burp versions, might have LIGHT/MEDIUM/THOROUGH configs
            builtInConfig = BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS;
        }
        
        AuditConfiguration auditConfig = AuditConfiguration.auditConfiguration(builtInConfig);
        boolean verbose = McpUtils.isVerbose(arguments);

        try {
            Audit audit = scanner.startAudit(auditConfig);
            activeAudits.put(scanId, audit);

            // Add URLs to audit
            int successCount = 0;
            List<Map<String, String>> failedUrls = new ArrayList<>();
            for (String url : urls) {
                try {
                    HttpRequest request = buildRequestWithHeaders(url, arguments);
                    audit.addRequest(request);
                    successCount++;
                } catch (Exception e) {
                    Map<String, String> f = new HashMap<>();
                    f.put("url", url);
                    f.put("error", e.getMessage());
                    failedUrls.add(f);
                }
            }

            scanMetadata.put(scanId, new ScanMetadata(scanId, "AUDIT", mode, config, urls));

            // Start crawl if requested
            String crawlId = null;
            String crawlError = null;
            if (doCrawl && successCount > 0) {
                try {
                    String[] seedUrls = urls.toArray(new String[0]);
                    CrawlConfiguration crawlConfig = CrawlConfiguration.crawlConfiguration(seedUrls);
                    Crawl crawl = scanner.startCrawl(crawlConfig);

                    crawlId = UUID.randomUUID().toString();
                    activeCrawls.put(crawlId, crawl);
                    scanMetadata.put(crawlId, new ScanMetadata(crawlId, "CRAWL", "N/A", "N/A", urls));
                } catch (Exception e) {
                    crawlError = e.getMessage();
                }
            }

            if (!verbose) {
                Map<String, Object> data = new HashMap<>();
                data.put("scanId", scanId);
                if (crawlId != null) data.put("crawlId", crawlId);
                if (crawlError != null) data.put("crawlError", crawlError);
                data.put("type", mode + " Audit");
                data.put("configuration", config);
                data.put("urlsAdded", successCount);
                data.put("urlsTotal", urls.size());
                data.put("targetUrls", urls);
                if (!failedUrls.isEmpty()) data.put("failedUrls", failedUrls);
                data.put("status", "STARTED");
                return McpUtils.createJsonResponse(data);
            }

            StringBuilder result = new StringBuilder();
            result.append("🔍 **Scan Initiated**\n");
            result.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");
            for (Map<String, String> f : failedUrls) {
                result.append("⚠️ Failed to add URL: ").append(f.get("url")).append("\n");
                result.append("   Error: ").append(f.get("error")).append("\n");
            }
            result.append("**Scan Details:**\n");
            result.append("• **Scan ID:** `").append(scanId).append("`\n");
            result.append("• **Type:** ").append(mode).append(" Audit\n");
            result.append("• **Configuration:** ").append(config).append("\n");
            result.append("• **URLs Added:** ").append(successCount).append("/").append(urls.size()).append("\n");
            if (crawlId != null) {
                result.append("• **Crawl ID:** `").append(crawlId).append("`\n");
                result.append("• **Crawl Status:** Started\n");
            } else if (crawlError != null) {
                result.append("• **Crawl:** Failed - ").append(crawlError).append("\n");
            }
            result.append("\n**Target URLs:**\n");
            for (String url : urls) {
                result.append("• ").append(url).append("\n");
            }
            result.append("\n**Next Steps:** Use GET_STATUS, GET_ISSUES, ADD_TO_SCAN, or CANCEL_SCAN with the scan ID.\n");
            return createTextResponse(result.toString());

        } catch (Exception e) {
            return createErrorResponse("Failed to start scan: " + e.getMessage());
        }
    }
    
    private Object getScanStatus(JsonNode arguments) {
        String scanId = arguments.has("scanId") ? arguments.get("scanId").asText() : null;
        if (scanId == null || scanId.isEmpty()) {
            return createErrorResponse("scanId is required for GET_STATUS");
        }

        boolean verbose = McpUtils.isVerbose(arguments);

        // Check if it's an audit
        Audit audit = activeAudits.get(scanId);
        if (audit != null) {
            ScanMetadata metadata = scanMetadata.get(scanId);

            // Compact JSON by default
            if (!verbose) {
                Map<String, Object> data = new HashMap<>();
                data.put("scanId", scanId);
                data.put("type", metadata != null ? metadata.mode + " Audit" : "Audit");
                if (metadata != null) {
                    data.put("started", metadata.startTime.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
                    data.put("configuration", metadata.config);
                }
                data.put("requestCount", audit.requestCount());
                data.put("insertionPointCount", audit.insertionPointCount());
                data.put("errorCount", audit.errorCount());
                String statusMsg = audit.statusMessage();
                data.put("status", statusMsg != null ? statusMsg : "Running");
                try {
                    List<AuditIssue> issues = audit.issues();
                    data.put("issuesFound", issues.size());
                    Map<String, Long> severityCount = issues.stream()
                        .collect(Collectors.groupingBy(
                            issue -> issue.severity().name(),
                            Collectors.counting()
                        ));
                    data.put("severityBreakdown", severityCount);
                } catch (Exception e) {
                    data.put("issuesError", e.getMessage());
                }
                return McpUtils.createJsonResponse(data);
            }

            StringBuilder result = new StringBuilder();
            result.append("📊 **Scan Status Report**\n");
            result.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");

            result.append("**Scan Information:**\n");
            result.append("• **ID:** `").append(scanId).append("`\n");
            result.append("• **Type:** ").append(metadata != null ? metadata.mode + " Audit" : "Audit").append("\n");
            if (metadata != null) {
                result.append("• **Started:** ").append(metadata.startTime.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME)).append("\n");
                result.append("• **Configuration:** ").append(metadata.config).append("\n");
            }

            result.append("\n**Progress Metrics:**\n");
            result.append("• **Requests Made:** ").append(audit.requestCount()).append("\n");
            result.append("• **Insertion Points:** ").append(audit.insertionPointCount()).append("\n");
            result.append("• **Errors Encountered:** ").append(audit.errorCount()).append("\n");

            String status = audit.statusMessage();
            result.append("• **Current Status:** ").append(status != null ? status : "Running").append("\n");

            // Get issues count
            try {
                List<AuditIssue> issues = audit.issues();
                result.append("• **Issues Found:** ").append(issues.size()).append("\n");

                if (!issues.isEmpty()) {
                    // Group by severity
                    Map<String, Long> severityCount = issues.stream()
                        .collect(Collectors.groupingBy(
                            issue -> issue.severity().name(),
                            Collectors.counting()
                        ));

                    result.append("\n**Issue Breakdown:**\n");
                    for (Map.Entry<String, Long> entry : severityCount.entrySet()) {
                        String severity = entry.getKey();
                        String icon = getSeverityIcon(severity);
                        result.append("• ").append(icon).append(" ").append(severity).append(": ").append(entry.getValue()).append("\n");
                    }
                }
            } catch (Exception e) {
                result.append("• **Issues:** Unable to retrieve (").append(e.getMessage()).append(")\n");
            }

            return createTextResponse(result.toString());
        }
        
        // Check if it's a crawl
        Crawl crawl = activeCrawls.get(scanId);
        if (crawl != null) {
            ScanMetadata metadata = scanMetadata.get(scanId);

            // Compute status (statusMessage() throws UnsupportedOperationException in some Burp versions)
            String status = "Running";
            try {
                String statusMsg = crawl.statusMessage();
                if (statusMsg != null && !statusMsg.isEmpty()) {
                    status = statusMsg;
                }
            } catch (UnsupportedOperationException e) {
                int requests = crawl.requestCount();
                int errors = crawl.errorCount();
                if (requests == 0) {
                    status = "Starting...";
                } else if (errors > requests / 2) {
                    status = "Running (high error rate)";
                } else {
                    status = "Running (" + requests + " requests completed)";
                }
            }

            // Compact JSON by default
            if (!verbose) {
                Map<String, Object> data = new HashMap<>();
                data.put("scanId", scanId);
                data.put("type", "Crawl");
                if (metadata != null) {
                    data.put("started", metadata.startTime.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
                }
                data.put("requestCount", crawl.requestCount());
                data.put("errorCount", crawl.errorCount());
                data.put("status", status);
                return McpUtils.createJsonResponse(data);
            }

            StringBuilder result = new StringBuilder();
            result.append("📊 **Scan Status Report**\n");
            result.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");
            result.append("**Crawl Information:**\n");
            result.append("• **ID:** `").append(scanId).append("`\n");
            result.append("• **Type:** Crawl\n");
            if (metadata != null) {
                result.append("• **Started:** ").append(metadata.startTime.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME)).append("\n");
            }
            result.append("\n**Progress Metrics:**\n");
            result.append("• **Requests Made:** ").append(crawl.requestCount()).append("\n");
            result.append("• **Errors Encountered:** ").append(crawl.errorCount()).append("\n");
            result.append("• **Current Status:** ").append(status).append("\n");

            return createTextResponse(result.toString());
        }
        
        return createErrorResponse("No active scan found with ID: " + scanId);
    }
    
    private Object getScanIssues(JsonNode arguments) {
        String scanId = arguments.has("scanId") ? arguments.get("scanId").asText() : null;
        if (scanId == null || scanId.isEmpty()) {
            return createErrorResponse("scanId is required for GET_ISSUES");
        }

        Audit audit = activeAudits.get(scanId);
        if (audit == null) {
            return createErrorResponse("No active audit found with ID: " + scanId);
        }

        try {
            List<AuditIssue> issues;
            try {
                issues = audit.issues();
            } catch (UnsupportedOperationException e) {
                api.logging().logToOutput("Note: audit.issues() not supported, using siteMap.issues() instead");
                issues = api.siteMap().issues();
            }

            issues = new ArrayList<>(applyIssueFilters(issues, arguments));
            sortIssuesBySeverity(issues);

            String title = "Scan Issues (ID: " + scanId + ")";
            boolean verbose = McpUtils.isVerbose(arguments);

            // Detail mode if issueIndex is provided
            if (arguments.has("issueIndex") && arguments.get("issueIndex").isArray()) {
                List<Integer> indices = new ArrayList<>();
                arguments.get("issueIndex").forEach(node -> indices.add(node.asInt()));
                return formatIssueDetail(issues, indices, title, verbose);
            }

            // Summary mode with pagination
            int limit = arguments.has("limit") ? arguments.get("limit").asInt() : 50;
            int offset = arguments.has("offset") ? arguments.get("offset").asInt() : 0;
            return formatIssueSummary(issues, limit, offset, title, verbose);

        } catch (Exception e) {
            return createErrorResponse("Failed to retrieve issues: " + e.getMessage());
        }
    }
    
    private Object cancelScan(JsonNode arguments) {
        String scanId = arguments.has("scanId") ? arguments.get("scanId").asText() : null;
        if (scanId == null || scanId.isEmpty()) {
            return createErrorResponse("scanId is required for CANCEL_SCAN");
        }

        boolean verbose = McpUtils.isVerbose(arguments);
        boolean cancelledAudit = false;
        boolean cancelledCrawl = false;
        String auditError = null;
        String crawlError = null;

        Audit audit = activeAudits.get(scanId);
        if (audit != null) {
            try {
                audit.delete();
                activeAudits.remove(scanId);
                scanMetadata.remove(scanId);
                cancelledAudit = true;
            } catch (Exception e) {
                auditError = e.getMessage();
            }
        }

        Crawl crawl = activeCrawls.get(scanId);
        if (crawl != null) {
            try {
                crawl.delete();
                activeCrawls.remove(scanId);
                scanMetadata.remove(scanId);
                cancelledCrawl = true;
            } catch (Exception e) {
                crawlError = e.getMessage();
            }
        }

        if (!cancelledAudit && !cancelledCrawl && audit == null && crawl == null) {
            return createErrorResponse("No active scan found with ID: " + scanId);
        }

        if (!verbose) {
            Map<String, Object> data = new HashMap<>();
            data.put("scanId", scanId);
            data.put("cancelledAudit", cancelledAudit);
            data.put("cancelledCrawl", cancelledCrawl);
            if (auditError != null) data.put("auditError", auditError);
            if (crawlError != null) data.put("crawlError", crawlError);
            return McpUtils.createJsonResponse(data);
        }

        StringBuilder result = new StringBuilder();
        if (cancelledAudit) result.append("✅ Successfully cancelled audit scan: ").append(scanId).append("\n");
        if (auditError != null) result.append("❌ Failed to cancel audit: ").append(auditError).append("\n");
        if (cancelledCrawl) result.append("✅ Successfully cancelled crawl: ").append(scanId).append("\n");
        if (crawlError != null) result.append("❌ Failed to cancel crawl: ").append(crawlError).append("\n");
        return createTextResponse(result.toString());
    }
    
    private Object listActiveScans(JsonNode arguments) {
        // Build audit/crawl lists
        List<Map<String, Object>> audits = new ArrayList<>();
        for (Map.Entry<String, Audit> entry : activeAudits.entrySet()) {
            String id = entry.getKey();
            Audit audit = entry.getValue();
            ScanMetadata metadata = scanMetadata.get(id);
            Map<String, Object> a = new HashMap<>();
            a.put("id", id);
            if (metadata != null) {
                a.put("mode", metadata.mode);
                a.put("started", metadata.startTime.format(DateTimeFormatter.ISO_LOCAL_TIME));
            }
            a.put("requestCount", audit.requestCount());
            try {
                a.put("issuesCount", audit.issues().size());
            } catch (Exception e) {
                a.put("issuesError", e.getMessage());
            }
            audits.add(a);
        }

        List<Map<String, Object>> crawls = new ArrayList<>();
        for (Map.Entry<String, Crawl> entry : activeCrawls.entrySet()) {
            String id = entry.getKey();
            Crawl crawl = entry.getValue();
            ScanMetadata metadata = scanMetadata.get(id);
            Map<String, Object> c = new HashMap<>();
            c.put("id", id);
            if (metadata != null) {
                c.put("started", metadata.startTime.format(DateTimeFormatter.ISO_LOCAL_TIME));
            }
            c.put("requestCount", crawl.requestCount());
            c.put("errorCount", crawl.errorCount());
            crawls.add(c);
        }

        if (!McpUtils.isVerbose(arguments)) {
            Map<String, Object> data = new HashMap<>();
            data.put("auditsCount", audits.size());
            data.put("crawlsCount", crawls.size());
            data.put("audits", audits);
            data.put("crawls", crawls);
            return McpUtils.createJsonResponse(data);
        }

        StringBuilder result = new StringBuilder();
        result.append("📋 **Active Scans**\n");
        result.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");
        if (audits.isEmpty() && crawls.isEmpty()) {
            result.append("No active scans.\n");
        } else {
            if (!audits.isEmpty()) {
                result.append("## Active Audits\n");
                for (Map<String, Object> a : audits) {
                    result.append("• **ID:** `").append(a.get("id")).append("`\n");
                    if (a.containsKey("mode")) result.append("  **Type:** ").append(a.get("mode")).append("\n");
                    if (a.containsKey("started")) result.append("  **Started:** ").append(a.get("started")).append("\n");
                    result.append("  **Requests:** ").append(a.get("requestCount")).append("\n");
                    if (a.containsKey("issuesCount")) result.append("  **Issues:** ").append(a.get("issuesCount")).append("\n");
                    else if (a.containsKey("issuesError")) result.append("  **Issues:** N/A (").append(a.get("issuesError")).append(")\n");
                    result.append("\n");
                }
            }
            if (!crawls.isEmpty()) {
                result.append("## Active Crawls\n");
                for (Map<String, Object> c : crawls) {
                    result.append("• **ID:** `").append(c.get("id")).append("`\n");
                    if (c.containsKey("started")) result.append("  **Started:** ").append(c.get("started")).append("\n");
                    result.append("  **Requests:** ").append(c.get("requestCount")).append("\n");
                    result.append("  **Errors:** ").append(c.get("errorCount")).append("\n");
                    result.append("\n");
                }
            }
        }
        return createTextResponse(result.toString());
    }
    
    private Object addToScan(JsonNode arguments) {
        String scanId = arguments.has("scanId") ? arguments.get("scanId").asText() : null;
        if (scanId == null || scanId.isEmpty()) {
            return createErrorResponse("scanId is required for ADD_TO_SCAN");
        }

        Audit audit = activeAudits.get(scanId);
        if (audit == null) {
            return createErrorResponse("No active audit found with ID: " + scanId);
        }

        boolean verbose = McpUtils.isVerbose(arguments);
        StringBuilder ipLog = new StringBuilder();
        int urlsAdded = 0;
        List<String> urlsFailed = new ArrayList<>();
        Integer requestInsertionPoints = null;
        boolean requestAdded = false;

        // URLs
        if (arguments.has("urls")) {
            JsonNode urlsNode = arguments.get("urls");
            for (JsonNode urlNode : urlsNode) {
                try {
                    String url = urlNode.asText();
                    HttpRequest request = HttpRequest.httpRequestFromUrl(url);
                    audit.addRequest(request);
                    urlsAdded++;
                } catch (Exception e) {
                    urlsFailed.add(urlNode.asText());
                }
            }
        }

        // Raw request with optional insertion points
        if (arguments.has("request")) {
            String requestStr = arguments.get("request").asText();
            try {
                HttpRequest request = buildScanRequest(requestStr, arguments);
                List<Range> ranges = resolveInsertionPoints(requestStr, arguments, ipLog);
                if (!ranges.isEmpty()) {
                    audit.addRequest(request, ranges);
                    requestInsertionPoints = ranges.size();
                } else {
                    audit.addRequest(request);
                    requestInsertionPoints = 0;
                }
                requestAdded = true;
            } catch (Exception e) {
                return createErrorResponse("Failed to add request: " + e.getMessage());
            }
        }

        if (!verbose) {
            Map<String, Object> data = new HashMap<>();
            data.put("scanId", scanId);
            if (arguments.has("urls")) {
                data.put("urlsAdded", urlsAdded);
                if (!urlsFailed.isEmpty()) data.put("urlsFailed", urlsFailed);
            }
            if (requestAdded) {
                data.put("requestAdded", true);
                data.put("insertionPoints", requestInsertionPoints);
            }
            data.put("totalRequests", audit.requestCount());
            return McpUtils.createJsonResponse(data);
        }

        StringBuilder result = new StringBuilder();
        for (String f : urlsFailed) result.append("⚠️ Failed to add URL: ").append(f).append("\n");
        if (arguments.has("urls")) {
            result.append("✅ Added ").append(urlsAdded).append(" URL(s) to scan ").append(scanId).append("\n");
        }
        if (ipLog.length() > 0) result.append(ipLog);
        if (requestAdded) {
            if (requestInsertionPoints > 0) {
                result.append("✅ Added request with ").append(requestInsertionPoints).append(" insertion point(s)\n");
            } else {
                result.append("✅ Added request to scan (all parameters)\n");
            }
        }
        result.append("Current scan has ").append(audit.requestCount()).append(" total requests\n");
        return createTextResponse(result.toString());
    }
    
    private Object generateReport(JsonNode arguments, Scanner scanner) {
        String scanId = arguments.has("scanId") ? arguments.get("scanId").asText() : null;
        if (scanId == null || scanId.isEmpty()) {
            return createErrorResponse("scanId is required for GENERATE_REPORT");
        }
        
        Audit audit = activeAudits.get(scanId);
        if (audit == null) {
            return createErrorResponse("No active audit found with ID: " + scanId);
        }
        
        String format = arguments.has("format") ? arguments.get("format").asText().toUpperCase() : "HTML";
        String outputPath = arguments.has("outputPath") ? arguments.get("outputPath").asText() : null;
        
        if (outputPath == null) {
            // Generate default path
            String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss"));
            outputPath = "/tmp/burp_scan_" + scanId.substring(0, 8) + "_" + timestamp + "." + format.toLowerCase();
        }
        
        try {
            List<AuditIssue> issues = audit.issues();

            if (issues.isEmpty()) {
                return createErrorResponse("No issues to report. Scan may still be in progress.");
            }

            ReportFormat reportFormat = "XML".equals(format) ? ReportFormat.XML : ReportFormat.HTML;
            Path path = Paths.get(outputPath);

            scanner.generateReport(issues, reportFormat, path);

            Map<String, Long> severityCount = issues.stream()
                .collect(Collectors.groupingBy(
                    issue -> issue.severity().name(),
                    Collectors.counting()
                ));

            if (!McpUtils.isVerbose(arguments)) {
                Map<String, Object> data = new HashMap<>();
                data.put("format", format);
                data.put("issuesIncluded", issues.size());
                data.put("outputPath", outputPath);
                data.put("severityCount", severityCount);
                return McpUtils.createJsonResponse(data);
            }

            StringBuilder result = new StringBuilder();
            result.append("📄 **Report Generated Successfully**\n");
            result.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");
            result.append("**Format:** ").append(format).append("\n");
            result.append("**Issues Included:** ").append(issues.size()).append("\n");
            result.append("**File Location:** `").append(outputPath).append("`\n\n");
            result.append("**Issue Summary:**\n");
            for (Map.Entry<String, Long> entry : severityCount.entrySet()) {
                result.append("• ").append(entry.getKey()).append(": ").append(entry.getValue()).append("\n");
            }
            return createTextResponse(result.toString());

        } catch (Exception e) {
            return createErrorResponse("Failed to generate report: " + e.getMessage());
        }
    }
    
    private Object importBCheck(JsonNode arguments, Scanner scanner) {
        String definition = arguments.has("definition") ? arguments.get("definition").asText() : null;
        if (definition == null || definition.isEmpty()) {
            return createErrorResponse("definition is required for IMPORT_BCHECK");
        }
        
        boolean autoEnable = arguments.has("autoEnable") ? arguments.get("autoEnable").asBoolean() : true;
        
        try {
            BCheckImportResult result = scanner.bChecks().importBCheck(definition, autoEnable);

            BCheckImportResult.Status status = result.status();
            List<String> errors = result.importErrors();

            if (!McpUtils.isVerbose(arguments)) {
                Map<String, Object> data = new HashMap<>();
                data.put("status", status.name());
                data.put("autoEnabled", autoEnable);
                if (errors != null && !errors.isEmpty()) data.put("errors", errors);
                return McpUtils.createJsonResponse(data);
            }

            StringBuilder response = new StringBuilder();
            response.append("🔧 **BCheck Import Result**\n");
            response.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");
            if (status == BCheckImportResult.Status.LOADED_WITHOUT_ERRORS) {
                response.append("✅ **Status:** Successfully imported without errors\n");
                response.append("**Auto-enabled:** ").append(autoEnable ? "Yes" : "No").append("\n");
            } else if (status == BCheckImportResult.Status.LOADED_WITH_ERRORS) {
                response.append("⚠️ **Status:** Imported with errors\n");
                response.append("**Auto-enabled:** ").append(autoEnable ? "Yes" : "No").append("\n");
                if (errors != null && !errors.isEmpty()) {
                    response.append("\n**Errors/Warnings:**\n");
                    for (String error : errors) response.append("• ").append(error).append("\n");
                }
            } else {
                response.append("❌ **Status:** Import failed\n");
                if (errors != null && !errors.isEmpty()) {
                    response.append("\n**Errors:**\n");
                    for (String error : errors) response.append("• ").append(error).append("\n");
                }
            }
            response.append("\n**Note:** Imported BChecks will be used in new scans automatically.");
            return createTextResponse(response.toString());

        } catch (Exception e) {
            return createErrorResponse("Failed to import BCheck: " + e.getMessage());
        }
    }
    
    private Object clearScanIssues(JsonNode arguments) {
        String scanId = arguments.has("scanId") ? arguments.get("scanId").asText() : null;
        boolean verbose = McpUtils.isVerbose(arguments);

        if (scanId != null && !scanId.isEmpty()) {
            Audit audit = activeAudits.remove(scanId);
            Crawl crawl = activeCrawls.remove(scanId);
            scanMetadata.remove(scanId);
            boolean cleared = (audit != null || crawl != null);

            if (!verbose) {
                Map<String, Object> data = new HashMap<>();
                data.put("scanId", scanId);
                data.put("cleared", cleared);
                if (!cleared) data.put("error", "scan_not_found");
                return McpUtils.createJsonResponse(data);
            }
            return cleared
                ? createTextResponse("✅ Cleared scan data for ID: " + scanId)
                : createErrorResponse("No scan found with ID: " + scanId);
        }

        // Clear all completed scans
        int cleared = 0;
        List<String> toRemove = new ArrayList<>();
        for (Map.Entry<String, Audit> entry : activeAudits.entrySet()) {
            try {
                String status = entry.getValue().statusMessage();
                if (status != null && (status.toLowerCase().contains("complete") ||
                                      status.toLowerCase().contains("finished"))) {
                    toRemove.add(entry.getKey());
                }
            } catch (Exception e) { }
        }
        for (String id : toRemove) {
            activeAudits.remove(id);
            scanMetadata.remove(id);
            cleared++;
        }

        if (!verbose) {
            Map<String, Object> data = new HashMap<>();
            data.put("clearedCount", cleared);
            data.put("activeScansPreserved", true);
            return McpUtils.createJsonResponse(data);
        }
        return createTextResponse("✅ Cleared " + cleared + " completed scan(s). Active scans preserved.");
    }
    
    /**
     * Apply severity and URL filters to a list of issues.
     */
    private List<AuditIssue> applyIssueFilters(List<AuditIssue> issues, JsonNode arguments) {
        String severityFilter = arguments.has("severity") ? arguments.get("severity").asText().toUpperCase() : null;
        String urlFilter = arguments.has("urlFilter") ? arguments.get("urlFilter").asText() : null;

        if (severityFilter == null && urlFilter == null) {
            return issues;
        }

        AuditIssueSeverity parsedSeverity = null;
        if (severityFilter != null) {
            try {
                parsedSeverity = AuditIssueSeverity.valueOf(severityFilter);
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("Invalid severity: " + severityFilter +
                    ". Valid values: HIGH, MEDIUM, LOW, INFORMATION, FALSE_POSITIVE");
            }
        }

        List<AuditIssue> filtered = new ArrayList<>();
        for (AuditIssue issue : issues) {
            if (parsedSeverity != null && issue.severity() != parsedSeverity) continue;
            if (urlFilter != null && !urlFilter.isEmpty()) {
                String pattern = urlFilter.replace("*", ".*");
                if (!issue.baseUrl().matches(pattern)) continue;
            }
            filtered.add(issue);
        }
        return filtered;
    }

    /**
     * Sort issues by severity (HIGH first) then by name.
     */
    private List<AuditIssue> sortIssuesBySeverity(List<AuditIssue> issues) {
        List<AuditIssueSeverity> order = List.of(
            AuditIssueSeverity.HIGH,
            AuditIssueSeverity.MEDIUM,
            AuditIssueSeverity.LOW,
            AuditIssueSeverity.INFORMATION,
            AuditIssueSeverity.FALSE_POSITIVE
        );
        issues.sort(Comparator.<AuditIssue, Integer>comparing(
            issue -> {
                int idx = order.indexOf(issue.severity());
                return idx >= 0 ? idx : order.size();
            }
        ).thenComparing(AuditIssue::name));
        return issues;
    }

    /**
     * Format issues as a compact summary table with pagination.
     */
    private Object formatIssueSummary(List<AuditIssue> issues, int limit, int offset, String title, boolean verbose) {
        if (offset < 0) {
            return createErrorResponse("offset must be >= 0, got: " + offset);
        }
        if (limit < 1) {
            return createErrorResponse("limit must be >= 1, got: " + limit);
        }

        int total = issues.size();
        if (total > 0 && offset >= total) {
            return createErrorResponse("offset " + offset + " is beyond total issue count " + total);
        }

        int end = Math.min(offset + limit, total);
        List<AuditIssue> page = total > 0 ? issues.subList(offset, end) : new ArrayList<>();

        // Build issue list
        List<Map<String, Object>> jsonIssues = new ArrayList<>();
        for (int i = 0; i < page.size(); i++) {
            AuditIssue issue = page.get(i);
            Map<String, Object> e = new HashMap<>();
            e.put("index", offset + i + 1);
            e.put("severity", issue.severity().name());
            e.put("confidence", issue.confidence().name());
            e.put("name", issue.name());
            e.put("url", issue.baseUrl());
            jsonIssues.add(e);
        }

        if (!verbose) {
            Map<String, Object> data = new HashMap<>();
            data.put("title", title);
            data.put("total", total);
            data.put("offset", offset);
            data.put("showing", end - offset);
            if (end < total) data.put("nextOffset", end);
            data.put("issues", jsonIssues);
            return McpUtils.createJsonResponse(data);
        }

        StringBuilder result = new StringBuilder();
        result.append("**").append(title).append("**\n");
        if (total == 0) {
            result.append("**Total:** 0\n\nNo issues found.\n");
            return createTextResponse(result.toString());
        }
        result.append(String.format("**Total:** %d | **Showing:** %d-%d\n\n", total, offset + 1, end));
        result.append("```\n");
        result.append(String.format("%-5s | %-15s | %-10s | %-30s | %s\n", "#", "Severity", "Confidence", "Name", "URL"));
        result.append("------|-----------------|------------|--------------------------------|---------------------------\n");
        for (Map<String, Object> e : jsonIssues) {
            String name = (String) e.get("name");
            if (name.length() > 30) name = name.substring(0, 27) + "...";
            String url = (String) e.get("url");
            if (url.length() > 50) url = url.substring(0, 47) + "...";
            result.append(String.format("%-5d | %-15s | %-10s | %-30s | %s\n",
                e.get("index"), e.get("severity"), e.get("confidence"), name, url));
        }
        result.append("```\n");
        if (end < total) {
            result.append(String.format("\nUse `offset: %d` to see next page.\n", end));
        }
        result.append("Use `issueIndex: [1, 2, ...]` to get full details for specific issues.\n");
        return createTextResponse(result.toString());
    }

    /**
     * Format full details for issues at specific 1-based indices.
     */
    private Object formatIssueDetail(List<AuditIssue> issues, List<Integer> indices, String title, boolean verbose) {
        // Build detail list
        List<Map<String, Object>> jsonDetails = new ArrayList<>();
        for (int idx : indices) {
            Map<String, Object> e = new HashMap<>();
            e.put("index", idx);
            if (idx < 1 || idx > issues.size()) {
                e.put("error", "not_found");
                e.put("validRange", "1-" + issues.size());
                jsonDetails.add(e);
                continue;
            }
            AuditIssue issue = issues.get(idx - 1);
            e.put("name", issue.name());
            e.put("severity", issue.severity().name());
            e.put("confidence", issue.confidence().name());
            e.put("url", issue.baseUrl());
            String detail = issue.detail();
            if (detail != null && !detail.isEmpty()) {
                if (detail.length() > 500) detail = detail.substring(0, 497) + "...";
                e.put("detail", detail);
            }
            String remediation = issue.remediation();
            if (remediation != null && !remediation.isEmpty()) {
                if (remediation.length() > 500) remediation = remediation.substring(0, 497) + "...";
                e.put("remediation", remediation);
            }
            jsonDetails.add(e);
        }

        if (!verbose) {
            Map<String, Object> data = new HashMap<>();
            data.put("title", title);
            data.put("issues", jsonDetails);
            return McpUtils.createJsonResponse(data);
        }

        StringBuilder result = new StringBuilder();
        result.append("**").append(title).append("** (Detail)\n\n");
        for (Map<String, Object> e : jsonDetails) {
            int idx = (Integer) e.get("index");
            if (e.containsKey("error")) {
                result.append(String.format("Issue #%d not found (valid: %s)\n\n", idx, e.get("validRange")));
                continue;
            }
            String icon = getSeverityIcon((String) e.get("severity"));
            result.append(String.format("### %s #%d: %s\n", icon, idx, e.get("name")));
            result.append(String.format("**URL:** %s\n", e.get("url")));
            result.append(String.format("**Severity:** %s\n", e.get("severity")));
            result.append(String.format("**Confidence:** %s\n", e.get("confidence")));
            if (e.containsKey("detail")) result.append(String.format("**Details:** %s\n", e.get("detail")));
            if (e.containsKey("remediation")) result.append(String.format("**Remediation:** %s\n", e.get("remediation")));
            result.append("\n");
        }
        return createTextResponse(result.toString());
    }

    private String getSeverityIcon(String severity) {
        switch (severity.toUpperCase()) {
            case "HIGH":
                return "🔴";
            case "MEDIUM":
                return "🟠";
            case "LOW":
                return "🟡";
            case "INFORMATION":
            case "INFO":
                return "🔵";
            default:
                return "⚪";
        }
    }
    
    private Object scanSpecificRequest(JsonNode arguments, Scanner scanner) {
        // Validate required parameters
        String requestStr = arguments.has("request") ? arguments.get("request").asText() : null;
        if (requestStr == null || requestStr.isEmpty()) {
            return createErrorResponse("request parameter is required for SCAN_SPECIFIC_REQUEST");
        }

        String mode = arguments.has("mode") ? arguments.get("mode").asText().toUpperCase() : "ACTIVE";
        String config = arguments.has("config") ? arguments.get("config").asText().toUpperCase() : "MEDIUM";

        try {
            HttpRequest request = buildScanRequest(requestStr, arguments);
            
            // Generate scan ID
            String scanId = UUID.randomUUID().toString();
            
            // Select appropriate configuration
            BuiltInAuditConfiguration builtInConfig;
            if ("PASSIVE".equals(mode)) {
                builtInConfig = BuiltInAuditConfiguration.LEGACY_PASSIVE_AUDIT_CHECKS;
            } else {
                builtInConfig = BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS;
            }
            
            AuditConfiguration auditConfig = AuditConfiguration.auditConfiguration(builtInConfig);
            
            // Start audit
            Audit audit = scanner.startAudit(auditConfig);
            activeAudits.put(scanId, audit);
            
            // Resolve insertion points if specified
            StringBuilder ipLog = new StringBuilder();
            List<Range> ranges = resolveInsertionPoints(requestStr, arguments, ipLog);
            if (!ranges.isEmpty()) {
                audit.addRequest(request, ranges);
            } else {
                audit.addRequest(request);
            }
            
            // Store metadata
            HttpService svc = request.httpService();
            List<String> urls = new ArrayList<>();
            urls.add(String.format("%s://%s:%d%s",
                svc.secure() ? "https" : "http",
                svc.host(),
                svc.port(),
                request.path()));
            scanMetadata.put(scanId, new ScanMetadata(scanId, "AUDIT", mode, config, urls));

            if (!McpUtils.isVerbose(arguments)) {
                Map<String, Object> data = new HashMap<>();
                data.put("scanId", scanId);
                data.put("type", mode + " Audit (Single Request)");
                data.put("configuration", config);
                data.put("target", svc.host() + ":" + svc.port());
                data.put("protocol", svc.secure() ? "HTTPS" : "HTTP");
                data.put("method", request.method());
                data.put("path", request.path());
                data.put("insertionPointsResolved", ranges.size());
                return McpUtils.createJsonResponse(data);
            }

            StringBuilder result = new StringBuilder();
            result.append("🎯 **Single Request Scan Initiated**\n");
            result.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");
            result.append("**Scan Details:**\n");
            result.append("• **Scan ID:** `").append(scanId).append("`\n");
            result.append("• **Type:** ").append(mode).append(" Audit (Single Request)\n");
            result.append("• **Configuration:** ").append(config).append("\n");
            result.append("• **Target:** ").append(svc.host()).append(":").append(svc.port()).append("\n");
            result.append("• **Protocol:** ").append(svc.secure() ? "HTTPS" : "HTTP").append("\n");
            result.append("• **Method:** ").append(request.method()).append("\n");
            result.append("• **Path:** ").append(request.path()).append("\n");
            result.append("• **Insertion Points Resolved:** ").append(ranges.size()).append("\n");
            if (ipLog.length() > 0) {
                result.append("\n**Insertion Points:**\n").append(ipLog);
            }
            result.append("\n**Important:** This scan will ONLY test the specific request provided.\n");
            return createTextResponse(result.toString());
            
        } catch (Exception e) {
            return createErrorResponse("Failed to start specific request scan: " + e.getMessage());
        }
    }
    
    /**
     * Resolve insertion points from insertionPoints, insertionPointValues, and insertionPointParams.
     * Returns a combined list of Range objects. Logs what was resolved to the result StringBuilder.
     */
    /**
     * Get a JsonNode as an array, handling the case where the LLM sends a JSON string
     * like "[\"category\"]" instead of an actual array ["category"].
     */
    private JsonNode getAsArray(JsonNode arguments, String fieldName) {
        if (!arguments.has(fieldName)) return null;
        JsonNode node = arguments.get(fieldName);
        if (node.isArray()) return node;
        // Try parsing string as JSON array
        if (node.isTextual()) {
            try {
                JsonNode parsed = new com.fasterxml.jackson.databind.ObjectMapper().readTree(node.asText());
                if (parsed.isArray()) return parsed;
            } catch (Exception ignored) {}
        }
        return null;
    }

    private List<Range> resolveInsertionPoints(String requestStr, JsonNode arguments, StringBuilder result) {
        List<Range> ranges = new ArrayList<>();

        // 1. Explicit byte offset ranges
        if (arguments.has("insertionPoints")) {
            JsonNode pointsNode = arguments.get("insertionPoints");
            for (JsonNode point : pointsNode) {
                int start = point.get("start").asInt();
                int end = point.get("end").asInt();
                ranges.add(Range.range(start, end));
            }
        }

        // Normalize request for searching (same normalization as buildScanRequest)
        String normalized = requestStr.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\r\n");

        // 2. Find insertion points by value strings
        JsonNode valuesNode = getAsArray(arguments, "insertionPointValues");
        if (valuesNode != null) {
            for (JsonNode valueNode : valuesNode) {
                String value = valueNode.asText();
                int idx = normalized.indexOf(value);
                if (idx >= 0) {
                    ranges.add(Range.range(idx, idx + value.length()));
                    result.append("📍 Insertion point for value \"").append(value)
                          .append("\" at bytes ").append(idx).append("-").append(idx + value.length()).append("\n");
                } else {
                    result.append("⚠️ Value \"").append(value).append("\" not found in request\n");
                }
            }
        }

        // 3. Find insertion points by parameter name (URL query, form body, JSON)
        JsonNode paramsNode = getAsArray(arguments, "insertionPointParams");
        if (paramsNode != null) {
            for (JsonNode paramNode : paramsNode) {
                String paramName = paramNode.asText();
                boolean found = false;

                // Try URL query param: name=value (& or end-of-string terminated)
                String queryPattern = paramName + "=";
                int idx = normalized.indexOf(queryPattern);
                while (idx >= 0 && !found) {
                    int valueStart = idx + queryPattern.length();
                    // Value ends at & or space or \r or end
                    int valueEnd = valueStart;
                    while (valueEnd < normalized.length()) {
                        char c = normalized.charAt(valueEnd);
                        if (c == '&' || c == ' ' || c == '\r' || c == '\n' || c == '#') break;
                        valueEnd++;
                    }
                    if (valueEnd > valueStart) {
                        ranges.add(Range.range(valueStart, valueEnd));
                        String paramValue = normalized.substring(valueStart, valueEnd);
                        result.append("📍 Insertion point for param \"").append(paramName)
                              .append("\" = \"").append(paramValue)
                              .append("\" at bytes ").append(valueStart).append("-").append(valueEnd).append("\n");
                        found = true;
                    }
                    idx = normalized.indexOf(queryPattern, valueEnd);
                }

                // Try JSON: "name": "value" or "name":"value"
                if (!found) {
                    String jsonPattern1 = "\"" + paramName + "\":\"";
                    String jsonPattern2 = "\"" + paramName + "\": \"";
                    for (String jp : new String[]{jsonPattern1, jsonPattern2}) {
                        idx = normalized.indexOf(jp);
                        if (idx >= 0) {
                            int valueStart = idx + jp.length();
                            int valueEnd = normalized.indexOf("\"", valueStart);
                            if (valueEnd > valueStart) {
                                ranges.add(Range.range(valueStart, valueEnd));
                                String paramValue = normalized.substring(valueStart, valueEnd);
                                result.append("📍 Insertion point for JSON param \"").append(paramName)
                                      .append("\" = \"").append(paramValue)
                                      .append("\" at bytes ").append(valueStart).append("-").append(valueEnd).append("\n");
                                found = true;
                                break;
                            }
                        }
                    }
                }

                if (!found) {
                    result.append("⚠️ Parameter \"").append(paramName).append("\" not found in request\n");
                }
            }
        }

        return ranges;
    }

    /**
     * Build an HttpRequest with a proper HttpService from a raw request string.
     * Parses host/port from the Host header if not provided as arguments.
     * Normalizes absolute-form URLs to origin-form.
     * Requires useHttps to be set explicitly.
     */
    private HttpRequest buildScanRequest(String requestStr, JsonNode arguments) {
        // Normalize line endings to CRLF
        requestStr = requestStr.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\r\n");

        String[] lines = requestStr.split("\r\n", -1);

        // Normalize absolute-form URL to origin-form (e.g. GET https://host/path -> GET /path)
        if (lines.length > 0) {
            String[] parts = lines[0].split(" ", 3);
            if (parts.length >= 2) {
                String url = parts[1];
                String lowerUrl = url.toLowerCase();
                if (lowerUrl.startsWith("https://") || lowerUrl.startsWith("http://")) {
                    int schemeSeparator = url.indexOf("://");
                    String afterScheme = url.substring(schemeSeparator + 3);
                    int slashIndex = afterScheme.indexOf('/');
                    parts[1] = slashIndex >= 0 ? afterScheme.substring(slashIndex) : "/";
                    lines[0] = String.join(" ", parts);
                }
            }
        }

        // Extract Host header
        String hostHeader = null;
        for (String line : lines) {
            if (line.toLowerCase().startsWith("host:")) {
                hostHeader = line.substring(5).trim();
                break;
            }
        }

        // Determine host: argument > Host header
        String host = arguments.has("host") ? arguments.get("host").asText() : null;
        if ((host == null || host.isEmpty()) && hostHeader != null) {
            // Parse host from Host header (strip port if present)
            int colonIdx = hostHeader.lastIndexOf(':');
            if (colonIdx > 0) {
                String potentialPort = hostHeader.substring(colonIdx + 1);
                if (potentialPort.matches("\\d+")) {
                    host = hostHeader.substring(0, colonIdx);
                } else {
                    host = hostHeader;
                }
            } else {
                host = hostHeader;
            }
        }
        if (host == null || host.isEmpty()) {
            throw new IllegalArgumentException("Cannot determine target host: provide 'host' parameter or include a Host header in the request");
        }

        // Determine useHttps — required, no default
        if (!arguments.has("useHttps")) {
            throw new IllegalArgumentException("useHttps is required — set to true for HTTPS or false for HTTP");
        }
        boolean secure = arguments.get("useHttps").asBoolean();

        // Determine port: argument > Host header > default from scheme
        int port;
        if (arguments.has("port")) {
            port = arguments.get("port").asInt();
        } else if (hostHeader != null && hostHeader.lastIndexOf(':') > 0) {
            String potentialPort = hostHeader.substring(hostHeader.lastIndexOf(':') + 1);
            if (potentialPort.matches("\\d+")) {
                port = Integer.parseInt(potentialPort);
            } else {
                port = secure ? 443 : 80;
            }
        } else {
            port = secure ? 443 : 80;
        }

        requestStr = String.join("\r\n", lines);
        HttpService service = HttpService.httpService(host, port, secure);
        return HttpRequest.httpRequest(service, requestStr);
    }

    private List<Map<String, Object>> createTextResponse(String text) {
        // Return the content array directly, not wrapped in a Map
        List<Map<String, Object>> content = new ArrayList<>();
        Map<String, Object> textContent = new HashMap<>();
        textContent.put("type", "text");
        textContent.put("text", text);
        content.add(textContent);
        return content;
    }
    
    private List<Map<String, Object>> createErrorResponse(String error) {
        // Return the content array directly, not wrapped in a Map
        List<Map<String, Object>> content = new ArrayList<>();
        Map<String, Object> textContent = new HashMap<>();
        textContent.put("type", "text");
        textContent.put("text", "❌ Error: " + error);
        content.add(textContent);
        // Note: isError flag is lost here, but MCP can detect errors from the ❌ prefix
        return content;
    }

    private Object crawlOnly(JsonNode arguments, Scanner scanner) {
        JsonNode urlsNode = arguments.get("urls");
        if (urlsNode == null || !urlsNode.isArray() || urlsNode.size() == 0) {
            return createErrorResponse("URLs array is required for CRAWL_ONLY");
        }

        List<String> urls = new ArrayList<>();
        for (JsonNode urlNode : urlsNode) {
            urls.add(urlNode.asText());
        }

        // Generate crawl ID
        String crawlId = "crawl_" + System.currentTimeMillis();

        try {
            // Create crawl configuration
            CrawlConfiguration crawlConfig = CrawlConfiguration.crawlConfiguration();

            // Start crawl (no audit)
            Crawl crawl = scanner.startCrawl(crawlConfig);

            // Track the crawl
            activeCrawls.put(crawlId, crawl);
            scanMetadata.put(crawlId, new ScanMetadata(crawlId, "CRAWL", "PASSIVE", "DEFAULT", urls));

            String started = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
            if (!McpUtils.isVerbose(arguments)) {
                Map<String, Object> data = new HashMap<>();
                data.put("crawlId", crawlId);
                data.put("targetUrls", urls);
                data.put("status", "crawling");
                data.put("started", started);
                return McpUtils.createJsonResponse(data);
            }

            StringBuilder result = new StringBuilder();
            result.append("🕷️ **CRAWL STARTED**\n");
            result.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");
            result.append(String.format("**Crawl ID**: %s\n", crawlId));
            result.append(String.format("**Target URLs**: %d\n", urls.size()));
            for (String url : urls) {
                result.append(String.format("  - %s\n", url));
            }
            result.append("\n**Status**: Crawling in progress\n");
            result.append(String.format("**Started**: %s\n\n", started));
            result.append("💡 Use GET_STATUS with this crawlId to monitor progress\n");
            return createTextResponse(result.toString());

        } catch (Exception e) {
            api.logging().logToError("Crawl error: " + e.getMessage());
            return createErrorResponse("Failed to start crawl: " + e.getMessage());
        }
    }

    private Object getScanMetrics(JsonNode arguments) {
        // Overall statistics
        int totalAudits = activeAudits.size();
        int totalCrawls = activeCrawls.size();
        int totalRequests = 0;
        int totalErrors = 0;
        int totalIssues = 0;

        for (Audit audit : activeAudits.values()) {
            totalRequests += audit.requestCount();
            totalErrors += audit.errorCount();
        }

        try {
            totalIssues = api.siteMap().issues().size();
        } catch (Exception e) {
            api.logging().logToError("Cannot get issues from siteMap: " + e.getMessage());
        }

        // Per-scan details
        List<Map<String, Object>> perScan = new ArrayList<>();
        for (Map.Entry<String, Audit> entry : activeAudits.entrySet()) {
            Audit audit = entry.getValue();
            ScanMetadata metadata = scanMetadata.get(entry.getKey());
            Map<String, Object> s = new HashMap<>();
            s.put("scanId", entry.getKey());
            s.put("requestCount", audit.requestCount());
            s.put("errorCount", audit.errorCount());
            s.put("insertionPointCount", audit.insertionPointCount());
            if (metadata != null) {
                s.put("mode", metadata.mode);
                s.put("started", metadata.startTime.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
            }
            perScan.add(s);
        }

        if (!McpUtils.isVerbose(arguments)) {
            Map<String, Object> data = new HashMap<>();
            data.put("activeAudits", totalAudits);
            data.put("activeCrawls", totalCrawls);
            data.put("totalRequests", totalRequests);
            data.put("totalErrors", totalErrors);
            data.put("totalIssues", totalIssues);
            data.put("scans", perScan);
            return McpUtils.createJsonResponse(data);
        }

        StringBuilder result = new StringBuilder();
        result.append("📈 **SCAN METRICS & ANALYTICS**\n");
        result.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");
        result.append("## 📊 Overall Statistics\n");
        result.append(String.format("- **Active Audits**: %d\n", totalAudits));
        result.append(String.format("- **Active Crawls**: %d\n", totalCrawls));
        result.append(String.format("- **Total Requests**: %d\n", totalRequests));
        result.append(String.format("- **Total Errors**: %d\n", totalErrors));
        result.append(String.format("- **Total Issues Found**: %d\n\n", totalIssues));
        if (!perScan.isEmpty()) {
            result.append("## 🔍 Active Scan Details\n\n");
            for (Map<String, Object> s : perScan) {
                result.append(String.format("### Scan: %s\n", s.get("scanId")));
                result.append(String.format("- Requests: %s\n", s.get("requestCount")));
                result.append(String.format("- Errors: %s\n", s.get("errorCount")));
                result.append(String.format("- Insertion Points: %s\n", s.get("insertionPointCount")));
                if (s.containsKey("mode")) result.append(String.format("- Mode: %s\n", s.get("mode")));
                if (s.containsKey("started")) result.append(String.format("- Started: %s\n", s.get("started")));
                result.append("\n");
            }
        }
        return createTextResponse(result.toString());
    }

    private Object getFilteredIssues(JsonNode arguments) {
        try {
            List<AuditIssue> issues = new ArrayList<>(applyIssueFilters(api.siteMap().issues(), arguments));
            sortIssuesBySeverity(issues);

            String title = "Site Map Issues";
            boolean verbose = McpUtils.isVerbose(arguments);

            // Detail mode if issueIndex is provided
            if (arguments.has("issueIndex") && arguments.get("issueIndex").isArray()) {
                List<Integer> indices = new ArrayList<>();
                arguments.get("issueIndex").forEach(node -> indices.add(node.asInt()));
                return formatIssueDetail(issues, indices, title, verbose);
            }

            // Summary mode with pagination
            int limit = arguments.has("limit") ? arguments.get("limit").asInt() : 50;
            int offset = arguments.has("offset") ? arguments.get("offset").asInt() : 0;
            return formatIssueSummary(issues, limit, offset, title, verbose);

        } catch (Exception e) {
            return createErrorResponse("Failed to retrieve filtered issues: " + e.getMessage());
        }
    }

    /**
     * Build HTTP request with custom headers and cookies from arguments
     * If useProxySession=true, automatically extracts session from proxy history
     */
    private HttpRequest buildRequestWithHeaders(String url, JsonNode arguments) {
        HttpRequest request;

        // Option 1: Use proxy history to get authenticated request (default behavior)
        boolean useProxySession = !arguments.has("useProxySession") || arguments.get("useProxySession").asBoolean();

        if (useProxySession) {
            // Try to get the most recent valid request from proxy history for this URL
            HttpRequest proxyRequest = getLatestProxyRequest(url);
            if (proxyRequest != null) {
                api.logging().logToOutput("Scanner: Using authenticated request from proxy history for " + url);
                request = proxyRequest;
            } else {
                // Fallback to basic request
                api.logging().logToOutput("Scanner: No proxy history found for " + url + ", using basic request");
                request = HttpRequest.httpRequestFromUrl(url);
            }
        } else {
            // Start with basic request from URL
            request = HttpRequest.httpRequestFromUrl(url);
        }

        // Override with custom headers if provided
        if (arguments.has("headers") && arguments.get("headers").isObject()) {
            JsonNode headersNode = arguments.get("headers");
            Iterator<Map.Entry<String, JsonNode>> iter = headersNode.fields();
            while (iter.hasNext()) {
                Map.Entry<String, JsonNode> entry = iter.next();
                String headerName = entry.getKey();
                String headerValue = entry.getValue().asText();
                request = request.withUpdatedHeader(headerName, headerValue);
            }
        }

        // Override with custom cookies if provided
        if (arguments.has("cookies") && arguments.get("cookies").isObject()) {
            JsonNode cookiesNode = arguments.get("cookies");
            StringBuilder cookieHeader = new StringBuilder();

            Iterator<Map.Entry<String, JsonNode>> iter = cookiesNode.fields();
            while (iter.hasNext()) {
                Map.Entry<String, JsonNode> entry = iter.next();
                if (cookieHeader.length() > 0) {
                    cookieHeader.append("; ");
                }
                cookieHeader.append(entry.getKey()).append("=").append(entry.getValue().asText());
            }

            if (cookieHeader.length() > 0) {
                request = request.withUpdatedHeader("Cookie", cookieHeader.toString());
            }
        }

        return request;
    }

    /**
     * Get the most recent request from proxy history for a given URL
     * This ensures scans use authenticated sessions automatically
     */
    private HttpRequest getLatestProxyRequest(String targetUrl) {
        try {
            // Parse target URL to get host and path
            java.net.URL url = new java.net.URL(targetUrl);
            String targetHost = url.getHost();
            String targetPath = url.getPath();
            if (targetPath.isEmpty()) {
                targetPath = "/";
            }

            // Search proxy history (most recent first)
            List<burp.api.montoya.proxy.ProxyHttpRequestResponse> proxyHistory = api.proxy().history();

            for (int i = proxyHistory.size() - 1; i >= 0; i--) {
                burp.api.montoya.proxy.ProxyHttpRequestResponse item = proxyHistory.get(i);
                HttpRequest request = item.request();

                // Match by host and path
                if (request.url().startsWith(targetUrl) ||
                    (request.httpService().host().equals(targetHost) && request.path().startsWith(targetPath))) {

                    // Found a matching request - validate session is still active
                    if (isSessionValid(item)) {
                        return request;
                    }
                }
            }
        } catch (Exception e) {
            api.logging().logToError("Error extracting request from proxy history: " + e.getMessage());
        }

        return null;
    }

    /**
     * Validate that a session is still active by checking response status
     * Returns false if response indicates session expired (401, 403, redirects to login, etc.)
     */
    private boolean isSessionValid(burp.api.montoya.proxy.ProxyHttpRequestResponse item) {
        if (item.response() == null) {
            return false;
        }

        short statusCode = item.response().statusCode();

        // Check for authentication failures
        if (statusCode == 401 || statusCode == 403) {
            return false;
        }

        // Check for redirects to login pages
        if (statusCode >= 300 && statusCode < 400) {
            String location = item.response().headerValue("Location");
            if (location != null &&
                (location.toLowerCase().contains("login") ||
                 location.toLowerCase().contains("signin") ||
                 location.toLowerCase().contains("auth"))) {
                return false;
            }
        }

        // Check response body for common session expiry indicators
        String responseBody = item.response().bodyToString().toLowerCase();
        if (responseBody.contains("session expired") ||
            responseBody.contains("please log in") ||
            responseBody.contains("please sign in")) {
            return false;
        }

        return true;
    }
}
