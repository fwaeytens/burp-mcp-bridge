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
            "Supports authenticated scanning via headers/cookies parameters. Use insertionPoints for targeted parameter testing.");

        // MCP 2025-06-18 annotations
        Map<String, Object> annotations = new HashMap<>();
        annotations.put("readOnlyHint", false);
        annotations.put("destructiveHint", false);
        annotations.put("idempotentHint", false);
        annotations.put("openWorldHint", true);
        tool.put("annotations", annotations);
        
        Map<String, Object> inputSchema = new HashMap<>();
        inputSchema.put("type", "object");
        
        Map<String, Object> properties = new HashMap<>();
        
        // Action property
        Map<String, Object> actionProperty = new HashMap<>();
        actionProperty.put("type", "string");
        actionProperty.put("description", "Scanner action to perform");
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
        requestProperty.put("description", "HTTP request to add to scan");
        properties.put("request", requestProperty);
        
        // Insertion points for ADD_TO_SCAN
        Map<String, Object> insertionPointsProperty = new HashMap<>();
        insertionPointsProperty.put("type", "array");
        insertionPointsProperty.put("description", "Insertion point ranges [{start: int, end: int}]");
        properties.put("insertionPoints", insertionPointsProperty);
        
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
        
        // BCheck definition
        Map<String, Object> bcheckProperty = new HashMap<>();
        bcheckProperty.put("type", "string");
        bcheckProperty.put("description", "BCheck definition YAML");
        properties.put("definition", bcheckProperty);
        
        // Auto-enable for BCheck
        Map<String, Object> autoEnableProperty = new HashMap<>();
        autoEnableProperty.put("type", "boolean");
        autoEnableProperty.put("description", "Auto-enable imported BCheck");
        
        // Properties for SCAN_SPECIFIC_REQUEST
        Map<String, Object> hostProperty = new HashMap<>();
        hostProperty.put("type", "string");
        hostProperty.put("description", "Target host for SCAN_SPECIFIC_REQUEST");
        properties.put("host", hostProperty);
        
        Map<String, Object> portProperty = new HashMap<>();
        portProperty.put("type", "integer");
        portProperty.put("description", "Target port (default: 80 for HTTP, 443 for HTTPS)");
        properties.put("port", portProperty);
        
        Map<String, Object> useHttpsProperty = new HashMap<>();
        useHttpsProperty.put("type", "boolean");
        useHttpsProperty.put("description", "Use HTTPS (default: false)");
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
        
        tool.put("inputSchema", inputSchema);
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
                    return listActiveScans();
                
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
        
        StringBuilder result = new StringBuilder();
        result.append("🔍 **Scan Initiated**\n");
        result.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");
        
        // Start audit
        try {
            Audit audit = scanner.startAudit(auditConfig);
            activeAudits.put(scanId, audit);
            
            // Add URLs to audit
            int successCount = 0;
            for (String url : urls) {
                try {
                    HttpRequest request = buildRequestWithHeaders(url, arguments);
                    audit.addRequest(request);
                    successCount++;
                } catch (Exception e) {
                    result.append("⚠️ Failed to add URL: ").append(url).append("\n");
                    result.append("   Error: ").append(e.getMessage()).append("\n");
                }
            }
            
            result.append("**Scan Details:**\n");
            result.append("• **Scan ID:** `").append(scanId).append("`\n");
            result.append("• **Type:** ").append(mode).append(" Audit\n");
            result.append("• **Configuration:** ").append(config).append("\n");
            result.append("• **URLs Added:** ").append(successCount).append("/").append(urls.size()).append("\n");
            
            // Store metadata
            scanMetadata.put(scanId, new ScanMetadata(scanId, "AUDIT", mode, config, urls));
            
            // Start crawl if requested
            String crawlId = null;
            if (doCrawl && successCount > 0) {
                try {
                    String[] seedUrls = urls.toArray(new String[0]);
                    CrawlConfiguration crawlConfig = CrawlConfiguration.crawlConfiguration(seedUrls);
                    Crawl crawl = scanner.startCrawl(crawlConfig);
                    
                    crawlId = UUID.randomUUID().toString();
                    activeCrawls.put(crawlId, crawl);
                    scanMetadata.put(crawlId, new ScanMetadata(crawlId, "CRAWL", "N/A", "N/A", urls));
                    
                    result.append("• **Crawl ID:** `").append(crawlId).append("`\n");
                    result.append("• **Crawl Status:** Started\n");
                } catch (Exception e) {
                    result.append("• **Crawl:** Failed - ").append(e.getMessage()).append("\n");
                }
            }
            
            result.append("\n**Target URLs:**\n");
            for (String url : urls) {
                result.append("• ").append(url).append("\n");
            }
            
            result.append("\n**Next Steps:**\n");
            result.append("• Use `GET_STATUS` with scan ID to check progress\n");
            result.append("• Use `GET_ISSUES` with scan ID to retrieve findings\n");
            result.append("• Use `ADD_TO_SCAN` to add more targets\n");
            result.append("• Use `CANCEL_SCAN` to stop the scan\n");
            
            // Return scan metadata
            Map<String, Object> response = new HashMap<>();
            response.put("scanId", scanId);
            if (crawlId != null) {
                response.put("crawlId", crawlId);
            }
            response.put("status", "STARTED");
            response.put("message", result.toString());
            
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
        
        StringBuilder result = new StringBuilder();
        result.append("📊 **Scan Status Report**\n");
        result.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");
        
        // Check if it's an audit
        Audit audit = activeAudits.get(scanId);
        if (audit != null) {
            ScanMetadata metadata = scanMetadata.get(scanId);
            
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
            
            result.append("**Crawl Information:**\n");
            result.append("• **ID:** `").append(scanId).append("`\n");
            result.append("• **Type:** Crawl\n");
            if (metadata != null) {
                result.append("• **Started:** ").append(metadata.startTime.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME)).append("\n");
            }
            
            result.append("\n**Progress Metrics:**\n");
            result.append("• **Requests Made:** ").append(crawl.requestCount()).append("\n");
            result.append("• **Errors Encountered:** ").append(crawl.errorCount()).append("\n");

            // Try to get status - statusMessage() throws UnsupportedOperationException in some Burp versions
            String status = "Running";
            try {
                String statusMsg = crawl.statusMessage();
                if (statusMsg != null && !statusMsg.isEmpty()) {
                    status = statusMsg;
                }
            } catch (UnsupportedOperationException e) {
                // Burp hasn't implemented statusMessage() for crawls yet
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
            // Note: audit.issues() may not be supported in all Burp versions
            // Fallback to siteMap issues if needed
            List<AuditIssue> issues;
            try {
                issues = audit.issues();
            } catch (UnsupportedOperationException e) {
                api.logging().logToOutput("Note: audit.issues() not supported, using siteMap.issues() instead");
                issues = api.siteMap().issues();
            }

            StringBuilder result = new StringBuilder();
            result.append("🔒 **Security Issues Report**\n");
            result.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
            result.append("**Scan ID:** `").append(scanId).append("`\n");
            result.append("**Total Issues:** ").append(issues.size()).append("\n\n");
            
            if (issues.isEmpty()) {
                result.append("✅ No security issues found yet.\n");
                result.append("\nNote: Scan may still be in progress. Use GET_STATUS to check.\n");
            } else {
                // Group issues by severity
                Map<AuditIssueSeverity, List<AuditIssue>> bySeverity = issues.stream()
                    .collect(Collectors.groupingBy(AuditIssue::severity));
                
                // Sort by severity (HIGH -> MEDIUM -> LOW -> INFO)
                List<AuditIssueSeverity> severityOrder = Arrays.asList(
                    AuditIssueSeverity.HIGH,
                    AuditIssueSeverity.MEDIUM,
                    AuditIssueSeverity.LOW,
                    AuditIssueSeverity.INFORMATION
                );
                
                for (AuditIssueSeverity severity : severityOrder) {
                    List<AuditIssue> severityIssues = bySeverity.get(severity);
                    if (severityIssues != null && !severityIssues.isEmpty()) {
                        String icon = getSeverityIcon(severity.name());
                        result.append("## ").append(icon).append(" ").append(severity.name())
                            .append(" (").append(severityIssues.size()).append(")\n\n");
                        
                        for (AuditIssue issue : severityIssues) {
                            result.append("### ").append(issue.name()).append("\n");
                            result.append("**URL:** ").append(issue.baseUrl()).append("\n");
                            result.append("**Confidence:** ").append(issue.confidence().name()).append("\n");
                            
                            // Add detail if available
                            String detail = issue.detail();
                            if (detail != null && !detail.isEmpty()) {
                                // Truncate if too long
                                if (detail.length() > 500) {
                                    detail = detail.substring(0, 497) + "...";
                                }
                                result.append("**Details:** ").append(detail).append("\n");
                            }
                            
                            result.append("\n");
                        }
                    }
                }
                
                result.append("## Summary\n");
                result.append("Use GENERATE_REPORT action to export full details to HTML/XML.\n");
            }
            
            return createTextResponse(result.toString());
            
        } catch (Exception e) {
            return createErrorResponse("Failed to retrieve issues: " + e.getMessage());
        }
    }
    
    private Object cancelScan(JsonNode arguments) {
        String scanId = arguments.has("scanId") ? arguments.get("scanId").asText() : null;
        if (scanId == null || scanId.isEmpty()) {
            return createErrorResponse("scanId is required for CANCEL_SCAN");
        }
        
        StringBuilder result = new StringBuilder();
        boolean found = false;
        
        // Try to cancel audit
        Audit audit = activeAudits.get(scanId);
        if (audit != null) {
            try {
                audit.delete();
                activeAudits.remove(scanId);
                scanMetadata.remove(scanId);
                result.append("✅ Successfully cancelled audit scan: ").append(scanId).append("\n");
                found = true;
            } catch (Exception e) {
                result.append("❌ Failed to cancel audit: ").append(e.getMessage()).append("\n");
            }
        }
        
        // Try to cancel crawl
        Crawl crawl = activeCrawls.get(scanId);
        if (crawl != null) {
            try {
                crawl.delete();
                activeCrawls.remove(scanId);
                scanMetadata.remove(scanId);
                result.append("✅ Successfully cancelled crawl: ").append(scanId).append("\n");
                found = true;
            } catch (Exception e) {
                result.append("❌ Failed to cancel crawl: ").append(e.getMessage()).append("\n");
            }
        }
        
        if (!found) {
            return createErrorResponse("No active scan found with ID: " + scanId);
        }
        
        return createTextResponse(result.toString());
    }
    
    private Object listActiveScans() {
        StringBuilder result = new StringBuilder();
        result.append("📋 **Active Scans**\n");
        result.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");
        
        if (activeAudits.isEmpty() && activeCrawls.isEmpty()) {
            result.append("No active scans.\n");
        } else {
            if (!activeAudits.isEmpty()) {
                result.append("## Active Audits\n");
                for (Map.Entry<String, Audit> entry : activeAudits.entrySet()) {
                    String id = entry.getKey();
                    Audit audit = entry.getValue();
                    ScanMetadata metadata = scanMetadata.get(id);
                    
                    result.append("• **ID:** `").append(id).append("`\n");
                    if (metadata != null) {
                        result.append("  **Type:** ").append(metadata.mode).append("\n");
                        result.append("  **Started:** ").append(metadata.startTime.format(DateTimeFormatter.ISO_LOCAL_TIME)).append("\n");
                    }
                    result.append("  **Requests:** ").append(audit.requestCount()).append("\n");
                    try {
                        result.append("  **Issues:** ").append(audit.issues().size()).append("\n");
                    } catch (Exception e) {
                        result.append("  **Issues:** N/A (").append(e.getMessage()).append(")\n");
                    }
                    result.append("\n");
                }
            }
            
            if (!activeCrawls.isEmpty()) {
                result.append("## Active Crawls\n");
                for (Map.Entry<String, Crawl> entry : activeCrawls.entrySet()) {
                    String id = entry.getKey();
                    Crawl crawl = entry.getValue();
                    ScanMetadata metadata = scanMetadata.get(id);
                    
                    result.append("• **ID:** `").append(id).append("`\n");
                    if (metadata != null) {
                        result.append("  **Started:** ").append(metadata.startTime.format(DateTimeFormatter.ISO_LOCAL_TIME)).append("\n");
                    }
                    result.append("  **Requests:** ").append(crawl.requestCount()).append("\n");
                    result.append("  **Errors:** ").append(crawl.errorCount()).append("\n");
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
        
        StringBuilder result = new StringBuilder();
        
        // Check if we're adding a URL or raw request
        if (arguments.has("urls")) {
            JsonNode urlsNode = arguments.get("urls");
            int added = 0;
            
            for (JsonNode urlNode : urlsNode) {
                try {
                    String url = urlNode.asText();
                    HttpRequest request = HttpRequest.httpRequestFromUrl(url);
                    audit.addRequest(request);
                    added++;
                } catch (Exception e) {
                    result.append("⚠️ Failed to add URL: ").append(urlNode.asText()).append("\n");
                }
            }
            
            result.append("✅ Added ").append(added).append(" URL(s) to scan ").append(scanId).append("\n");
        }
        
        // Check for raw request with optional insertion points
        if (arguments.has("request")) {
            String requestStr = arguments.get("request").asText();
            
            try {
                // Parse the raw request
                HttpRequest request = HttpRequest.httpRequest(requestStr);
                
                // Check for insertion points
                if (arguments.has("insertionPoints")) {
                    List<Range> ranges = new ArrayList<>();
                    JsonNode pointsNode = arguments.get("insertionPoints");
                    
                    for (JsonNode point : pointsNode) {
                        int start = point.get("start").asInt();
                        int end = point.get("end").asInt();
                        ranges.add(Range.range(start, end));
                    }
                    
                    audit.addRequest(request, ranges);
                    result.append("✅ Added request with ").append(ranges.size()).append(" insertion points\n");
                } else {
                    audit.addRequest(request);
                    result.append("✅ Added request to scan\n");
                }
            } catch (Exception e) {
                return createErrorResponse("Failed to add request: " + e.getMessage());
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
            
            StringBuilder result = new StringBuilder();
            result.append("📄 **Report Generated Successfully**\n");
            result.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");
            result.append("**Format:** ").append(format).append("\n");
            result.append("**Issues Included:** ").append(issues.size()).append("\n");
            result.append("**File Location:** `").append(outputPath).append("`\n");
            result.append("\n");
            
            // Add summary
            Map<String, Long> severityCount = issues.stream()
                .collect(Collectors.groupingBy(
                    issue -> issue.severity().name(),
                    Collectors.counting()
                ));
            
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
            
            StringBuilder response = new StringBuilder();
            response.append("🔧 **BCheck Import Result**\n");
            response.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");
            
            BCheckImportResult.Status status = result.status();
            if (status == BCheckImportResult.Status.LOADED_WITHOUT_ERRORS) {
                response.append("✅ **Status:** Successfully imported without errors\n");
                response.append("**Auto-enabled:** ").append(autoEnable ? "Yes" : "No").append("\n");
            } else if (status == BCheckImportResult.Status.LOADED_WITH_ERRORS) {
                response.append("⚠️ **Status:** Imported with errors\n");
                response.append("**Auto-enabled:** ").append(autoEnable ? "Yes" : "No").append("\n");
                
                List<String> errors = result.importErrors();
                if (errors != null && !errors.isEmpty()) {
                    response.append("\n**Errors/Warnings:**\n");
                    for (String error : errors) {
                        response.append("• ").append(error).append("\n");
                    }
                }
            } else {
                response.append("❌ **Status:** Import failed\n");
                
                List<String> errors = result.importErrors();
                if (errors != null && !errors.isEmpty()) {
                    response.append("\n**Errors:**\n");
                    for (String error : errors) {
                        response.append("• ").append(error).append("\n");
                    }
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
        
        if (scanId != null && !scanId.isEmpty()) {
            // Clear specific scan
            Audit audit = activeAudits.remove(scanId);
            Crawl crawl = activeCrawls.remove(scanId);
            scanMetadata.remove(scanId);
            
            if (audit != null || crawl != null) {
                return createTextResponse("✅ Cleared scan data for ID: " + scanId);
            } else {
                return createErrorResponse("No scan found with ID: " + scanId);
            }
        } else {
            // Clear all completed scans (keep running ones)
            int cleared = 0;
            
            // Check and clear completed audits
            List<String> toRemove = new ArrayList<>();
            for (Map.Entry<String, Audit> entry : activeAudits.entrySet()) {
                try {
                    String status = entry.getValue().statusMessage();
                    // If status indicates completion, mark for removal
                    if (status != null && (status.toLowerCase().contains("complete") || 
                                          status.toLowerCase().contains("finished"))) {
                        toRemove.add(entry.getKey());
                    }
                } catch (Exception e) {
                    // Skip if we can't check status
                }
            }
            
            for (String id : toRemove) {
                activeAudits.remove(id);
                scanMetadata.remove(id);
                cleared++;
            }
            
            return createTextResponse("✅ Cleared " + cleared + " completed scan(s). Active scans preserved.");
        }
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
        
        String host = arguments.has("host") ? arguments.get("host").asText() : null;
        if (host == null || host.isEmpty()) {
            return createErrorResponse("host parameter is required for SCAN_SPECIFIC_REQUEST");
        }
        
        // Optional parameters with defaults
        int port = arguments.has("port") ? arguments.get("port").asInt() : -1;
        boolean useHttps = arguments.has("useHttps") ? arguments.get("useHttps").asBoolean() : false;
        
        // Auto-detect port if not specified
        if (port == -1) {
            port = useHttps ? 443 : 80;
        }
        
        String mode = arguments.has("mode") ? arguments.get("mode").asText().toUpperCase() : "ACTIVE";
        String config = arguments.has("config") ? arguments.get("config").asText().toUpperCase() : "MEDIUM";
        
        try {
            // Create HttpService and HttpRequest
            HttpService service = HttpService.httpService(host, port, useHttps);
            HttpRequest request = HttpRequest.httpRequest(service, requestStr);
            
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
            
            // Add the specific request (without insertion points to scan all positions)
            audit.addRequest(request);
            
            // Store metadata
            List<String> urls = new ArrayList<>();
            urls.add(String.format("%s://%s:%d%s", 
                useHttps ? "https" : "http", 
                host, 
                port,
                request.path()));
            scanMetadata.put(scanId, new ScanMetadata(scanId, "AUDIT", mode, config, urls));
            
            // Build response
            StringBuilder result = new StringBuilder();
            result.append("🎯 **Single Request Scan Initiated**\n");
            result.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");
            result.append("**Scan Details:**\n");
            result.append("• **Scan ID:** `").append(scanId).append("`\n");
            result.append("• **Type:** ").append(mode).append(" Audit (Single Request)\n");
            result.append("• **Configuration:** ").append(config).append("\n");
            result.append("• **Target:** ").append(host).append(":").append(port).append("\n");
            result.append("• **Protocol:** ").append(useHttps ? "HTTPS" : "HTTP").append("\n");
            result.append("• **Method:** ").append(request.method()).append("\n");
            result.append("• **Path:** ").append(request.path()).append("\n");
            result.append("\n**Important:** This scan will ONLY test the specific request provided.\n");
            result.append("It will NOT follow links or spider to other pages.\n");
            result.append("\n**Next Steps:**\n");
            result.append("• Use `GET_STATUS` with scan ID to check progress\n");
            result.append("• Use `GET_ISSUES` with scan ID to retrieve findings\n");
            result.append("• Use `CANCEL_SCAN` to stop the scan\n");
            
            return createTextResponse(result.toString());
            
        } catch (Exception e) {
            return createErrorResponse("Failed to start specific request scan: " + e.getMessage());
        }
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

            StringBuilder result = new StringBuilder();
            result.append("🕷️ **CRAWL STARTED**\n");
            result.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");
            result.append(String.format("**Crawl ID**: %s\n", crawlId));
            result.append(String.format("**Target URLs**: %d\n", urls.size()));
            for (String url : urls) {
                result.append(String.format("  - %s\n", url));
            }
            result.append("\n**Status**: Crawling in progress\n");
            result.append(String.format("**Started**: %s\n\n",
                LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))));
            result.append("💡 **Tip**: Use GET_STATUS with this crawlId to monitor progress\n");

            return createTextResponse(result.toString());

        } catch (Exception e) {
            api.logging().logToError("Crawl error: " + e.getMessage());
            return createErrorResponse("Failed to start crawl: " + e.getMessage());
        }
    }

    private Object getScanMetrics(JsonNode arguments) {
        StringBuilder result = new StringBuilder();
        result.append("📈 **SCAN METRICS & ANALYTICS**\n");
        result.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");

        // Overall statistics
        int totalAudits = activeAudits.size();
        int totalCrawls = activeCrawls.size();
        int totalRequests = 0;
        int totalErrors = 0;
        int totalIssues = 0;

        for (Audit audit : activeAudits.values()) {
            totalRequests += audit.requestCount();
            totalErrors += audit.errorCount();
            // Note: audit.issues() is not supported in all Burp versions
            // Use api.siteMap().issues() instead for issue counts
        }

        // Get total issues from siteMap instead of individual audits
        try {
            totalIssues = api.siteMap().issues().size();
        } catch (Exception e) {
            api.logging().logToError("Cannot get issues from siteMap: " + e.getMessage());
        }

        result.append("## 📊 Overall Statistics\n");
        result.append(String.format("- **Active Audits**: %d\n", totalAudits));
        result.append(String.format("- **Active Crawls**: %d\n", totalCrawls));
        result.append(String.format("- **Total Requests**: %d\n", totalRequests));
        result.append(String.format("- **Total Errors**: %d\n", totalErrors));
        result.append(String.format("- **Total Issues Found**: %d\n\n", totalIssues));

        // Per-scan metrics
        if (!activeAudits.isEmpty()) {
            result.append("## 🔍 Active Scan Details\n\n");
            for (Map.Entry<String, Audit> entry : activeAudits.entrySet()) {
                Audit audit = entry.getValue();
                ScanMetadata metadata = scanMetadata.get(entry.getKey());

                result.append(String.format("### Scan: %s\n", entry.getKey()));
                result.append(String.format("- Requests: %d\n", audit.requestCount()));
                result.append(String.format("- Errors: %d\n", audit.errorCount()));
                result.append(String.format("- Insertion Points: %d\n", audit.insertionPointCount()));

                if (metadata != null) {
                    result.append(String.format("- Mode: %s\n", metadata.mode));
                    result.append(String.format("- Started: %s\n", metadata.startTime.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))));
                }

                // Note: Per-scan issue counts not available in all Burp versions
                // Use GET_ISSUES or siteMap for full issue details
                result.append("\n");
            }
        }

        return createTextResponse(result.toString());
    }

    private Object getFilteredIssues(JsonNode arguments) {
        String severityFilter = arguments.has("severity") ? arguments.get("severity").asText().toUpperCase() : null;
        String urlFilter = arguments.has("urlFilter") ? arguments.get("urlFilter").asText() : null;

        List<AuditIssue> allIssues = api.siteMap().issues();
        List<AuditIssue> filteredIssues = new ArrayList<>();

        for (AuditIssue issue : allIssues) {
            // Filter by severity
            if (severityFilter != null) {
                try {
                    AuditIssueSeverity severity = AuditIssueSeverity.valueOf(severityFilter);
                    if (issue.severity() != severity) {
                        continue;
                    }
                } catch (IllegalArgumentException e) {
                    // Invalid severity, skip filter
                }
            }

            // Filter by URL pattern
            if (urlFilter != null && !urlFilter.isEmpty()) {
                String url = issue.baseUrl();
                String pattern = urlFilter.replace("*", ".*");
                if (!url.matches(pattern)) {
                    continue;
                }
            }

            filteredIssues.add(issue);
        }

        StringBuilder result = new StringBuilder();
        result.append("🔍 **FILTERED SCAN ISSUES**\n");
        result.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");

        if (severityFilter != null) {
            result.append(String.format("**Severity Filter**: %s\n", severityFilter));
        }
        if (urlFilter != null) {
            result.append(String.format("**URL Filter**: %s\n", urlFilter));
        }
        result.append(String.format("**Total Matches**: %d\n\n", filteredIssues.size()));

        // Group by severity
        Map<AuditIssueSeverity, List<AuditIssue>> bySeverity = filteredIssues.stream()
            .collect(Collectors.groupingBy(AuditIssue::severity));

        for (AuditIssueSeverity severity : AuditIssueSeverity.values()) {
            List<AuditIssue> issues = bySeverity.get(severity);
            if (issues != null && !issues.isEmpty()) {
                String icon = switch (severity) {
                    case HIGH -> "🔴";
                    case MEDIUM -> "🟠";
                    case LOW -> "🟡";
                    case INFORMATION -> "🔵";
                    case FALSE_POSITIVE -> "⚪";
                };

                result.append(String.format("## %s %s (%d)\n\n", icon, severity, issues.size()));

                for (AuditIssue issue : issues) {
                    result.append(String.format("- **%s**\n", issue.name()));
                    result.append(String.format("  - URL: %s\n", issue.baseUrl()));
                    result.append(String.format("  - Confidence: %s\n", issue.confidence()));
                    result.append("\n");
                }
            }
        }

        return createTextResponse(result.toString());
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
