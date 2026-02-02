package com.example.burpmcp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.handler.TimingData;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.responses.analysis.AttributeType;
import burp.api.montoya.http.message.responses.analysis.ResponseKeywordsAnalyzer;
import burp.api.montoya.http.message.responses.analysis.ResponseVariationsAnalyzer;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.sitemap.SiteMap;
import burp.api.montoya.sitemap.SiteMapFilter;
import burp.api.montoya.sitemap.SiteMapNode;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.net.URL;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Enhanced Site Map Analysis Tool with full Montoya API utilization for comprehensive
 * application structure analysis, technology detection, and security assessment.
 * 
 * Version 1.7.40 - Full Montoya API implementation including:
 * - ResponseKeywordsAnalyzer for variant/invariant keyword detection
 * - ResponseVariationsAnalyzer for dynamic content identification
 * - TimingData for accurate performance metrics
 * - Direct API methods for cleaner code
 * - Annotations support for enhanced metadata
 */
public class SiteMapAnalysisTool implements McpTool {
    private final MontoyaApi api;
    private final SiteMap siteMap;
    private final ObjectMapper objectMapper;
    private static final List<String> SUPPORTED_ACTIONS = List.of(
        "ANALYZE_STRUCTURE",
        "DETECT_TECHNOLOGY",
        "MAP_ATTACK_SURFACE",
        "CONTENT_ANALYSIS",
        "RESPONSE_STATS",
        "CORRELATE_ISSUES",
        "RESPONSE_VARIATIONS",
        "KEYWORD_ANALYSIS",
        "FULL_ANALYSIS",
        "CREATE_ISSUES_FROM_ANALYSIS"
    );
    
    // Patterns for technology detection
    private static final Map<String, Pattern> TECH_PATTERNS = new HashMap<>();
    static {
        TECH_PATTERNS.put("jQuery", Pattern.compile("jquery[-.\\d]*\\.js", Pattern.CASE_INSENSITIVE));
        TECH_PATTERNS.put("React", Pattern.compile("react[-.\\d]*\\.js", Pattern.CASE_INSENSITIVE));
        TECH_PATTERNS.put("Angular", Pattern.compile("angular[-.\\d]*\\.js", Pattern.CASE_INSENSITIVE));
        TECH_PATTERNS.put("Vue.js", Pattern.compile("vue[-.\\d]*\\.js", Pattern.CASE_INSENSITIVE));
        TECH_PATTERNS.put("Bootstrap", Pattern.compile("bootstrap[-.\\d]*\\.(css|js)", Pattern.CASE_INSENSITIVE));
        TECH_PATTERNS.put("WordPress", Pattern.compile("/wp-(content|includes|admin)/", Pattern.CASE_INSENSITIVE));
        TECH_PATTERNS.put("Drupal", Pattern.compile("/sites/(default|all)/", Pattern.CASE_INSENSITIVE));
        TECH_PATTERNS.put("Joomla", Pattern.compile("/components/com_", Pattern.CASE_INSENSITIVE));
        TECH_PATTERNS.put("Laravel", Pattern.compile("/(storage|vendor|artisan)", Pattern.CASE_INSENSITIVE));
        TECH_PATTERNS.put("Django", Pattern.compile("/(admin|static|media)/", Pattern.CASE_INSENSITIVE));
        TECH_PATTERNS.put("Express.js", Pattern.compile("X-Powered-By: Express", Pattern.CASE_INSENSITIVE));
        TECH_PATTERNS.put("Spring", Pattern.compile("/spring|/actuator", Pattern.CASE_INSENSITIVE));
    }
    
    // Patterns for sensitive data
    private static final Map<String, Pattern> SENSITIVE_PATTERNS = new HashMap<>();
    static {
        SENSITIVE_PATTERNS.put("emails", Pattern.compile("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"));
        SENSITIVE_PATTERNS.put("api_keys", Pattern.compile("(api[_-]?key|apikey|api_token)[\\s:=\"']*([a-zA-Z0-9_-]{20,})", Pattern.CASE_INSENSITIVE));
        SENSITIVE_PATTERNS.put("jwt_tokens", Pattern.compile("eyJ[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.?[A-Za-z0-9-_.+/=]*"));
        SENSITIVE_PATTERNS.put("private_keys", Pattern.compile("-----BEGIN (RSA |EC )?PRIVATE KEY-----"));
        SENSITIVE_PATTERNS.put("aws_keys", Pattern.compile("(AKIA[0-9A-Z]{16})"));
        SENSITIVE_PATTERNS.put("debug_info", Pattern.compile("(stack.?trace|exception|error.?log|debug|stacktrace)", Pattern.CASE_INSENSITIVE));
        SENSITIVE_PATTERNS.put("internal_ips", Pattern.compile("\\b(10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|172\\.(1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3}|192\\.168\\.\\d{1,3}\\.\\d{1,3})\\b"));
        SENSITIVE_PATTERNS.put("sql_errors", Pattern.compile("(SQL syntax|mysql_fetch|ORA-\\d{5}|PostgreSQL|SQLite|syntax error)", Pattern.CASE_INSENSITIVE));
    }

    public SiteMapAnalysisTool(MontoyaApi api) {
        this.api = api;
        this.siteMap = api.siteMap();
        this.objectMapper = new ObjectMapper();
    }

    @Override
    public Map<String, Object> getToolInfo() {
        Map<String, Object> tool = new HashMap<>();
        tool.put("name", "burp_sitemap_analysis");
        tool.put("title", "Site Map Analysis");
        tool.put("description", "Analyze site structure, detect technologies, map attack surface, and identify potential vulnerabilities from captured traffic. " +
            "Actions: ANALYZE_STRUCTURE (directory tree), DETECT_TECHNOLOGY (stack fingerprinting), " +
            "MAP_ATTACK_SURFACE (input points), CONTENT_ANALYSIS (sensitive data), RESPONSE_STATS (metrics), " +
            "CORRELATE_ISSUES, RESPONSE_VARIATIONS, KEYWORD_ANALYSIS, FULL_ANALYSIS, CREATE_ISSUES_FROM_ANALYSIS.");

        // MCP 2025-06-18 annotations
        Map<String, Object> annotations = new HashMap<>();
        annotations.put("readOnlyHint", true);
        annotations.put("destructiveHint", false);
        annotations.put("idempotentHint", true);
        annotations.put("openWorldHint", false);
        tool.put("annotations", annotations);

        Map<String, Object> inputSchema = new HashMap<>();
        inputSchema.put("type", "object");
        
        Map<String, Object> properties = new HashMap<>();
        
        Map<String, Object> action = new HashMap<>();
        action.put("type", "string");
        action.put("enum", SUPPORTED_ACTIONS.toArray(new String[0]));
        action.put("description", "Type of analysis to perform");
        properties.put("action", action);
        
        Map<String, Object> target = new HashMap<>();
        target.put("type", "string");
        target.put("description", "Target URL prefix to analyze (e.g., https://example.com)");
        properties.put("target", target);
        
        Map<String, Object> includeSubdomains = new HashMap<>();
        includeSubdomains.put("type", "boolean");
        includeSubdomains.put("default", false);
        includeSubdomains.put("description", "Include subdomains in analysis");
        properties.put("includeSubdomains", includeSubdomains);
        
        Map<String, Object> analyzeKeywords = new HashMap<>();
        analyzeKeywords.put("type", "array");
        analyzeKeywords.put("items", Map.of("type", "string"));
        analyzeKeywords.put("description", "Keywords to analyze for variance (for KEYWORD_ANALYSIS action)");
        properties.put("analyzeKeywords", analyzeKeywords);
        
        Map<String, Object> maxSamples = new HashMap<>();
        maxSamples.put("type", "integer");
        maxSamples.put("default", 100);
        maxSamples.put("description", "Maximum samples for variation analysis");
        properties.put("maxSamples", maxSamples);
        
        inputSchema.put("properties", properties);
        inputSchema.put("required", new String[]{"action"});
        
        tool.put("inputSchema", inputSchema);
        
        return tool;
    }

    @Override
    public Object execute(JsonNode arguments) throws Exception {
        ObjectNode result = objectMapper.createObjectNode();
        
        String action;
        McpUtils.ActionResolution actionResolution = McpUtils.resolveAction(arguments, SUPPORTED_ACTIONS);
        if (actionResolution.hasError()) {
            if (actionResolution.isMissing()) {
                action = "FULL_ANALYSIS";
            } else {
                ObjectNode errorResult = objectMapper.createObjectNode();
                errorResult.put("success", false);
                errorResult.put("message", actionResolution.getErrorMessage());
                return createMcpResponse(errorResult);
            }
        } else {
            action = actionResolution.getAction();
        }
        String target = arguments.has("target") ? arguments.get("target").asText() : null;
        boolean includeSubdomains = arguments.has("includeSubdomains") ? 
            arguments.get("includeSubdomains").asBoolean() : false;
        int maxSamples = arguments.has("maxSamples") ? 
            arguments.get("maxSamples").asInt() : 100;
        
        List<String> analyzeKeywords = new ArrayList<>();
        if (arguments.has("analyzeKeywords") && arguments.get("analyzeKeywords").isArray()) {
            arguments.get("analyzeKeywords").forEach(node -> analyzeKeywords.add(node.asText()));
        }
        
        try {
            // Get site map entries using Montoya API
            List<HttpRequestResponse> entries = target != null ? 
                siteMap.requestResponses(SiteMapFilter.prefixFilter(target)) :
                siteMap.requestResponses();
            
            if (entries.isEmpty()) {
                result.put("success", false);
                result.put("message", "No entries found in site map" + (target != null ? " for " + target : ""));
                return createMcpResponse(result);
            }
            
            // Filter by subdomain if needed
            if (target != null && !includeSubdomains) {
                String hostName = new URL(target).getHost();
                entries = entries.stream()
                    .filter(e -> {
                        try {
                            return new URL(e.url()).getHost().equals(hostName);
                        } catch (Exception ex) {
                            return false;
                        }
                    })
                    .collect(Collectors.toList());
            }
            
            result.put("success", true);
            result.put("totalEntries", entries.size());
            if (target != null) {
                result.put("target", target);
            }
            result.put("montoyaApiVersion", "2025.8");
            result.put("enhancedFeatures", true);
            
            switch (action) {
                case "ANALYZE_STRUCTURE":
                    result.set("structure", analyzeStructure(entries));
                    break;
                    
                case "DETECT_TECHNOLOGY":
                    result.set("technology", detectTechnology(entries));
                    break;
                    
                case "MAP_ATTACK_SURFACE":
                    result.set("attackSurface", mapAttackSurface(entries));
                    break;
                    
                case "CONTENT_ANALYSIS":
                    result.set("contentAnalysis", analyzeContent(entries));
                    break;
                    
                case "RESPONSE_STATS":
                    result.set("statistics", calculateStatistics(entries));
                    break;
                    
                case "CORRELATE_ISSUES":
                    result.set("issues", correlateIssues(target));
                    break;
                    
                case "RESPONSE_VARIATIONS":
                    result.set("variations", analyzeResponseVariations(entries, maxSamples));
                    break;
                    
                case "KEYWORD_ANALYSIS":
                    result.set("keywords", analyzeKeywords(entries, analyzeKeywords, maxSamples));
                    break;
                    
                case "FULL_ANALYSIS":
                    result.set("structure", analyzeStructure(entries));
                    result.set("technology", detectTechnology(entries));
                    result.set("attackSurface", mapAttackSurface(entries));
                    result.set("statistics", calculateStatistics(entries));
                    result.set("issues", correlateIssues(target));
                    // Add new enhanced analyses
                    result.set("variations", analyzeResponseVariations(entries, Math.min(50, maxSamples)));
                    if (!analyzeKeywords.isEmpty()) {
                        result.set("keywords", analyzeKeywords(entries, analyzeKeywords, Math.min(50, maxSamples)));
                    }
                    break;

                case "CREATE_ISSUES_FROM_ANALYSIS":
                    return createIssuesFromAnalysis(entries, target);

                default:
                    result.put("success", false);
                    result.put("error", "Unknown action: " + action);
            }
            
        } catch (Exception e) {
            result.put("success", false);
            result.put("error", "Analysis failed: " + e.getMessage());
            result.put("errorType", e.getClass().getSimpleName());
        }
        
        return createMcpResponse(result);
    }
    
    /**
     * Analyze response variations using Montoya API's ResponseVariationsAnalyzer
     */
    private ObjectNode analyzeResponseVariations(List<HttpRequestResponse> entries, int maxSamples) {
        ObjectNode variations = objectMapper.createObjectNode();
        
        try {
            // Create analyzer using Montoya API
            ResponseVariationsAnalyzer analyzer = api.http().createResponseVariationsAnalyzer();
            
            // Group entries by base URL path (without query params)
            Map<String, List<HttpRequestResponse>> groupedByPath = new HashMap<>();
            for (HttpRequestResponse entry : entries) {
                if (!entry.hasResponse()) continue;
                
                try {
                    URL url = new URL(entry.url());
                    String basePath = url.getProtocol() + "://" + url.getHost() + url.getPath();
                    groupedByPath.computeIfAbsent(basePath, k -> new ArrayList<>()).add(entry);
                } catch (Exception e) {
                    // Skip malformed URLs
                }
            }
            
            // Analyze variations for each path
            ArrayNode pathVariations = objectMapper.createArrayNode();
            int analyzed = 0;
            
            for (Map.Entry<String, List<HttpRequestResponse>> pathEntry : groupedByPath.entrySet()) {
                if (analyzed >= maxSamples) break;
                
                List<HttpRequestResponse> pathEntries = pathEntry.getValue();
                if (pathEntries.size() < 2) continue; // Need at least 2 responses to compare
                
                // Create new analyzer for this path
                ResponseVariationsAnalyzer pathAnalyzer = api.http().createResponseVariationsAnalyzer();
                
                // Update analyzer with responses
                for (HttpRequestResponse entry : pathEntries) {
                    if (entry.hasResponse()) {
                        pathAnalyzer.updateWith(entry.response());
                    }
                }
                
                // Get results
                Set<AttributeType> variantAttrs = pathAnalyzer.variantAttributes();
                Set<AttributeType> invariantAttrs = pathAnalyzer.invariantAttributes();
                
                if (!variantAttrs.isEmpty() || !invariantAttrs.isEmpty()) {
                    ObjectNode pathNode = objectMapper.createObjectNode();
                    pathNode.put("path", pathEntry.getKey());
                    pathNode.put("sampleCount", pathEntries.size());
                    
                    ArrayNode variantArray = objectMapper.createArrayNode();
                    for (AttributeType attr : variantAttrs) {
                        variantArray.add(attr.name());
                    }
                    pathNode.set("variantAttributes", variantArray);
                    
                    ArrayNode invariantArray = objectMapper.createArrayNode();
                    for (AttributeType attr : invariantAttrs) {
                        invariantArray.add(attr.name());
                    }
                    pathNode.set("invariantAttributes", invariantArray);
                    
                    // Determine if likely dynamic
                    boolean likelyDynamic = variantAttrs.contains(AttributeType.CONTENT_LENGTH) ||
                                           variantAttrs.contains(AttributeType.BODY_CONTENT) ||
                                           variantAttrs.contains(AttributeType.VISIBLE_TEXT);
                    pathNode.put("likelyDynamic", likelyDynamic);
                    
                    pathVariations.add(pathNode);
                    analyzed++;
                }
            }
            
            variations.put("analyzedPaths", analyzed);
            variations.set("pathVariations", pathVariations);
            
            // Summary statistics
            ObjectNode summary = objectMapper.createObjectNode();
            int dynamicCount = 0;
            int staticCount = 0;
            
            for (JsonNode node : pathVariations) {
                if (node.get("likelyDynamic").asBoolean()) {
                    dynamicCount++;
                } else {
                    staticCount++;
                }
            }
            
            summary.put("dynamicPaths", dynamicCount);
            summary.put("staticPaths", staticCount);
            summary.put("totalAnalyzed", analyzed);
            variations.set("summary", summary);
            
        } catch (Exception e) {
            variations.put("error", "Failed to analyze variations: " + e.getMessage());
        }
        
        return variations;
    }
    
    /**
     * Analyze keywords using Montoya API's ResponseKeywordsAnalyzer
     */
    private ObjectNode analyzeKeywords(List<HttpRequestResponse> entries, List<String> keywords, int maxSamples) {
        ObjectNode keywordAnalysis = objectMapper.createObjectNode();
        
        try {
            // If no keywords provided, use common interesting keywords
            if (keywords.isEmpty()) {
                keywords = Arrays.asList("error", "debug", "admin", "test", "api", "token", 
                                       "password", "secret", "key", "config", "internal");
            }
            
            // Create keyword analyzer with Montoya API
            ResponseKeywordsAnalyzer analyzer = api.http().createResponseKeywordsAnalyzer(keywords);
            
            // Update analyzer with responses
            int analyzed = 0;
            for (HttpRequestResponse entry : entries) {
                if (analyzed >= maxSamples) break;
                if (entry.hasResponse()) {
                    analyzer.updateWith(entry.response());
                    analyzed++;
                }
            }
            
            // Get results
            Set<String> variantKeywords = analyzer.variantKeywords();
            Set<String> invariantKeywords = analyzer.invariantKeywords();
            
            keywordAnalysis.put("samplesAnalyzed", analyzed);
            keywordAnalysis.put("keywordsProvided", keywords.size());
            
            // Variant keywords (change between responses)
            ArrayNode variantArray = objectMapper.createArrayNode();
            for (String keyword : variantKeywords) {
                variantArray.add(keyword);
            }
            keywordAnalysis.set("variantKeywords", variantArray);
            keywordAnalysis.put("variantCount", variantKeywords.size());
            
            // Invariant keywords (consistent across responses)
            ArrayNode invariantArray = objectMapper.createArrayNode();
            for (String keyword : invariantKeywords) {
                invariantArray.add(keyword);
            }
            keywordAnalysis.set("invariantKeywords", invariantArray);
            keywordAnalysis.put("invariantCount", invariantKeywords.size());
            
            // Analysis insights
            ObjectNode insights = objectMapper.createObjectNode();
            
            // Check for interesting invariant keywords (potential static identifiers)
            Set<String> interestingInvariant = new HashSet<>();
            for (String keyword : invariantKeywords) {
                if (keyword.matches(".*\\b(version|build|release|copyright)\\b.*")) {
                    interestingInvariant.add(keyword);
                }
            }
            if (!interestingInvariant.isEmpty()) {
                insights.set("staticIdentifiers", objectMapper.valueToTree(interestingInvariant));
            }
            
            // Check for interesting variant keywords (potential dynamic content)
            Set<String> interestingVariant = new HashSet<>();
            for (String keyword : variantKeywords) {
                if (keyword.matches(".*\\b(time|date|session|token|nonce|csrf)\\b.*")) {
                    interestingVariant.add(keyword);
                }
            }
            if (!interestingVariant.isEmpty()) {
                insights.set("dynamicIdentifiers", objectMapper.valueToTree(interestingVariant));
            }
            
            keywordAnalysis.set("insights", insights);
            
        } catch (Exception e) {
            keywordAnalysis.put("error", "Failed to analyze keywords: " + e.getMessage());
        }
        
        return keywordAnalysis;
    }
    
    private List<Map<String, Object>> createMcpResponse(ObjectNode result) {
        List<Map<String, Object>> content = new ArrayList<>();
        Map<String, Object> textContent = new HashMap<>();
        textContent.put("type", "text");
        
        // Convert the ObjectNode to a formatted JSON string
        try {
            String jsonOutput = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(result);
            textContent.put("text", jsonOutput);
        } catch (Exception e) {
            textContent.put("text", "Error formatting response: " + e.getMessage());
        }
        
        content.add(textContent);
        return content;
    }
    
    private ObjectNode analyzeStructure(List<HttpRequestResponse> entries) {
        ObjectNode structure = objectMapper.createObjectNode();
        
        Map<String, Integer> directories = new TreeMap<>();
        Map<String, Integer> fileTypes = new HashMap<>();
        Map<String, Set<String>> directoryFiles = new HashMap<>();
        Set<String> annotatedPaths = new HashSet<>();
        int maxDepth = 0;
        
        for (HttpRequestResponse entry : entries) {
            try {
                String url = entry.url(); // Use direct Montoya API method
                URL urlObj = new URL(url);
                String path = urlObj.getPath();
                
                // Check for annotations using Montoya API
                Annotations annotations = entry.annotations();
                if (annotations != null && !annotations.notes().isEmpty()) {
                    annotatedPaths.add(path);
                }
                
                // Calculate depth
                int depth = path.split("/").length - 1;
                maxDepth = Math.max(maxDepth, depth);
                
                // Extract directory
                int lastSlash = path.lastIndexOf('/');
                String directory = lastSlash > 0 ? path.substring(0, lastSlash) : "/";
                directories.merge(directory, 1, Integer::sum);
                
                // Track files per directory
                String fileName = lastSlash >= 0 ? path.substring(lastSlash + 1) : path;
                if (!fileName.isEmpty()) {
                    directoryFiles.computeIfAbsent(directory, k -> new HashSet<>()).add(fileName);
                    
                    // Extract file type
                    int lastDot = fileName.lastIndexOf('.');
                    if (lastDot > 0) {
                        String extension = fileName.substring(lastDot + 1).toLowerCase();
                        fileTypes.merge(extension, 1, Integer::sum);
                    }
                }
                
            } catch (Exception e) {
                // Skip malformed URLs
            }
        }
        
        // Build directory tree
        ObjectNode directoryTree = objectMapper.createObjectNode();
        for (Map.Entry<String, Integer> entry : directories.entrySet()) {
            ObjectNode dirNode = objectMapper.createObjectNode();
            dirNode.put("count", entry.getValue());
            dirNode.put("fileCount", directoryFiles.getOrDefault(entry.getKey(), Collections.emptySet()).size());
            directoryTree.set(entry.getKey(), dirNode);
        }
        
        structure.set("directories", directoryTree);
        structure.put("maxDepth", maxDepth);
        structure.put("totalDirectories", directories.size());
        
        // Add annotated paths if any
        if (!annotatedPaths.isEmpty()) {
            structure.set("annotatedPaths", objectMapper.valueToTree(annotatedPaths));
            structure.put("annotatedCount", annotatedPaths.size());
        }
        
        // File type distribution
        ObjectNode fileTypeNode = objectMapper.createObjectNode();
        fileTypes.entrySet().stream()
            .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
            .limit(20)
            .forEach(e -> fileTypeNode.put(e.getKey(), e.getValue()));
        structure.set("fileTypes", fileTypeNode);
        
        // Identify special directories
        ArrayNode specialDirs = objectMapper.createArrayNode();
        for (String dir : directories.keySet()) {
            if (dir.matches(".*(admin|manage|dashboard|config|backup|test|debug|api|v[0-9]|internal|private).*")) {
                specialDirs.add(dir);
            }
        }
        structure.set("interestingDirectories", specialDirs);
        
        return structure;
    }
    
    private ObjectNode detectTechnology(List<HttpRequestResponse> entries) {
        ObjectNode tech = objectMapper.createObjectNode();
        
        Set<String> servers = new HashSet<>();
        Set<String> technologies = new HashSet<>();
        Set<String> frameworks = new HashSet<>();
        Set<String> languages = new HashSet<>();
        Map<String, Integer> headers = new HashMap<>();
        
        for (HttpRequestResponse entry : entries) {
            HttpRequest request = entry.request();
            
            // Check URL patterns for CMS/frameworks
            String url = entry.url(); // Use direct Montoya API method
            for (Map.Entry<String, Pattern> pattern : TECH_PATTERNS.entrySet()) {
                if (pattern.getValue().matcher(url).find()) {
                    frameworks.add(pattern.getKey());
                }
            }
            
            // Use Montoya API's contains method for efficient searching
            if (entry.hasResponse()) {
                HttpResponse response = entry.response();
                
                // Check for technology patterns using Montoya API
                for (Map.Entry<String, Pattern> techPattern : TECH_PATTERNS.entrySet()) {
                    if (entry.contains(techPattern.getValue())) {
                        technologies.add(techPattern.getKey());
                    }
                }
                
                // Analyze headers
                for (HttpHeader header : response.headers()) {
                    String name = header.name().toLowerCase();
                    String value = header.value();
                    
                    // Server detection
                    if (name.equals("server")) {
                        servers.add(value);
                    }
                    
                    // Technology headers
                    if (name.equals("x-powered-by")) {
                        technologies.add(value);
                    }
                    
                    // Language detection
                    if (name.equals("x-aspnet-version") || name.equals("x-aspnetmvc-version")) {
                        languages.add("ASP.NET");
                        technologies.add(value);
                    }
                    
                    // Framework headers
                    if (name.startsWith("x-") && !name.equals("x-frame-options") && !name.equals("x-content-type-options")) {
                        headers.merge(header.name(), 1, Integer::sum);
                    }
                    
                    // Cookie technology hints
                    if (name.equals("set-cookie")) {
                        if (value.contains("PHPSESSID")) languages.add("PHP");
                        if (value.contains("JSESSIONID")) languages.add("Java");
                        if (value.contains("ASP.NET_SessionId")) languages.add("ASP.NET");
                        if (value.contains("connect.sid")) technologies.add("Node.js/Express");
                        if (value.contains("laravel_session")) frameworks.add("Laravel");
                    }
                }
                
                // Analyze response body for technology hints
                String body = response.bodyToString();
                if (body.length() > 0 && body.length() < 100000) { // Limit to reasonable size
                    // Meta generator tags
                    Pattern metaGen = Pattern.compile("<meta name=\"generator\" content=\"([^\"]+)\"", Pattern.CASE_INSENSITIVE);
                    Matcher matcher = metaGen.matcher(body);
                    if (matcher.find()) {
                        technologies.add(matcher.group(1));
                    }
                }
            }
        }
        
        tech.set("servers", objectMapper.valueToTree(servers));
        tech.set("technologies", objectMapper.valueToTree(technologies));
        tech.set("frameworks", objectMapper.valueToTree(frameworks));
        tech.set("languages", objectMapper.valueToTree(languages));
        
        // Top custom headers
        ObjectNode topHeaders = objectMapper.createObjectNode();
        headers.entrySet().stream()
            .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
            .limit(10)
            .forEach(e -> topHeaders.put(e.getKey(), e.getValue()));
        tech.set("customHeaders", topHeaders);
        
        return tech;
    }
    
    private ObjectNode mapAttackSurface(List<HttpRequestResponse> entries) {
        ObjectNode surface = objectMapper.createObjectNode();
        
        Set<String> parameterNames = new HashSet<>();
        Set<String> headerNames = new HashSet<>();
        Map<String, Set<String>> endpointParams = new HashMap<>();
        Set<String> formActions = new HashSet<>();
        Set<String> uploadEndpoints = new HashSet<>();
        Set<String> apiEndpoints = new HashSet<>();
        Map<String, Integer> methods = new HashMap<>();
        Set<String> contentTypes = new HashSet<>();
        
        for (HttpRequestResponse entry : entries) {
            HttpRequest request = entry.request();
            String url = entry.url(); // Use direct Montoya API method
            String method = request.method();
            
            methods.merge(method, 1, Integer::sum);
            
            // Use Montoya API's ContentType
            ContentType contentType = entry.contentType();
            if (contentType != null) {
                contentTypes.add(contentType.toString());
            }
            
            // Track parameters
            List<ParsedHttpParameter> params = request.parameters();
            Set<String> urlParams = new HashSet<>();
            for (ParsedHttpParameter param : params) {
                parameterNames.add(param.name());
                urlParams.add(param.name());
            }
            
            if (!urlParams.isEmpty()) {
                endpointParams.put(url, urlParams);
            }
            
            // Track custom headers
            for (HttpHeader header : request.headers()) {
                String name = header.name().toLowerCase();
                if (!name.startsWith("x-") && !isStandardHeader(name)) {
                    headerNames.add(header.name());
                }
            }
            
            // Identify upload endpoints
            if (request.hasHeader("Content-Type")) {
                String ct = request.headerValue("Content-Type");
                if (ct != null && ct.contains("multipart/form-data")) {
                    uploadEndpoints.add(url);
                }
            }
            
            // Identify API endpoints
            if (url.matches(".*/api/.*") || url.matches(".*/v[0-9]+/.*") || 
                url.contains("/rest/") || url.contains("/graphql") || url.contains("/ws/")) {
                apiEndpoints.add(url);
            }
            
            // Analyze response for forms
            if (entry.hasResponse()) {
                String body = entry.response().bodyToString();
                if (body.contains("<form")) {
                    Pattern formPattern = Pattern.compile("<form[^>]*action=[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE);
                    Matcher matcher = formPattern.matcher(body);
                    while (matcher.find()) {
                        formActions.add(matcher.group(1));
                    }
                }
            }
        }
        
        surface.put("totalParameters", parameterNames.size());
        surface.set("parameterNames", objectMapper.valueToTree(parameterNames));
        surface.put("totalEndpointsWithParams", endpointParams.size());
        surface.set("contentTypes", objectMapper.valueToTree(contentTypes));
        
        // Top endpoints by parameter count
        ArrayNode topEndpoints = objectMapper.createArrayNode();
        endpointParams.entrySet().stream()
            .sorted((a, b) -> Integer.compare(b.getValue().size(), a.getValue().size()))
            .limit(10)
            .forEach(e -> {
                ObjectNode endpoint = objectMapper.createObjectNode();
                endpoint.put("url", e.getKey());
                endpoint.put("paramCount", e.getValue().size());
                endpoint.set("params", objectMapper.valueToTree(e.getValue()));
                topEndpoints.add(endpoint);
            });
        surface.set("topParameterizedEndpoints", topEndpoints);
        
        surface.set("customHeaders", objectMapper.valueToTree(headerNames));
        surface.set("httpMethods", objectMapper.valueToTree(methods));
        surface.set("formActions", objectMapper.valueToTree(formActions));
        surface.set("uploadEndpoints", objectMapper.valueToTree(uploadEndpoints));
        surface.set("apiEndpoints", objectMapper.valueToTree(apiEndpoints));
        surface.put("uploadEndpointCount", uploadEndpoints.size());
        surface.put("apiEndpointCount", apiEndpoints.size());
        
        return surface;
    }
    
    private ObjectNode analyzeContent(List<HttpRequestResponse> entries) {
        ObjectNode content = objectMapper.createObjectNode();
        
        Map<String, Set<String>> findings = new HashMap<>();
        Map<String, Integer> sensitiveDataCount = new HashMap<>();
        Set<String> commentsFound = new HashSet<>();
        Set<String> markedEntries = new HashSet<>();
        
        int analyzed = 0;
        int skipped = 0;
        
        for (HttpRequestResponse entry : entries) {
            if (!entry.hasResponse()) {
                skipped++;
                continue;
            }
            
            // Check if entry has markers (interesting points marked by Burp)
            if (!entry.requestMarkers().isEmpty() || !entry.responseMarkers().isEmpty()) {
                markedEntries.add(entry.url());
            }
            
            String body = entry.response().bodyToString();
            if (body.length() > 500000) { // Skip very large responses
                skipped++;
                continue;
            }
            
            analyzed++;
            String url = entry.url();
            
            // Use Montoya API's contains method for efficient searching
            for (Map.Entry<String, Pattern> pattern : SENSITIVE_PATTERNS.entrySet()) {
                if (entry.contains(pattern.getValue())) {
                    Matcher matcher = pattern.getValue().matcher(body);
                    int count = 0;
                    Set<String> matches = new HashSet<>();
                    while (matcher.find() && count < 10) { // Limit matches per pattern
                        matches.add(matcher.group());
                        count++;
                    }
                    if (!matches.isEmpty()) {
                        findings.computeIfAbsent(pattern.getKey(), k -> new HashSet<>()).addAll(matches);
                        sensitiveDataCount.merge(pattern.getKey(), matches.size(), Integer::sum);
                    }
                }
            }
            
            // HTML comments
            Pattern commentPattern = Pattern.compile("<!--([^-]|-[^-])*-->");
            Matcher commentMatcher = commentPattern.matcher(body);
            while (commentMatcher.find()) {
                String comment = commentMatcher.group();
                if (comment.length() > 20 && comment.length() < 500) {
                    commentsFound.add(comment.substring(0, Math.min(comment.length(), 200)));
                }
            }
        }
        
        content.put("entriesAnalyzed", analyzed);
        content.put("entriesSkipped", skipped);
        content.put("entriesWithMarkers", markedEntries.size());
        
        // Summarize findings
        ObjectNode summary = objectMapper.createObjectNode();
        for (Map.Entry<String, Integer> entry : sensitiveDataCount.entrySet()) {
            summary.put(entry.getKey(), entry.getValue());
        }
        content.set("sensitiveFindingsSummary", summary);
        
        // Sample findings (don't expose all sensitive data)
        ObjectNode samples = objectMapper.createObjectNode();
        for (Map.Entry<String, Set<String>> entry : findings.entrySet()) {
            ArrayNode sampleArray = objectMapper.createArrayNode();
            entry.getValue().stream()
                .limit(3)
                .forEach(s -> {
                    if (entry.getKey().equals("emails") || entry.getKey().equals("internal_ips")) {
                        sampleArray.add(s); // Less sensitive
                    } else {
                        // Redact sensitive parts
                        sampleArray.add(s.substring(0, Math.min(10, s.length())) + "...[REDACTED]");
                    }
                });
            samples.set(entry.getKey(), sampleArray);
        }
        content.set("sampleFindings", samples);
        
        // Comments
        content.put("htmlCommentsFound", commentsFound.size());
        if (!commentsFound.isEmpty()) {
            ArrayNode commentSamples = objectMapper.createArrayNode();
            commentsFound.stream().limit(5).forEach(commentSamples::add);
            content.set("commentSamples", commentSamples);
        }
        
        // Add marked entries if any
        if (!markedEntries.isEmpty()) {
            ArrayNode markedArray = objectMapper.createArrayNode();
            markedEntries.stream().limit(10).forEach(markedArray::add);
            content.set("entriesWithMarkers", markedArray);
        }
        
        return content;
    }
    
    private ObjectNode calculateStatistics(List<HttpRequestResponse> entries) {
        ObjectNode stats = objectMapper.createObjectNode();
        
        Map<Integer, Integer> statusCodes = new HashMap<>();
        Map<String, Integer> mimeTypes = new HashMap<>();
        List<Integer> responseSizes = new ArrayList<>();
        List<Long> responseTimes = new ArrayList<>();
        int hasResponse = 0;
        int noResponse = 0;
        int hasTimingData = 0;
        
        for (HttpRequestResponse entry : entries) {
            if (entry.hasResponse()) {
                hasResponse++;
                
                // Use direct Montoya API methods
                int statusCode = entry.statusCode();
                statusCodes.merge(statusCode, 1, Integer::sum);
                
                // Use ContentType from Montoya API
                ContentType contentType = entry.contentType();
                if (contentType != null) {
                    mimeTypes.merge(contentType.toString(), 1, Integer::sum);
                }
                
                // Response size
                HttpResponse response = entry.response();
                responseSizes.add(response.body().length());
                
                // Use TimingData from Montoya API
                Optional<TimingData> timingData = entry.timingData();
                if (timingData.isPresent()) {
                    hasTimingData++;
                    // Convert Duration to milliseconds
                    long millis = timingData.get().timeBetweenRequestSentAndEndOfResponse().toMillis();
                    responseTimes.add(millis);
                }
                
            } else {
                noResponse++;
            }
        }
        
        stats.put("totalRequests", entries.size());
        stats.put("withResponse", hasResponse);
        stats.put("withoutResponse", noResponse);
        stats.put("withTimingData", hasTimingData);
        
        // Status code distribution
        ObjectNode statusDist = objectMapper.createObjectNode();
        statusCodes.entrySet().stream()
            .sorted(Map.Entry.comparingByKey())
            .forEach(e -> statusDist.put(String.valueOf(e.getKey()), e.getValue()));
        stats.set("statusCodes", statusDist);
        
        // Status categories
        ObjectNode statusCategories = objectMapper.createObjectNode();
        statusCategories.put("1xx", statusCodes.entrySet().stream().filter(e -> e.getKey() >= 100 && e.getKey() < 200).mapToInt(Map.Entry::getValue).sum());
        statusCategories.put("2xx", statusCodes.entrySet().stream().filter(e -> e.getKey() >= 200 && e.getKey() < 300).mapToInt(Map.Entry::getValue).sum());
        statusCategories.put("3xx", statusCodes.entrySet().stream().filter(e -> e.getKey() >= 300 && e.getKey() < 400).mapToInt(Map.Entry::getValue).sum());
        statusCategories.put("4xx", statusCodes.entrySet().stream().filter(e -> e.getKey() >= 400 && e.getKey() < 500).mapToInt(Map.Entry::getValue).sum());
        statusCategories.put("5xx", statusCodes.entrySet().stream().filter(e -> e.getKey() >= 500 && e.getKey() < 600).mapToInt(Map.Entry::getValue).sum());
        stats.set("statusCategories", statusCategories);
        
        // MIME type distribution
        ObjectNode mimeDist = objectMapper.createObjectNode();
        mimeTypes.entrySet().stream()
            .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
            .limit(10)
            .forEach(e -> mimeDist.put(e.getKey(), e.getValue()));
        stats.set("topMimeTypes", mimeDist);
        
        // Response size statistics
        if (!responseSizes.isEmpty()) {
            Collections.sort(responseSizes);
            ObjectNode sizeStats = objectMapper.createObjectNode();
            sizeStats.put("min", responseSizes.get(0));
            sizeStats.put("max", responseSizes.get(responseSizes.size() - 1));
            sizeStats.put("median", responseSizes.get(responseSizes.size() / 2));
            sizeStats.put("average", responseSizes.stream().mapToInt(Integer::intValue).average().orElse(0));
            stats.set("responseSizeStats", sizeStats);
        }
        
        // Response time statistics (NEW - using TimingData)
        if (!responseTimes.isEmpty()) {
            Collections.sort(responseTimes);
            ObjectNode timeStats = objectMapper.createObjectNode();
            timeStats.put("min", responseTimes.get(0));
            timeStats.put("max", responseTimes.get(responseTimes.size() - 1));
            timeStats.put("median", responseTimes.get(responseTimes.size() / 2));
            timeStats.put("average", responseTimes.stream().mapToLong(Long::longValue).average().orElse(0));
            timeStats.put("samplesWithTiming", hasTimingData);
            stats.set("responseTimeStats", timeStats);
        }
        
        return stats;
    }
    
    private ObjectNode correlateIssues(String target) {
        ObjectNode issueNode = objectMapper.createObjectNode();
        
        List<AuditIssue> issues = target != null ?
            siteMap.issues(SiteMapFilter.prefixFilter(target)) :
            siteMap.issues();
        
        Map<String, Integer> severityCount = new HashMap<>();
        Map<String, Set<String>> issuesByType = new HashMap<>();
        Map<String, Set<String>> issuesByPath = new HashMap<>();
        Map<String, Integer> confidenceCount = new HashMap<>();
        
        for (AuditIssue issue : issues) {
            String severity = issue.severity().name();
            severityCount.merge(severity, 1, Integer::sum);
            
            String confidence = issue.confidence().name();
            confidenceCount.merge(confidence, 1, Integer::sum);
            
            String issueType = issue.name();
            String url = issue.baseUrl();
            
            issuesByType.computeIfAbsent(issueType, k -> new HashSet<>()).add(url);
            
            // Group by directory
            try {
                URL u = new URL(url);
                String path = u.getPath();
                int lastSlash = path.lastIndexOf('/');
                String directory = lastSlash > 0 ? path.substring(0, lastSlash) : "/";
                issuesByPath.computeIfAbsent(directory, k -> new HashSet<>()).add(issueType);
            } catch (Exception e) {
                // Skip malformed URLs
            }
        }
        
        issueNode.put("totalIssues", issues.size());
        issueNode.set("severityDistribution", objectMapper.valueToTree(severityCount));
        issueNode.set("confidenceDistribution", objectMapper.valueToTree(confidenceCount));
        
        // Issues by type
        ObjectNode typeNode = objectMapper.createObjectNode();
        issuesByType.entrySet().stream()
            .sorted((a, b) -> Integer.compare(b.getValue().size(), a.getValue().size()))
            .limit(10)
            .forEach(e -> typeNode.put(e.getKey(), e.getValue().size()));
        issueNode.set("topIssueTypes", typeNode);
        
        // Vulnerable paths
        ArrayNode vulnPaths = objectMapper.createArrayNode();
        issuesByPath.entrySet().stream()
            .sorted((a, b) -> Integer.compare(b.getValue().size(), a.getValue().size()))
            .limit(10)
            .forEach(e -> {
                ObjectNode pathNode = objectMapper.createObjectNode();
                pathNode.put("path", e.getKey());
                pathNode.put("issueCount", e.getValue().size());
                pathNode.set("issueTypes", objectMapper.valueToTree(e.getValue()));
                vulnPaths.add(pathNode);
            });
        issueNode.set("vulnerablePaths", vulnPaths);
        
        return issueNode;
    }
    
    /**
     * Analyzes sitemap entries and automatically creates Burp issues for potential vulnerabilities
     */
    private Object createIssuesFromAnalysis(List<HttpRequestResponse> entries, String target) {
        try {
            StringBuilder report = new StringBuilder();
            report.append("# 🔍 Automated Issue Creation from Sitemap Analysis\n\n");
            report.append("**Target:** ").append(target).append("\n");
            report.append("**Entries Analyzed:** ").append(entries.size()).append("\n\n");

            int issuesCreated = 0;
            List<String> createdIssues = new ArrayList<>();

            // Analyze attack surface to find potential issues
            ObjectNode attackSurface = mapAttackSurface(entries);
            ArrayNode parameterNames = (ArrayNode) attackSurface.get("parameterNames");
            ArrayNode topEndpoints = (ArrayNode) attackSurface.get("topParameterizedEndpoints");

            // 1. Check for potential path traversal vulnerabilities
            if (parameterNames != null) {
                for (int i = 0; i < parameterNames.size(); i++) {
                    String param = parameterNames.get(i).asText();
                    if (param.equals("file") || param.equals("path") || param.equals("dir") ||
                        param.equals("folder") || param.equals("document") || param.equals("page")) {

                        // Find an example URL with this parameter
                        String exampleUrl = findExampleUrlWithParameter(entries, param);
                        if (exampleUrl != null) {
                            Map<String, Object> issue = createPathTraversalIssue(exampleUrl, param);
                            if (issue != null) {
                                createdIssues.add("Path Traversal: " + param + " in " + exampleUrl);
                                issuesCreated++;
                            }
                        }
                    }
                }
            }

            // 2. Check for potential SQL injection points
            if (topEndpoints != null) {
                for (int i = 0; i < Math.min(topEndpoints.size(), 10); i++) {
                    ObjectNode endpoint = (ObjectNode) topEndpoints.get(i);
                    String url = endpoint.get("url").asText();
                    ArrayNode params = (ArrayNode) endpoint.get("params");

                    for (int j = 0; j < params.size(); j++) {
                        String param = params.get(j).asText();
                        // Skip non-suspicious parameters
                        if (param.equals("goButton") || param.equals("submit")) continue;

                        if (param.contains("id") || param.equals("cat") || param.equals("artist") ||
                            param.equals("pid") || param.equals("search") || param.equals("query")) {
                            Map<String, Object> issue = createSQLiIssue(url, param);
                            if (issue != null) {
                                createdIssues.add("SQL Injection: " + param + " in " + url);
                                issuesCreated++;
                            }
                        }
                    }
                }
            }

            // 3. Check for outdated technology
            ObjectNode technology = detectTechnology(entries);
            ArrayNode technologies = (ArrayNode) technology.get("technologies");
            if (technologies != null) {
                for (int i = 0; i < technologies.size(); i++) {
                    String tech = technologies.get(i).asText().toLowerCase();
                    if (tech.contains("php/5.") || tech.contains("php/4.")) {
                        Map<String, Object> issue = createOutdatedTechIssue(target, tech);
                        if (issue != null) {
                            createdIssues.add("Outdated Technology: " + tech);
                            issuesCreated++;
                        }
                        break; // Only create one outdated tech issue
                    }
                }
            }

            // Build report
            report.append("## ✅ Issues Created: ").append(issuesCreated).append("\n\n");
            if (issuesCreated > 0) {
                for (String created : createdIssues) {
                    report.append("- ✓ ").append(created).append("\n");
                }
            } else {
                report.append("*No potential vulnerabilities detected from sitemap analysis.*\n");
            }

            report.append("\n## 📋 Analysis Summary\n\n");
            report.append("**Total Parameters:** ").append(parameterNames != null ? parameterNames.size() : 0).append("\n");
            report.append("**Parameterized Endpoints:** ").append(topEndpoints != null ? topEndpoints.size() : 0).append("\n");
            report.append("**Technologies Detected:** ").append(technologies != null ? technologies.size() : 0).append("\n");

            Map<String, Object> resultMap = new HashMap<>();
            resultMap.put("type", "text");
            resultMap.put("text", report.toString());
            return List.of(resultMap);

        } catch (Exception e) {
            api.logging().logToError("Failed to create issues from analysis: " + e.getMessage());
            e.printStackTrace();
            Map<String, Object> errorMap = new HashMap<>();
            errorMap.put("type", "text");
            errorMap.put("text", "❌ Failed to create issues: " + e.getMessage());
            return List.of(errorMap);
        }
    }

    private String findExampleUrlWithParameter(List<HttpRequestResponse> entries, String paramName) {
        for (HttpRequestResponse entry : entries) {
            for (ParsedHttpParameter param : entry.request().parameters()) {
                if (param.name().equals(paramName)) {
                    return entry.request().url();
                }
            }
        }
        return null;
    }

    private Map<String, Object> createPathTraversalIssue(String url, String param) {
        try {
            AddIssueTool issueTool = new AddIssueTool(api);
            ObjectMapper mapper = new ObjectMapper();
            ObjectNode args = mapper.createObjectNode();

            args.put("name", "Potential Path Traversal - " + param + " Parameter");
            args.put("url", url);
            args.put("severity", "HIGH");
            args.put("confidence", "TENTATIVE");
            args.put("detail", "The '" + param + "' parameter appears to accept file paths. " +
                    "This may allow directory traversal attacks if not properly validated. " +
                    "Sitemap analysis detected this parameter in: " + url);
            args.put("background", "Path traversal vulnerabilities occur when user input is used to construct " +
                    "file paths without proper validation, potentially allowing access to files outside " +
                    "the intended directory.");
            args.put("remediation", "1. Validate the '" + param + "' parameter against a whitelist of allowed files\n" +
                    "2. Use path canonicalization to prevent directory traversal sequences (../, etc.)\n" +
                    "3. Implement proper access controls and file permissions");
            args.put("issueType", "Path Traversal");

            ArrayNode params = mapper.createArrayNode();
            params.add(param);
            args.set("parameters", params);

            issueTool.execute(args);
            return Map.of("created", true);
        } catch (Exception e) {
            api.logging().logToError("Failed to create path traversal issue: " + e.getMessage());
            return null;
        }
    }

    private Map<String, Object> createSQLiIssue(String url, String param) {
        try {
            AddIssueTool issueTool = new AddIssueTool(api);
            ObjectMapper mapper = new ObjectMapper();
            ObjectNode args = mapper.createObjectNode();

            args.put("name", "Potential SQL Injection - " + param + " Parameter");
            args.put("url", url);
            args.put("severity", "HIGH");
            args.put("confidence", "TENTATIVE");
            args.put("detail", "The '" + param + "' parameter may be vulnerable to SQL injection. " +
                    "Sitemap analysis identified this as a database query parameter in: " + url);
            args.put("background", "SQL injection vulnerabilities allow attackers to interfere with database " +
                    "queries by injecting malicious SQL code through user-controllable input.");
            args.put("remediation", "1. Use parameterized queries (prepared statements) for all database operations\n" +
                    "2. Validate and sanitize the '" + param + "' parameter\n" +
                    "3. Apply principle of least privilege to database accounts\n" +
                    "4. Use ORM frameworks that provide built-in protection");
            args.put("issueType", "SQL Injection");

            ArrayNode params = mapper.createArrayNode();
            params.add(param);
            args.set("parameters", params);

            issueTool.execute(args);
            return Map.of("created", true);
        } catch (Exception e) {
            api.logging().logToError("Failed to create SQL injection issue: " + e.getMessage());
            return null;
        }
    }

    private Map<String, Object> createOutdatedTechIssue(String url, String technology) {
        try {
            AddIssueTool issueTool = new AddIssueTool(api);
            ObjectMapper mapper = new ObjectMapper();
            ObjectNode args = mapper.createObjectNode();

            args.put("name", "Outdated Technology Detected");
            args.put("url", url);
            args.put("severity", "MEDIUM");
            args.put("confidence", "CERTAIN");
            args.put("detail", "The application is using outdated technology: " + technology + ". " +
                    "This version has reached end-of-life and no longer receives security updates.");
            args.put("background", "Using outdated software versions exposes the application to known " +
                    "vulnerabilities that have been patched in newer versions. Attackers actively scan " +
                    "for and exploit these known vulnerabilities.");
            args.put("remediation", "1. Upgrade to the latest stable version of " + technology.split("/")[0] + "\n" +
                    "2. Review security advisories for the current version\n" +
                    "3. Implement a regular update and patching schedule\n" +
                    "4. Consider using containerization for easier version management");
            args.put("issueType", "Vulnerable Component");

            issueTool.execute(args);
            return Map.of("created", true);
        } catch (Exception e) {
            api.logging().logToError("Failed to create outdated technology issue: " + e.getMessage());
            return null;
        }
    }

    private boolean isStandardHeader(String name) {
        return name.equals("host") || name.equals("user-agent") || name.equals("accept") ||
               name.equals("accept-language") || name.equals("accept-encoding") ||
               name.equals("connection") || name.equals("referer") || name.equals("cookie") ||
               name.equals("content-type") || name.equals("content-length") ||
               name.equals("origin") || name.equals("cache-control") || name.equals("upgrade") ||
               name.equals("sec-websocket-version") || name.equals("sec-websocket-key");
    }
}
