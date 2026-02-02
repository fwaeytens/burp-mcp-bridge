package com.example.burpmcp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.responses.analysis.AttributeType;
import burp.api.montoya.http.message.responses.analysis.ResponseKeywordsAnalyzer;
import burp.api.montoya.http.message.responses.analysis.ResponseVariationsAnalyzer;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.utilities.ByteUtils;
import burp.api.montoya.utilities.rank.RankingUtils;
import burp.api.montoya.utilities.rank.RankingAlgorithm;
import burp.api.montoya.utilities.rank.RankedHttpRequestResponse;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.util.stream.Collectors;

public class ResponseAnalysisTool implements McpTool {
    private final MontoyaApi api;
    
    public ResponseAnalysisTool(MontoyaApi api) {
        this.api = api;
    }

    @Override
    public Map<String, Object> getToolInfo() {
        Map<String, Object> tool = new HashMap<>();
        tool.put("name", "burp_response_analyzer");
        tool.put("title", "Response Analyzer");
        tool.put("description", "Analyze HTTP responses for keywords, variations, reflection points, and anomalies. " +
            "Use this to find dynamic content, identify reflection points for XSS testing, detect security-related keywords, and rank anomalous responses. " +
            "Actions: keywords (find security terms), variations (detect dynamic content), reflection (XSS testing), " +
            "pattern (regex search), rank_anomalies (AI-powered anomaly detection), all (complete analysis).");

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
        
        properties.put("action", McpUtils.createEnumProperty("string",
            "Type of analysis to perform",
            List.of("keywords", "variations", "reflection", "pattern", "rank_anomalies", "all"),
            "all"));
        
        // For keyword analysis
        properties.put("keywords", McpUtils.createProperty("array", 
            "Keywords to search for in responses (for keywords action)"));
        
        // For variations analysis
        properties.put("urls", McpUtils.createProperty("array", 
            "URLs to analyze for response variations (for variations action)"));
        
        // For reflection analysis  
        properties.put("proxyIds", McpUtils.createProperty("array",
            "Proxy history IDs to analyze for reflection points"));
        
        properties.put("testString", McpUtils.createProperty("string",
            "Test string to look for in responses (for reflection analysis)", "REFLECTED_TEST_12345"));
        
        // For pattern analysis
        properties.put("pattern", McpUtils.createProperty("string",
            "Regular expression pattern to search for in responses"));
        
        properties.put("caseSensitive", McpUtils.createProperty("boolean",
            "Whether pattern matching should be case sensitive", false));
        
        properties.put("limit", McpUtils.createProperty("integer",
            "Maximum number of proxy entries to analyze", 50));

        // For anomaly ranking
        properties.put("topN", McpUtils.createProperty("integer",
            "Number of top-ranked anomalous responses to return (for rank_anomalies)", 10));

        properties.put("algorithm", McpUtils.createEnumProperty("string",
            "Ranking algorithm to use",
            List.of("ANOMALY"),
            "ANOMALY"));

        inputSchema.put("properties", properties);
        inputSchema.put("required", List.of("action"));
        
        tool.put("inputSchema", inputSchema);
        return tool;
    }

    @Override
    public Object execute(JsonNode arguments) throws Exception {
        String action = McpUtils.getStringParam(arguments, "action", "all");
        
        switch (action) {
            case "keywords":
                return analyzeKeywords(arguments);
            case "variations":
                return analyzeVariations(arguments);
            case "reflection":
                return analyzeReflection(arguments);
            case "pattern":
                return analyzePattern(arguments);
            case "rank_anomalies":
                return rankResponsesByAnomaly(arguments);
            case "all":
                return performCompleteAnalysis(arguments);
            default:
                return McpUtils.createErrorResponse("Unknown action: " + action);
        }
    }
    
    private Object analyzeKeywords(JsonNode arguments) {
        try {
            List<String> keywords = new ArrayList<>();
            
            // Get keywords from arguments
            if (arguments.has("keywords") && arguments.get("keywords").isArray()) {
                arguments.get("keywords").forEach(node -> keywords.add(node.asText()));
            } else {
                // Default security-related keywords
                keywords.addAll(List.of(
                    "error", "exception", "stack trace", "sql", "syntax",
                    "password", "token", "api_key", "secret", "credential",
                    "debug", "admin", "root", "localhost", "127.0.0.1",
                    "internal", "private", "sensitive", "unauthorized"
                ));
            }
            
            // Create keyword analyzer
            ResponseKeywordsAnalyzer analyzer = api.http().createResponseKeywordsAnalyzer(keywords);
            
            // Analyze recent proxy history
            List<ProxyHttpRequestResponse> history = api.proxy().history();
            int limit = McpUtils.getIntParam(arguments, "limit", 50);
            
            StringBuilder result = new StringBuilder();
            result.append("## Keyword Analysis Results\n\n");
            result.append("**Keywords searched:** ").append(String.join(", ", keywords)).append("\n\n");
            
            // Process responses through analyzer
            int analyzed = 0;
            for (int i = history.size() - 1; i >= 0 && analyzed < limit; i--) {
                ProxyHttpRequestResponse item = history.get(i);
                if (!item.hasResponse()) continue;
                
                analyzer.updateWith(item.response());
                analyzed++;
            }
            
            // Get variant and invariant keywords
            Set<String> variantKeywords = analyzer.variantKeywords();
            Set<String> invariantKeywords = analyzer.invariantKeywords();
            
            result.append("### Analysis Summary\n");
            result.append("**Responses analyzed:** ").append(analyzed).append("\n\n");
            
            if (!variantKeywords.isEmpty()) {
                result.append("### Dynamic Keywords (Found in some responses)\n");
                result.append("These keywords appear inconsistently, suggesting dynamic content:\n\n");
                for (String keyword : variantKeywords) {
                    result.append("- ").append(keyword).append("\n");
                }
                result.append("\n");
            }
            
            if (!invariantKeywords.isEmpty()) {
                result.append("### Static Keywords (Found consistently)\n");
                result.append("These keywords appear consistently across responses:\n\n");
                int count = 0;
                for (String keyword : invariantKeywords) {
                    if (count++ >= 20) {
                        result.append("... and ").append(invariantKeywords.size() - 20).append(" more\n");
                        break;
                    }
                    result.append("- ").append(keyword).append("\n");
                }
                result.append("\n");
            }
            
            if (variantKeywords.isEmpty() && invariantKeywords.isEmpty()) {
                result.append("No keywords from the search list were found in the analyzed responses.\n");
            } else {
                result.append("💡 **Tip:** Dynamic keywords often indicate areas where user input is processed.\n");
                result.append("Focus security testing on endpoints showing keyword variations.\n");
            }
            
            return McpUtils.createSuccessResponse(result.toString());
            
        } catch (Exception e) {
            return McpUtils.createErrorResponse("Failed to analyze keywords: " + e.getMessage());
        }
    }
    
    private Object analyzeVariations(JsonNode arguments) {
        try {
            ResponseVariationsAnalyzer analyzer = api.http().createResponseVariationsAnalyzer();
            
            // Get URLs to analyze from arguments or use recent proxy history
            List<HttpRequestResponse> responses = new ArrayList<>();
            
            if (arguments.has("urls") && arguments.get("urls").isArray()) {
                // Send requests to specified URLs
                for (JsonNode urlNode : arguments.get("urls")) {
                    String url = urlNode.asText();
                    HttpRequest request = McpUtils.createSafeHttpRequest(url);
                    HttpRequestResponse response = api.http().sendRequest(request);
                    responses.add(response);
                }
            } else {
                // Use recent proxy history
                List<ProxyHttpRequestResponse> history = api.proxy().history();
                int limit = McpUtils.getIntParam(arguments, "limit", 20);
                
                // Group by URL to find variations
                Map<String, List<ProxyHttpRequestResponse>> urlGroups = new HashMap<>();
                
                for (int i = history.size() - 1; i >= 0 && responses.size() < limit; i--) {
                    ProxyHttpRequestResponse item = history.get(i);
                    if (!item.hasResponse()) continue;
                    
                    String url = item.finalRequest().url();
                    urlGroups.computeIfAbsent(url, k -> new ArrayList<>()).add(item);
                }
                
                // Analyze URLs with multiple responses
                for (Map.Entry<String, List<ProxyHttpRequestResponse>> entry : urlGroups.entrySet()) {
                    if (entry.getValue().size() > 1) {
                        for (ProxyHttpRequestResponse item : entry.getValue()) {
                            responses.add(HttpRequestResponse.httpRequestResponse(
                                item.finalRequest(), 
                                item.response()
                            ));
                        }
                    }
                }
            }
            
            if (responses.isEmpty()) {
                return McpUtils.createErrorResponse("No responses available to analyze");
            }
            
            // Update analyzer with all responses
            for (HttpRequestResponse resp : responses) {
                if (resp.response() != null) {
                    analyzer.updateWith(resp.response());
                }
            }
            
            StringBuilder result = new StringBuilder();
            result.append("## Response Variation Analysis\n\n");
            result.append("**Responses analyzed:** ").append(responses.size()).append("\n\n");
            
            // Get variant and invariant attributes
            Set<AttributeType> variantAttributes = analyzer.variantAttributes();
            Set<AttributeType> invariantAttributes = analyzer.invariantAttributes();
            
            if (!variantAttributes.isEmpty()) {
                result.append("### Dynamic/Variant Attributes\n");
                result.append("These attributes vary between responses:\n\n");
                
                // Group attributes by category for better readability
                Map<String, List<AttributeType>> categorizedAttrs = categorizeAttributes(variantAttributes);
                
                for (Map.Entry<String, List<AttributeType>> entry : categorizedAttrs.entrySet()) {
                    if (!entry.getValue().isEmpty()) {
                        result.append("**").append(entry.getKey()).append(":**\n");
                        for (AttributeType attr : entry.getValue()) {
                            result.append("- ").append(formatAttributeName(attr)).append("\n");
                        }
                        result.append("\n");
                    }
                }
            }
            
            if (!invariantAttributes.isEmpty()) {
                result.append("### Static/Invariant Attributes\n");
                result.append("These attributes remain constant:\n\n");
                
                Map<String, List<AttributeType>> categorizedInvariant = categorizeAttributes(invariantAttributes);
                for (Map.Entry<String, List<AttributeType>> entry : categorizedInvariant.entrySet()) {
                    if (!entry.getValue().isEmpty()) {
                        result.append("**").append(entry.getKey()).append(":** ");
                        result.append(entry.getValue().stream()
                            .map(this::formatAttributeName)
                            .collect(Collectors.joining(", ")));
                        result.append("\n");
                    }
                }
                result.append("\n");
            }
            
            if (!variantAttributes.isEmpty()) {
                result.append("### 💡 Security Insights\n\n");
                
                // Enhanced insights based on all attribute types
                if (variantAttributes.contains(AttributeType.VISIBLE_TEXT) || 
                    variantAttributes.contains(AttributeType.BODY_CONTENT) ||
                    variantAttributes.contains(AttributeType.LIMITED_BODY_CONTENT)) {
                    result.append("- **Dynamic Content**: Body/text variations indicate user-specific or time-based content\n");
                }
                
                if (variantAttributes.contains(AttributeType.COOKIE_NAMES)) {
                    result.append("- **Session Management**: Cookie variations suggest active session handling\n");
                }
                
                if (variantAttributes.contains(AttributeType.ETAG_HEADER) || 
                    variantAttributes.contains(AttributeType.LAST_MODIFIED_HEADER)) {
                    result.append("- **Caching Behavior**: ETag/Last-Modified changes indicate cache control mechanisms\n");
                }
                
                if (variantAttributes.contains(AttributeType.PAGE_TITLE) || 
                    variantAttributes.contains(AttributeType.FIRST_HEADER_TAG)) {
                    result.append("- **Page State**: Title/header variations suggest different application states\n");
                }
                
                if (variantAttributes.contains(AttributeType.COMMENTS)) {
                    result.append("- **Information Disclosure**: Comment variations might expose debug/sensitive data\n");
                }
                
                if (variantAttributes.contains(AttributeType.INPUT_SUBMIT_LABELS) || 
                    variantAttributes.contains(AttributeType.BUTTON_SUBMIT_LABELS) ||
                    variantAttributes.contains(AttributeType.NON_HIDDEN_FORM_INPUT_TYPES)) {
                    result.append("- **Form Analysis**: Form field variations indicate dynamic form generation\n");
                }
                
                if (variantAttributes.contains(AttributeType.ANCHOR_LABELS) ||
                    variantAttributes.contains(AttributeType.OUTBOUND_EDGE_COUNT) ||
                    variantAttributes.contains(AttributeType.OUTBOUND_EDGE_TAG_NAMES)) {
                    result.append("- **Link Structure**: Changing links suggest dynamic navigation or permissions\n");
                }
                
                if (variantAttributes.contains(AttributeType.CSS_CLASSES) ||
                    variantAttributes.contains(AttributeType.TAG_IDS) ||
                    variantAttributes.contains(AttributeType.DIV_IDS)) {
                    result.append("- **DOM Structure**: CSS/ID changes indicate client-side state management\n");
                }
                
                if (variantAttributes.contains(AttributeType.WORD_COUNT) ||
                    variantAttributes.contains(AttributeType.VISIBLE_WORD_COUNT) ||
                    variantAttributes.contains(AttributeType.LINE_COUNT)) {
                    result.append("- **Content Size**: Length variations may reveal different data access levels\n");
                }
                
                if (variantAttributes.contains(AttributeType.LOCATION) ||
                    variantAttributes.contains(AttributeType.CONTENT_LOCATION)) {
                    result.append("- **Redirects**: Location header changes indicate dynamic routing\n");
                }
                
                result.append("\n**Testing Recommendations:**\n");
                result.append("- Focus injection testing on variant attributes\n");
                result.append("- Test authorization on pages with variant content\n");
                result.append("- Examine variant forms for parameter tampering opportunities\n");
            } else {
                result.append("No significant variations detected in the analyzed responses.\n");
                result.append("All responses appear to be static/identical.\n");
            }
            
            return McpUtils.createSuccessResponse(result.toString());
            
        } catch (Exception e) {
            return McpUtils.createErrorResponse("Failed to analyze variations: " + e.getMessage());
        }
    }
    
    private Object analyzePattern(JsonNode arguments) {
        try {
            String patternStr = McpUtils.getStringParam(arguments, "pattern", "");
            if (patternStr.isEmpty()) {
                return McpUtils.createErrorResponse("Pattern is required for pattern analysis");
            }
            
            boolean caseSensitive = McpUtils.getBooleanParam(arguments, "caseSensitive", false);
            int limit = McpUtils.getIntParam(arguments, "limit", 50);
            
            // Compile regex pattern
            Pattern pattern;
            try {
                int flags = caseSensitive ? 0 : Pattern.CASE_INSENSITIVE;
                pattern = Pattern.compile(patternStr, flags);
            } catch (Exception e) {
                return McpUtils.createErrorResponse("Invalid regex pattern: " + e.getMessage());
            }
            
            ByteUtils byteUtils = api.utilities().byteUtils();
            
            StringBuilder result = new StringBuilder();
            result.append("## Pattern Analysis Results\n\n");
            result.append("**Pattern:** `").append(patternStr).append("`\n");
            result.append("**Case Sensitive:** ").append(caseSensitive).append("\n\n");
            
            List<Map<String, Object>> matches = new ArrayList<>();
            List<ProxyHttpRequestResponse> history = api.proxy().history();
            
            int analyzed = 0;
            for (int i = history.size() - 1; i >= 0 && analyzed < limit; i--) {
                ProxyHttpRequestResponse item = history.get(i);
                if (!item.hasResponse()) continue;
                
                String url = item.finalRequest().url();
                byte[] responseBytes = item.response().toByteArray().getBytes();
                String responseStr = new String(responseBytes);

                // Count matches using Java regex (byteUtils.countMatches has a bug in some Burp versions)
                Matcher matcher = pattern.matcher(responseStr);
                int matchCount = 0;
                while (matcher.find()) {
                    matchCount++;
                }

                if (matchCount > 0) {
                    Map<String, Object> match = new HashMap<>();
                    match.put("url", url);
                    match.put("method", item.finalRequest().method());
                    match.put("statusCode", (int) item.response().statusCode()); // Cast Short to int
                    match.put("matchCount", matchCount);

                    // Find actual matches for preview (reset matcher)
                    matcher.reset();
                    List<String> foundMatches = new ArrayList<>();
                    int count = 0;
                    while (matcher.find() && count < 5) {
                        String matchText = matcher.group();
                        if (matchText.length() > 100) {
                            matchText = matchText.substring(0, 100) + "...";
                        }
                        foundMatches.add(matchText);
                        count++;
                    }
                    match.put("samples", foundMatches);
                    
                    matches.add(match);
                }
                
                analyzed++;
            }
            
            result.append("**Responses analyzed:** ").append(analyzed).append("\n");
            result.append("**Matches found:** ").append(matches.size()).append("\n\n");
            
            if (!matches.isEmpty()) {
                result.append("### Pattern Matches\n\n");
                
                matches.stream().limit(20).forEach(match -> {
                    result.append("**URL:** ").append(match.get("url")).append("\n");
                    result.append("**Method:** ").append(match.get("method"));
                    result.append(" | **Status:** ").append(match.get("statusCode"));
                    result.append(" | **Matches:** ").append(match.get("matchCount")).append("\n");
                    
                    @SuppressWarnings("unchecked")
                    List<String> samples = (List<String>) match.get("samples");
                    if (!samples.isEmpty()) {
                        result.append("**Sample Matches:**\n");
                        samples.forEach(sample -> {
                            result.append("  - `").append(sample).append("`\n");
                        });
                    }
                    result.append("\n");
                });
                
                if (matches.size() > 20) {
                    result.append("... and ").append(matches.size() - 20).append(" more matches\n\n");
                }
                
                result.append("### Pattern Analysis Summary\n\n");
                
                // Group by status code
                Map<Integer, Long> statusGroups = matches.stream()
                    .collect(Collectors.groupingBy(
                        m -> (Integer) m.get("statusCode"),
                        Collectors.counting()
                    ));
                
                result.append("**By Status Code:**\n");
                statusGroups.forEach((status, count) -> {
                    result.append("- ").append(status).append(": ").append(count).append(" matches\n");
                });
                
                result.append("\n💡 **Use Cases:**\n");
                result.append("- Finding sensitive data patterns (SSN, credit cards, API keys)\n");
                result.append("- Locating error messages or stack traces\n");
                result.append("- Identifying version information or technology fingerprints\n");
                result.append("- Discovering hidden parameters or debug output\n");
            } else {
                result.append("No matches found for the pattern in the analyzed responses.\n");
            }
            
            return McpUtils.createSuccessResponse(result.toString());
            
        } catch (Exception e) {
            api.logging().logToError("Pattern analysis failed: " + e.getMessage());
            e.printStackTrace();
            return McpUtils.createErrorResponse("Pattern analysis failed: " + e.getMessage());
        }
    }
    
    private Object analyzeReflection(JsonNode arguments) {
        try {
            String testString = McpUtils.getStringParam(arguments, "testString", "REFLECTED_TEST_12345");
            int limit = McpUtils.getIntParam(arguments, "limit", 50);
            
            StringBuilder result = new StringBuilder();
            result.append("## Reflection Point Analysis\n\n");
            result.append("**Test String:** ").append(testString).append("\n\n");
            
            List<Map<String, Object>> reflectionPoints = new ArrayList<>();
            
            // Analyze proxy history for reflection
            List<ProxyHttpRequestResponse> history = api.proxy().history();
            
            int analyzed = 0;
            for (int i = history.size() - 1; i >= 0 && analyzed < limit; i--) {
                ProxyHttpRequestResponse item = history.get(i);
                if (!item.hasResponse()) continue;
                
                String request = item.finalRequest().toString();
                String response = item.response().toString();
                
                // Check for reflection of parameters in response
                Map<String, List<String>> reflections = new HashMap<>();
                
                // Extract parameters from request
                String url = item.finalRequest().url();
                String body = item.finalRequest().bodyToString();
                
                // Check URL parameters
                if (url.contains("?")) {
                    String[] params = url.substring(url.indexOf("?") + 1).split("&");
                    for (String param : params) {
                        if (param.contains("=")) {
                            String[] parts = param.split("=", 2);
                            String value = parts.length > 1 ? parts[1] : "";
                            
                            if (!value.isEmpty() && response.contains(value)) {
                                reflections.computeIfAbsent(parts[0], k -> new ArrayList<>())
                                    .add("URL parameter");
                            }
                        }
                    }
                }
                
                // Check body parameters
                if (!body.isEmpty()) {
                    String[] params = body.split("&");
                    for (String param : params) {
                        if (param.contains("=")) {
                            String[] parts = param.split("=", 2);
                            String value = parts.length > 1 ? parts[1] : "";
                            
                            if (!value.isEmpty() && response.contains(value)) {
                                reflections.computeIfAbsent(parts[0], k -> new ArrayList<>())
                                    .add("Body parameter");
                            }
                        }
                    }
                }
                
                // Check headers
                for (burp.api.montoya.http.message.HttpHeader header : item.finalRequest().headers()) {
                    String headerName = header.name();
                    String headerValue = header.value();
                    
                    if (!headerValue.isEmpty() && response.contains(headerValue)) {
                        reflections.computeIfAbsent(headerName, k -> new ArrayList<>())
                            .add("Header");
                    }
                }
                
                if (!reflections.isEmpty()) {
                    Map<String, Object> point = new HashMap<>();
                    point.put("url", url);
                    point.put("method", item.finalRequest().method());
                    point.put("reflections", reflections);
                    point.put("responseCode", item.response().statusCode());
                    reflectionPoints.add(point);
                }
                
                analyzed++;
            }
            
            result.append("**Entries analyzed:** ").append(analyzed).append("\n");
            result.append("**Reflection points found:** ").append(reflectionPoints.size()).append("\n\n");
            
            if (!reflectionPoints.isEmpty()) {
                result.append("### Reflection Points\n\n");
                
                reflectionPoints.stream().limit(20).forEach(point -> {
                    result.append("**URL:** ").append(point.get("url")).append("\n");
                    result.append("**Method:** ").append(point.get("method")).append("\n");
                    result.append("**Status:** ").append(point.get("responseCode")).append("\n");
                    result.append("**Reflected Parameters:**\n");
                    
                    @SuppressWarnings("unchecked")
                    Map<String, List<String>> refs = (Map<String, List<String>>) point.get("reflections");
                    refs.forEach((param, types) -> {
                        result.append("  - **").append(param).append("** (")
                            .append(String.join(", ", types)).append(")\n");
                    });
                    result.append("\n");
                });
                
                result.append("⚠️ **Security Note:** Reflection points are potential XSS vulnerabilities. ");
                result.append("Test with XSS payloads to confirm if proper encoding is missing.\n");
            } else {
                result.append("No reflection points found in the analyzed responses.\n");
            }
            
            return McpUtils.createSuccessResponse(result.toString());
            
        } catch (Exception e) {
            return McpUtils.createErrorResponse("Failed to analyze reflections: " + e.getMessage());
        }
    }
    
    private Object rankResponsesByAnomaly(JsonNode arguments) {
        try {
            int limit = McpUtils.getIntParam(arguments, "limit", 100);
            int topN = McpUtils.getIntParam(arguments, "topN", 10);
            String algorithmStr = McpUtils.getStringParam(arguments, "algorithm", "ANOMALY");

            // Get RankingUtils from Montoya API
            RankingUtils rankingUtils;
            try {
                rankingUtils = api.utilities().rankingUtils();
            } catch (NoSuchMethodError e) {
                return McpUtils.createErrorResponse("rank_anomalies is not supported in this version of Burp Suite. " +
                    "This feature requires Burp Suite 2025.11 or later with rankingUtils() API support.");
            }

            // Get proxy history responses
            List<ProxyHttpRequestResponse> history = api.proxy().history();

            // Convert to HttpRequestResponse collection
            List<HttpRequestResponse> responses = new ArrayList<>();
            int collected = 0;

            for (int i = history.size() - 1; i >= 0 && collected < limit; i--) {
                ProxyHttpRequestResponse item = history.get(i);
                if (!item.hasResponse()) continue;

                // Convert ProxyHttpRequestResponse to HttpRequestResponse
                HttpRequestResponse reqResp = HttpRequestResponse.httpRequestResponse(
                    item.finalRequest(),
                    item.response()
                );
                responses.add(reqResp);
                collected++;
            }

            if (responses.isEmpty()) {
                return McpUtils.createErrorResponse("No responses available to analyze. " +
                    "Ensure proxy history contains responses.");
            }

            // Rank responses using the ANOMALY algorithm
            RankingAlgorithm algorithm = RankingAlgorithm.ANOMALY;
            List<RankedHttpRequestResponse> ranked = rankingUtils.rank(responses, algorithm);

            // Sort by rank (higher rank = more anomalous)
            ranked.sort(Comparator.comparingInt(RankedHttpRequestResponse::rank).reversed());

            // Build result
            StringBuilder result = new StringBuilder();
            result.append("## 🎯 Anomaly Ranking Results\n\n");
            result.append("**Algorithm:** ").append(algorithm.name()).append("\n");
            result.append("**Responses analyzed:** ").append(responses.size()).append("\n");
            result.append("**Showing top:** ").append(Math.min(topN, ranked.size())).append("\n\n");

            result.append("### Top Anomalous Responses\n\n");
            result.append("Higher ranks indicate more unusual/interesting behavior compared to typical responses.\n\n");

            int count = 0;
            for (RankedHttpRequestResponse rankedResp : ranked) {
                if (count >= topN) break;
                count++;

                HttpRequestResponse resp = rankedResp.requestResponse();
                int rank = rankedResp.rank();

                // Determine anomaly level
                String anomalyLevel;
                String emoji;
                if (rank >= 80) {
                    anomalyLevel = "Very High";
                    emoji = "🔴";
                } else if (rank >= 60) {
                    anomalyLevel = "High";
                    emoji = "🟠";
                } else if (rank >= 40) {
                    anomalyLevel = "Medium";
                    emoji = "🟡";
                } else if (rank >= 20) {
                    anomalyLevel = "Low";
                    emoji = "🟢";
                } else {
                    anomalyLevel = "Very Low";
                    emoji = "⚪";
                }

                result.append("**").append(count).append(". ").append(emoji)
                    .append(" Rank: ").append(rank).append("/100** - ")
                    .append(anomalyLevel).append(" Anomaly\n");
                result.append("   - **URL:** ").append(resp.request().url()).append("\n");
                result.append("   - **Method:** ").append(resp.request().method()).append("\n");
                result.append("   - **Status:** ").append(resp.response().statusCode()).append("\n");
                result.append("   - **Size:** ").append(resp.response().toByteArray().length()).append(" bytes\n");

                // Analyze content type
                String contentType = resp.response().headerValue("Content-Type");
                if (contentType != null) {
                    result.append("   - **Content-Type:** ").append(contentType).append("\n");
                }

                result.append("\n");
            }

            // Add summary statistics
            result.append("### Anomaly Distribution\n\n");

            long veryHighCount = ranked.stream().filter(r -> r.rank() >= 80).count();
            long highCount = ranked.stream().filter(r -> r.rank() >= 60 && r.rank() < 80).count();
            long mediumCount = ranked.stream().filter(r -> r.rank() >= 40 && r.rank() < 60).count();
            long lowCount = ranked.stream().filter(r -> r.rank() >= 20 && r.rank() < 40).count();
            long veryLowCount = ranked.stream().filter(r -> r.rank() < 20).count();

            result.append("- 🔴 **Very High (80-100):** ").append(veryHighCount).append(" responses\n");
            result.append("- 🟠 **High (60-79):** ").append(highCount).append(" responses\n");
            result.append("- 🟡 **Medium (40-59):** ").append(mediumCount).append(" responses\n");
            result.append("- 🟢 **Low (20-39):** ").append(lowCount).append(" responses\n");
            result.append("- ⚪ **Very Low (0-19):** ").append(veryLowCount).append(" responses\n\n");

            // Add interpretation guide
            result.append("### 💡 What This Means\n\n");
            result.append("**Anomaly ranking** identifies responses that differ significantly from the norm:\n\n");
            result.append("- **High-ranked responses** often indicate:\n");
            result.append("  - Error conditions or unexpected behavior\n");
            result.append("  - Different application states (admin vs. user)\n");
            result.append("  - Security-relevant differences (authorization issues)\n");
            result.append("  - Potential vulnerabilities or interesting attack surfaces\n\n");
            result.append("- **Low-ranked responses** typically represent:\n");
            result.append("  - Normal application behavior\n");
            result.append("  - Standard static content\n");
            result.append("  - Consistent API responses\n\n");
            result.append("**Recommendation:** Focus security testing on high-ranked anomalies first.\n");

            return McpUtils.createSuccessResponse(result.toString());

        } catch (Exception e) {
            api.logging().logToError("Anomaly ranking failed: " + e.getMessage());
            e.printStackTrace();
            return McpUtils.createErrorResponse("Failed to rank responses: " + e.getMessage() +
                ". Ensure Burp Suite 2025.10+ is installed for RankingUtils support.");
        }
    }

    private Object performCompleteAnalysis(JsonNode arguments) {
        StringBuilder result = new StringBuilder();
        result.append("# Complete Response Analysis\n\n");

        // Run all three analyses
        result.append("---\n");
        Object keywordResult = analyzeKeywords(arguments);
        result.append(extractTextFromResult(keywordResult)).append("\n\n");

        result.append("---\n");
        Object variationResult = analyzeVariations(arguments);
        result.append(extractTextFromResult(variationResult)).append("\n\n");

        result.append("---\n");
        Object reflectionResult = analyzeReflection(arguments);
        result.append(extractTextFromResult(reflectionResult));

        return McpUtils.createSuccessResponse(result.toString());
    }
    
    @SuppressWarnings("unchecked")
    private String extractTextFromResult(Object result) {
        if (result instanceof List) {
            List<Map<String, Object>> list = (List<Map<String, Object>>) result;
            if (!list.isEmpty() && list.get(0).containsKey("text")) {
                return (String) list.get(0).get("text");
            }
        }
        return "Analysis failed";
    }
    
    private Map<String, List<AttributeType>> categorizeAttributes(Set<AttributeType> attributes) {
        Map<String, List<AttributeType>> categories = new LinkedHashMap<>();
        categories.put("Headers", new ArrayList<>());
        categories.put("Content", new ArrayList<>());
        categories.put("Structure", new ArrayList<>());
        categories.put("Forms", new ArrayList<>());
        categories.put("Links", new ArrayList<>());
        categories.put("Metadata", new ArrayList<>());
        
        for (AttributeType attr : attributes) {
            switch (attr) {
                case STATUS_CODE:
                case ETAG_HEADER:
                case LAST_MODIFIED_HEADER:
                case CONTENT_TYPE:
                case CONTENT_LENGTH:
                case CONTENT_LOCATION:
                case LOCATION:
                case COOKIE_NAMES:
                    categories.get("Headers").add(attr);
                    break;
                    
                case BODY_CONTENT:
                case VISIBLE_TEXT:
                case LIMITED_BODY_CONTENT:
                case COMMENTS:
                case INITIAL_CONTENT:
                case WORD_COUNT:
                case VISIBLE_WORD_COUNT:
                case LINE_COUNT:
                    categories.get("Content").add(attr);
                    break;
                    
                case TAG_NAMES:
                case TAG_IDS:
                case DIV_IDS:
                case CSS_CLASSES:
                case HEADER_TAGS:
                case FIRST_HEADER_TAG:
                    categories.get("Structure").add(attr);
                    break;
                    
                case INPUT_SUBMIT_LABELS:
                case BUTTON_SUBMIT_LABELS:
                case INPUT_IMAGE_LABELS:
                case NON_HIDDEN_FORM_INPUT_TYPES:
                    categories.get("Forms").add(attr);
                    break;
                    
                case ANCHOR_LABELS:
                case OUTBOUND_EDGE_COUNT:
                case OUTBOUND_EDGE_TAG_NAMES:
                    categories.get("Links").add(attr);
                    break;
                    
                case PAGE_TITLE:
                case CANONICAL_LINK:
                    categories.get("Metadata").add(attr);
                    break;
            }
        }
        
        // Remove empty categories
        categories.entrySet().removeIf(entry -> entry.getValue().isEmpty());
        return categories;
    }
    
    private String formatAttributeName(AttributeType attr) {
        String name = attr.name().replace("_", " ").toLowerCase();
        return name.substring(0, 1).toUpperCase() + name.substring(1);
    }
}