package com.example.burpmcp;

import burp.api.montoya.MontoyaApi;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.JsonProcessingException;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Unified Help Tool - Single interface for all documentation needs
 * Replaces: get_documentation, discover_tools, get_tool_help
 */
public class BurpHelpTool implements McpTool {
    private final MontoyaApi api;
    private final ObjectMapper mapper;
    private final ToolDocumentationStore docStore;

    public BurpHelpTool(MontoyaApi api) {
        this.api = api;
        this.mapper = new ObjectMapper();
        this.docStore = ToolDocumentationStore.getInstance();
    }

    @Override
    public Map<String, Object> getToolInfo() {
        Map<String, Object> tool = new HashMap<>();
        tool.put("name", "burp_help");
        tool.put("title", "Help & Discovery");

        int securityToolCount = docStore.getAllDocumentation().size();
        tool.put("description", "Discover and learn about all Burp MCP capabilities. Use this tool to list available tools, " +
            "search by capability, or get detailed help for a specific tool. Returns tool names, descriptions, and examples. " +
            "Always start here when unsure which tool to use. (" + securityToolCount + " tools available)");

        // MCP 2025-06-18 annotations
        Map<String, Object> annotations = new HashMap<>();
        annotations.put("readOnlyHint", true);
        annotations.put("destructiveHint", false);
        annotations.put("idempotentHint", true);
        annotations.put("openWorldHint", false);
        tool.put("annotations", annotations);

        Map<String, Object> inputSchema = new HashMap<>();
        Map<String, Object> properties = new HashMap<>();

        // For getting specific tool docs
        Map<String, Object> toolParam = new HashMap<>();
        toolParam.put("type", "string");
        toolParam.put("description", "Specific tool name (e.g., 'burp_scanner') - returns full documentation for that tool");
        properties.put("tool", toolParam);

        // For discovering tools by capability
        Map<String, Object> capabilityParam = new HashMap<>();
        capabilityParam.put("type", "string");
        capabilityParam.put("description", "What you want to do (e.g., 'scan for vulnerabilities', 'decode data') - finds matching tools");
        properties.put("capability", capabilityParam);

        // For listing all tools
        Map<String, Object> listParam = new HashMap<>();
        listParam.put("type", "boolean");
        listParam.put("description", "Set to true to list all available tools with summaries");
        properties.put("list", listParam);

        // Optional: section filter for specific tool
        Map<String, Object> sectionParam = new HashMap<>();
        sectionParam.put("type", "string");
        sectionParam.put("enum", Arrays.asList("full", "examples", "parameters", "summary"));
        sectionParam.put("description", "When requesting specific tool: which section (default: full)");
        properties.put("section", sectionParam);

        inputSchema.put("type", "object");
        inputSchema.put("properties", properties);

        tool.put("inputSchema", inputSchema);
        return tool;
    }

    @Override
    public Object execute(JsonNode arguments) throws Exception {
        Map<String, Object> args = mapper.convertValue(arguments, Map.class);

        String tool = (String) args.get("tool");
        String capability = (String) args.get("capability");
        Boolean list = (Boolean) args.get("list");
        String section = (String) args.get("section");

        if (section == null) {
            section = "full";
        }

        // Mode 1: Get specific tool documentation
        if (tool != null && !tool.isEmpty()) {
            return getToolDocumentation(tool, section);
        }

        // Mode 2: Discover tools by capability
        if (capability != null && !capability.isEmpty()) {
            return discoverTools(capability);
        }

        // Mode 3: List all tools
        if (Boolean.TRUE.equals(list)) {
            return listAllTools();
        }

        // Mode 4: No parameters - return usage guide
        return getUsageGuide();
    }

    /**
     * Get documentation for a specific tool
     */
    private Object getToolDocumentation(String toolName, String section) {
        ToolDocumentation doc = docStore.getDocumentation(toolName);

        if (doc == null) {
            // Try to find similar tools
            List<String> similar = findSimilarTools(toolName);

            Map<String, Object> error = new HashMap<>();
            error.put("error", "Tool not found: " + toolName);

            if (!similar.isEmpty()) {
                error.put("did_you_mean", similar);
            }

            error.put("available_tools", docStore.getAllToolNames());
            error.put("hint", "Use burp_help with 'list: true' to see all tools");

            return toTextResponse(error);
        }

        Map<String, Object> result = new HashMap<>();
        result.put("tool", doc.getName());
        result.put("category", doc.getCategory());
        result.put("description", doc.getDescription());

        switch (section) {
            case "summary":
                result.put("parameters_count", doc.getParameters().size());
                result.put("examples_count", doc.getExamples().size());
                break;

            case "parameters":
                result.put("parameters", doc.getParameters());
                result.put("returns", doc.getReturns());
                result.put("required_params", getRequiredParams(doc));
                break;

            case "examples":
                result.put("examples", doc.getExamples());
                result.put("quick_start", getQuickStart(doc));
                break;

            default: // "full"
                result.put("parameters", doc.getParameters());
                result.put("required_params", getRequiredParams(doc));
                result.put("returns", doc.getReturns());
                result.put("examples", doc.getExamples());
                result.put("errors", doc.getErrors());
                result.put("best_practices", doc.getBestPractices());
                result.put("related_tools", doc.getRelatedTools());
                result.put("keywords", doc.getKeywords());
                result.put("capabilities", doc.getCapabilities());
        }

        return toTextResponse(result);
    }

    /**
     * Discover tools by capability/keyword
     */
    private Object discoverTools(String capability) {
        String search = capability.toLowerCase();
        List<ToolMatch> matches = new ArrayList<>();

        for (ToolDocumentation doc : docStore.getAllDocumentation()) {
            int score = 0;
            List<String> reasons = new ArrayList<>();

            // Match against capabilities
            for (String cap : doc.getCapabilities()) {
                if (cap.toLowerCase().contains(search) || search.contains(cap.toLowerCase())) {
                    score += 5;
                    reasons.add("Capability: " + cap);
                    break;
                }
            }

            // Match against keywords
            for (String keyword : doc.getKeywords()) {
                if (keyword.toLowerCase().contains(search) || search.contains(keyword.toLowerCase())) {
                    score += 3;
                    reasons.add("Keyword: " + keyword);
                    break;
                }
            }

            // Match in description
            if (doc.getDescription().toLowerCase().contains(search)) {
                score += 2;
                reasons.add("Found in description");
            }

            // Match in tool name
            if (doc.getName().toLowerCase().contains(search)) {
                score += 4;
                reasons.add("Tool name match");
            }

            if (score > 0) {
                matches.add(new ToolMatch(doc, score, reasons));
            }
        }

        // Sort by score
        matches.sort((a, b) -> b.score - a.score);

        Map<String, Object> result = new HashMap<>();
        result.put("search", capability);
        result.put("found", matches.size());

        List<Map<String, Object>> tools = new ArrayList<>();
        for (ToolMatch match : matches) {
            Map<String, Object> toolInfo = new HashMap<>();
            toolInfo.put("tool", match.doc.getName());
            toolInfo.put("score", match.score);
            toolInfo.put("description", match.doc.getDescription());
            toolInfo.put("category", match.doc.getCategory());
            toolInfo.put("match_reasons", match.reasons);

            // Add a simple example if available
            if (!match.doc.getExamples().isEmpty()) {
                toolInfo.put("example", match.doc.getExamples().get(0).get("title"));
            }

            tools.add(toolInfo);
        }
        result.put("tools", tools);

        if (matches.isEmpty()) {
            result.put("suggestion", "No matches found. Try: 'scan', 'proxy', 'intercept', 'decode', 'session', 'websocket'");
            result.put("categories", docStore.getCategories());
        } else {
            result.put("next_step", "Use burp_help with 'tool: \"" + matches.get(0).doc.getName() + "\"' for full documentation");
        }

        return toTextResponse(result);
    }

    /**
     * List all available tools
     */
    private Object listAllTools() {
        Map<String, Object> result = new HashMap<>();
        result.put("total_tools", docStore.getAllDocumentation().size());
        result.put("version", Version.VERSION);

        // Group by category
        Map<String, List<String>> categories = docStore.getCategorizedTools();
        result.put("categories", categories);

        // Tool summaries
        List<Map<String, Object>> summaries = new ArrayList<>();
        for (ToolDocumentation doc : docStore.getAllDocumentation()) {
            Map<String, Object> summary = new HashMap<>();
            summary.put("tool", doc.getName());
            summary.put("category", doc.getCategory());
            summary.put("description", doc.getDescription());
            summary.put("capabilities", doc.getCapabilities());
            summaries.add(summary);
        }
        result.put("tools", summaries);

        result.put("usage_tips", Arrays.asList(
            "Use burp_help with 'capability' to search for tools",
            "Use burp_help with 'tool' to get detailed docs",
            "Tools work together - check 'related_tools' in each tool's docs"
        ));

        return toTextResponse(result);
    }

    /**
     * Usage guide when no parameters provided
     */
    private Object getUsageGuide() {
        Map<String, Object> guide = new HashMap<>();

        int toolCount = docStore.getAllDocumentation().size();
        guide.put("welcome", "Burp MCP Help - " + toolCount + " security testing tools available");

        guide.put("usage", Map.of(
            "list_all_tools", "burp_help(list: true)",
            "find_by_capability", "burp_help(capability: \"scan for vulnerabilities\")",
            "get_tool_docs", "burp_help(tool: \"burp_scanner\")",
            "get_examples_only", "burp_help(tool: \"burp_scanner\", section: \"examples\")"
        ));

        guide.put("quick_start_examples", Arrays.asList(
            Map.of("task", "I want to scan for vulnerabilities",
                   "use", "burp_help(capability: \"scan\")"),
            Map.of("task", "I need to intercept and modify requests",
                   "use", "burp_help(capability: \"intercept\")"),
            Map.of("task", "I want to see all available tools",
                   "use", "burp_help(list: true)"),
            Map.of("task", "I need help with burp_repeater",
                   "use", "burp_help(tool: \"burp_repeater\")")
        ));

        guide.put("categories", docStore.getCategories());

        guide.put("common_capabilities", Arrays.asList(
            "scan", "intercept", "decode", "analyze", "test",
            "crawl", "compare", "session", "websocket"
        ));

        return toTextResponse(guide);
    }

    // Helper methods

    private List<String> findSimilarTools(String input) {
        String lower = input.toLowerCase();
        return docStore.getAllToolNames().stream()
            .filter(name -> name.toLowerCase().contains(lower) ||
                          lower.contains(name.replace("burp_", "")))
            .collect(Collectors.toList());
    }

    private List<String> getRequiredParams(ToolDocumentation doc) {
        return doc.getParameters().stream()
            .filter(p -> Boolean.TRUE.equals(p.get("required")))
            .map(p -> (String) p.get("name"))
            .collect(Collectors.toList());
    }

    private Map<String, Object> getQuickStart(ToolDocumentation doc) {
        Map<String, Object> quickStart = new HashMap<>();

        if (!doc.getExamples().isEmpty()) {
            Map<String, Object> example = doc.getExamples().get(0);
            quickStart.put("simple_example", example.get("input"));
            quickStart.put("description", example.get("title"));
        }

        quickStart.put("required_params", getRequiredParams(doc));

        return quickStart;
    }

    private List<Map<String, Object>> toTextResponse(Map<String, Object> data) {
        Map<String, Object> response = new HashMap<>();
        response.put("type", "text");
        try {
            response.put("text", mapper.writeValueAsString(data));
        } catch (JsonProcessingException e) {
            response.put("text", "Error formatting response: " + e.getMessage());
        }
        return List.of(response);
    }

    // Helper class for matching
    private static class ToolMatch {
        final ToolDocumentation doc;
        final int score;
        final List<String> reasons;

        ToolMatch(ToolDocumentation doc, int score, List<String> reasons) {
            this.doc = doc;
            this.score = score;
            this.reasons = reasons;
        }
    }
}
