package com.example.burpmcp;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Builds the checked-in docs snapshot from the same agent-facing metadata
 * returned by tools/list. The JSON file is generated through the docs/export
 * RPC method; it is not a second runtime registry.
 */
final class ToolDocumentationExporter {
    static final String MCP_PROTOCOL_VERSION = "2025-06-18";

    private static final Map<String, String> CATEGORY_DESCRIPTIONS = Map.ofEntries(
        Map.entry("Documentation & Discovery", "Help and tool discovery"),
        Map.entry("Core HTTP/Proxy", "HTTP operations, proxy control, and traffic interception"),
        Map.entry("Scanning & Analysis", "Vulnerability scanning and attack configuration"),
        Map.entry("Issue Management", "Creating and managing security findings"),
        Map.entry("Session Management", "Cookie and session handling"),
        Map.entry("Analysis & Comparison", "Data comparison and out-of-band testing"),
        Map.entry("Configuration & Utilities", "Scope, config, organizer, and annotations"),
        Map.entry("Site Map Analysis", "Site structure and technology analysis"),
        Map.entry("Advanced Filtering", "Bambda-based traffic filtering"),
        Map.entry("Documentation & Logging", "Extension logs and debugging"),
        Map.entry("WebSocket Support", "WebSocket testing and interception"),
        Map.entry("Response Analysis", "Response content analysis and anomaly detection"),
        Map.entry("Utilities", "Encoding, hashing, and data manipulation")
    );

    private final Map<String, McpTool> tools;

    ToolDocumentationExporter(Map<String, McpTool> tools) {
        this.tools = tools;
    }

    Map<String, Object> exportSnapshot() {
        Map<String, Object> snapshot = new LinkedHashMap<>();
        snapshot.put("version", Version.VERSION);
        snapshot.put("mcpVersion", MCP_PROTOCOL_VERSION);
        snapshot.put("toolCount", tools.size());
        snapshot.put("compatibility", compatibility());
        snapshot.put("tools", exportTools());
        snapshot.put("categories", exportCategories());
        return snapshot;
    }

    private Map<String, Object> compatibility() {
        Map<String, Object> compatibility = new LinkedHashMap<>();
        compatibility.put("burpSuite", Version.MIN_BURP_VERSION + "+");
        compatibility.put("java", Version.MIN_JAVA_VERSION + "+");
        compatibility.put("node", "18.14.1+");
        compatibility.put("license", "Professional");
        return compatibility;
    }

    private List<Map<String, Object>> exportTools() {
        List<Map<String, Object>> exportedTools = new ArrayList<>();
        for (Map.Entry<String, McpTool> entry : tools.entrySet()) {
            exportedTools.add(exportTool(entry.getKey(), entry.getValue()));
        }
        return exportedTools;
    }

    private Map<String, Object> exportTool(String toolName, McpTool tool) {
        Map<String, Object> toolInfo = AgentToolMetadata.forToolsList(toolName, tool.getToolInfo());
        Map<String, Object> exported = new LinkedHashMap<>();

        exported.put("name", toolInfo.getOrDefault("name", toolName));
        copyIfPresent(toolInfo, exported, "title");
        exported.put("category", categoryFor(toolName));
        copyIfPresent(toolInfo, exported, "description");
        copyIfPresent(toolInfo, exported, "inputSchema");
        copyIfPresent(toolInfo, exported, "outputSchema");
        copyIfPresent(toolInfo, exported, "annotations");
        copyIfPresent(toolInfo, exported, "_meta");

        for (Map.Entry<String, Object> entry : toolInfo.entrySet()) {
            exported.putIfAbsent(entry.getKey(), entry.getValue());
        }
        return exported;
    }

    private List<Map<String, Object>> exportCategories() {
        Map<String, Integer> counts = new LinkedHashMap<>();
        for (String toolName : tools.keySet()) {
            counts.merge(categoryFor(toolName), 1, Integer::sum);
        }

        List<Map<String, Object>> categories = new ArrayList<>();
        for (Map.Entry<String, Integer> entry : counts.entrySet()) {
            Map<String, Object> category = new LinkedHashMap<>();
            category.put("name", entry.getKey());
            category.put("tools", entry.getValue());
            String description = CATEGORY_DESCRIPTIONS.get(entry.getKey());
            if (description != null) {
                category.put("description", description);
            }
            categories.add(category);
        }
        return categories;
    }

    private String categoryFor(String toolName) {
        ToolDescriptor descriptor = ToolRegistry.get(toolName);
        return descriptor != null ? descriptor.getCategory() : "Uncategorized";
    }

    private void copyIfPresent(Map<String, Object> source, Map<String, Object> target, String key) {
        if (source.containsKey(key)) {
            target.put(key, source.get(key));
        }
    }
}
