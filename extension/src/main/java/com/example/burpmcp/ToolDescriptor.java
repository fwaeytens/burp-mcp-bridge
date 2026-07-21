package com.example.burpmcp;

import burp.api.montoya.MontoyaApi;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Immutable registry entry for a single MCP tool.
 */
public final class ToolDescriptor {
    @FunctionalInterface
    public interface Factory {
        McpTool create(MontoyaApi api);
    }

    private final String name;
    private final String category;
    private final Factory factory;
    private final List<String> keywords;
    private final List<String> capabilities;
    private final Map<String, List<String>> actionRequirements;
    private final boolean includeInHelpDocs;

    public ToolDescriptor(String name,
                          String category,
                          Factory factory,
                          List<String> keywords,
                          List<String> capabilities,
                          Map<String, List<String>> actionRequirements,
                          boolean includeInHelpDocs) {
        this.name = name;
        this.category = category;
        this.factory = factory;
        this.keywords = List.copyOf(keywords);
        this.capabilities = List.copyOf(capabilities);
        this.actionRequirements = copyActionRequirements(actionRequirements);
        this.includeInHelpDocs = includeInHelpDocs;
    }

    public String getName() {
        return name;
    }

    public String getCategory() {
        return category;
    }

    public McpTool create(MontoyaApi api) {
        return factory.create(api);
    }

    public List<String> getKeywords() {
        return new ArrayList<>(keywords);
    }

    public List<String> getCapabilities() {
        return new ArrayList<>(capabilities);
    }

    public Map<String, List<String>> getActionRequirements() {
        return copyActionRequirements(actionRequirements);
    }

    public boolean isIncludedInHelpDocs() {
        return includeInHelpDocs;
    }

    private static Map<String, List<String>> copyActionRequirements(Map<String, List<String>> source) {
        Map<String, List<String>> copy = new LinkedHashMap<>();
        if (source != null) {
            source.forEach((action, params) ->
                copy.put(action, params == null ? List.of() : List.copyOf(params)));
        }
        return copy;
    }
}
