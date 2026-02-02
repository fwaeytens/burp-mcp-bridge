package com.example.burpmcp;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.Map;

public interface McpTool {
    Map<String, Object> getToolInfo();
    Object execute(JsonNode arguments) throws Exception;
}