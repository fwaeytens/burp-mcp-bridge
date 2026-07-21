package com.example.burpmcp;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.Map;

public interface McpTool {
    Map<String, Object> getToolInfo();
    Object execute(JsonNode arguments) throws Exception;

    /**
     * Release registrations, background workers, and in-memory state owned by this tool.
     * Stateful tools override this; stateless tools inherit the no-op default.
     */
    default void close() throws Exception {
        // No-op by default.
    }
}
