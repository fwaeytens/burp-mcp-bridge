package com.example.burpmcp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.Before;
import org.junit.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class JsonRpcDispatcherTest {
    private final ObjectMapper mapper = new ObjectMapper();
    private Map<String, McpTool> tools;
    private JsonRpcDispatcher dispatcher;

    @Before
    public void setUp() {
        tools = new LinkedHashMap<>();
        tools.put("first_tool", new FakeTool("first_tool"));
        tools.put("second_tool", new FakeTool("second_tool"));
        dispatcher = new JsonRpcDispatcher(
            mapper,
            tools,
            new FakeAsyncToolExecutor(tools),
            () -> 1000,
            () -> 8081,
            () -> "test config",
            new ToolDocumentationExporter(tools)
        );
    }

    @Test
    public void toolsListPreservesRegisteredOrder() throws Exception {
        JsonNode response = dispatcher.handle("tools/list", request(1, "tools/list"), "127.0.0.1");
        JsonNode listedTools = response.path("result").path("tools");

        assertEquals(2, listedTools.size());
        assertEquals("first_tool", listedTools.get(0).path("name").asText());
        assertEquals("second_tool", listedTools.get(1).path("name").asText());
    }

    @Test
    public void toolsCallAttachesStructuredContentForJsonText() throws Exception {
        ObjectNode request = request(2, "tools/call");
        request.set("params", mapper.valueToTree(Map.of("name", "first_tool", "arguments", Map.of())));

        JsonNode response = dispatcher.handle("tools/call", request, "127.0.0.1");

        assertFalse(response.has("error"));
        assertTrue(response.path("result").path("structuredContent").path("ok").asBoolean());
        assertEquals("first_tool", response.path("result").path("structuredContent").path("tool").asText());
    }

    @Test
    public void toolsCallAttachesStructuredContentForPlainText() throws Exception {
        tools.put("plain_tool", new PlainTextTool());
        dispatcher = new JsonRpcDispatcher(
            mapper,
            tools,
            new FakeAsyncToolExecutor(tools),
            () -> 1000,
            () -> 8081,
            () -> "test config",
            new ToolDocumentationExporter(tools)
        );

        ObjectNode request = request(6, "tools/call");
        request.set("params", mapper.valueToTree(Map.of("name", "plain_tool", "arguments", Map.of())));

        JsonNode response = dispatcher.handle("tools/call", request, "127.0.0.1");

        assertFalse(response.has("error"));
        assertEquals("plain response", response.path("result").path("structuredContent").path("text").asText());
    }

    @Test
    public void toolsCallWrapsPrimitiveJsonArraysInItems() throws Exception {
        tools.put("array_tool", new PrimitiveArrayTool());
        dispatcher = new JsonRpcDispatcher(
            mapper,
            tools,
            new FakeAsyncToolExecutor(tools),
            () -> 1000,
            () -> 8081,
            () -> "test config",
            new ToolDocumentationExporter(tools)
        );

        ObjectNode request = request(7, "tools/call");
        request.set("params", mapper.valueToTree(Map.of("name", "array_tool", "arguments", Map.of())));

        JsonNode response = dispatcher.handle("tools/call", request, "127.0.0.1");

        assertFalse(response.has("error"));
        assertEquals("first", response.path("result").path("structuredContent").path("items").get(0).asText());
        assertEquals(2, response.path("result").path("structuredContent").path("items").get(1).asInt());
    }

    @Test
    public void toolsCallAttachesStructuredContentForToolExecutionErrors() throws Exception {
        tools.put("error_tool", new ErrorTextTool());
        dispatcher = new JsonRpcDispatcher(
            mapper,
            tools,
            new FakeAsyncToolExecutor(tools),
            () -> 1000,
            () -> 8081,
            () -> "test config",
            new ToolDocumentationExporter(tools)
        );

        ObjectNode request = request(8, "tools/call");
        request.set("params", mapper.valueToTree(Map.of("name", "error_tool", "arguments", Map.of())));

        JsonNode response = dispatcher.handle("tools/call", request, "127.0.0.1");

        assertFalse(response.has("error"));
        assertTrue(response.path("result").path("isError").asBoolean());
        assertEquals("failed", response.path("result").path("structuredContent").path("text").asText());
    }

    @Test
    public void toolsCallAttachesEmptyStructuredContentForNonTextContent() throws Exception {
        tools.put("non_text_tool", new NonTextTool());
        dispatcher = new JsonRpcDispatcher(
            mapper,
            tools,
            new FakeAsyncToolExecutor(tools),
            () -> 1000,
            () -> 8081,
            () -> "test config",
            new ToolDocumentationExporter(tools)
        );

        ObjectNode request = request(9, "tools/call");
        request.set("params", mapper.valueToTree(Map.of("name", "non_text_tool", "arguments", Map.of())));

        JsonNode response = dispatcher.handle("tools/call", request, "127.0.0.1");

        assertFalse(response.has("error"));
        assertTrue(response.path("result").path("structuredContent").isObject());
        assertEquals(0, response.path("result").path("structuredContent").size());
    }

    @Test
    public void unknownToolAndUnknownMethodReturnJsonRpcErrors() throws Exception {
        ObjectNode toolRequest = request(3, "tools/call");
        toolRequest.set("params", mapper.valueToTree(Map.of("name", "missing_tool")));

        JsonNode unknownTool = dispatcher.handle("tools/call", toolRequest, "127.0.0.1");
        JsonNode unknownMethod = dispatcher.handle("missing/method", request(4, "missing/method"), "127.0.0.1");

        assertEquals(-32601, unknownTool.path("error").path("code").asInt());
        assertEquals("Unknown tool: missing_tool", unknownTool.path("error").path("message").asText());
        assertEquals(-32601, unknownMethod.path("error").path("code").asInt());
        assertEquals("Method not found: missing/method", unknownMethod.path("error").path("message").asText());
    }

    @Test
    public void docsExportUsesLiveToolMetadata() throws Exception {
        JsonNode response = dispatcher.handle("docs/export", request(5, "docs/export"), "127.0.0.1");
        JsonNode snapshot = response.path("result");

        assertEquals(Version.VERSION, snapshot.path("version").asText());
        assertEquals(2, snapshot.path("toolCount").asInt());
        assertEquals("first_tool", snapshot.path("tools").get(0).path("name").asText());
        assertEquals("Uncategorized", snapshot.path("tools").get(0).path("category").asText());
        assertEquals(1, snapshot.path("categories").size());
    }

    private ObjectNode request(int id, String method) {
        ObjectNode request = mapper.createObjectNode();
        request.put("jsonrpc", "2.0");
        request.put("id", id);
        request.put("method", method);
        request.set("params", mapper.createObjectNode());
        return request;
    }

    private static final class FakeTool implements McpTool {
        private final String name;

        private FakeTool(String name) {
            this.name = name;
        }

        @Override
        public Map<String, Object> getToolInfo() {
            Map<String, Object> info = new LinkedHashMap<>();
            info.put("name", name);
            info.put("title", name);
            info.put("description", "Fake tool " + name);
            info.put("inputSchema", Map.of("type", "object"));
            return info;
        }

        @Override
        public Object execute(JsonNode arguments) {
            return Map.of(
                "content", List.of(Map.of("type", "text", "text", "{\"ok\":true,\"tool\":\"" + name + "\"}"))
            );
        }
    }

    private static final class FakeAsyncToolExecutor implements AsyncToolExecutor {
        private final Map<String, McpTool> tools;

        private FakeAsyncToolExecutor(Map<String, McpTool> tools) {
            this.tools = tools;
        }

        @Override
        public CompletableFuture<Object> executeAsync(String toolName, JsonNode arguments, String clientHost) {
            try {
                return CompletableFuture.completedFuture(tools.get(toolName).execute(arguments));
            } catch (Exception e) {
                return CompletableFuture.failedFuture(e);
            }
        }

        @Override
        public Object getStats() {
            return "fake stats";
        }
    }

    private static final class PlainTextTool implements McpTool {
        @Override
        public Map<String, Object> getToolInfo() {
            return Map.of(
                "name", "plain_tool",
                "description", "Plain text tool",
                "inputSchema", Map.of("type", "object")
            );
        }

        @Override
        public Object execute(JsonNode arguments) {
            return List.of(Map.of("type", "text", "text", "plain response"));
        }
    }

    private static final class NonTextTool implements McpTool {
        @Override
        public Map<String, Object> getToolInfo() {
            return Map.of(
                "name", "non_text_tool",
                "description", "Non-text tool",
                "inputSchema", Map.of("type", "object")
            );
        }

        @Override
        public Object execute(JsonNode arguments) {
            return List.of(Map.of("type", "image", "data", "ignored"));
        }
    }

    private static final class PrimitiveArrayTool implements McpTool {
        @Override
        public Map<String, Object> getToolInfo() {
            return Map.of(
                "name", "array_tool",
                "description", "Primitive array tool",
                "inputSchema", Map.of("type", "object")
            );
        }

        @Override
        public Object execute(JsonNode arguments) {
            return List.of(Map.of("type", "text", "text", "[\"first\",2]"));
        }
    }

    private static final class ErrorTextTool implements McpTool {
        @Override
        public Map<String, Object> getToolInfo() {
            return Map.of(
                "name", "error_tool",
                "description", "Error text tool",
                "inputSchema", Map.of("type", "object")
            );
        }

        @Override
        public Object execute(JsonNode arguments) {
            return Map.of(
                "content", List.of(Map.of("type", "text", "text", "failed")),
                "isError", true
            );
        }
    }
}
