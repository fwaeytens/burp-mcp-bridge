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
}
