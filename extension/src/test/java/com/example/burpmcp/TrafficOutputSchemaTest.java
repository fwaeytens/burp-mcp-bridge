package com.example.burpmcp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.internal.MontoyaObjectFactory;
import burp.api.montoya.internal.ObjectFactoryLocator;
import burp.api.montoya.proxy.ProxyWebSocketMessage;
import burp.api.montoya.websocket.Direction;
import burp.api.montoya.websocket.extension.ExtensionWebSocket;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Proxy;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicLong;

import static com.example.burpmcp.OutputSchemaAssertions.assertDocumented;
import static com.example.burpmcp.OutputSchemaAssertions.assertMatches;
import static org.junit.Assert.*;

/** Real action returns and MCP normalization, using only inert Montoya doubles and local state. */
public class TrafficOutputSchemaTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private final Map<String, McpTool> tools = new LinkedHashMap<>();
    private final Map<String, JsonNode> schemas = new LinkedHashMap<>();
    private MontoyaObjectFactory originalFactory;
    private JsonRpcDispatcher dispatcher;
    private List<ProxyWebSocketMessage> history;

    @Before
    public void setup() {
        originalFactory = ObjectFactoryLocator.FACTORY;
        ObjectFactoryLocator.FACTORY = fake(MontoyaObjectFactory.class, Map.of());
        HttpRequest upgrade = fake(HttpRequest.class, Map.of("url", "https://example.test/socket", "method", "GET"));
        history = List.of(
            fake(ProxyWebSocketMessage.class, Map.of("upgradeRequest", upgrade, "direction", Direction.CLIENT_TO_SERVER,
                "payload", fake(ByteArray.class, Map.of("toString", "short message")))),
            fake(ProxyWebSocketMessage.class, Map.of("upgradeRequest", upgrade, "direction", Direction.SERVER_TO_CLIENT,
                "payload", fake(ByteArray.class, Map.of("toString", "x".repeat(700))))));
        MontoyaApi api = fake(MontoyaApi.class, Map.of());
        // Clear static state before creating the proxy tool, whose constructor initializes handlers.
        new ProxyInterceptorTool(null).close();
        new GlobalInterceptorTool(null).close();
        new WebSocketInterceptorTool(null).close();
        add(new ProxyInterceptorTool(api));
        add(new GlobalInterceptorTool(api));
        add(new WebSocketTool(api));
        add(new WebSocketInterceptorTool(api));
        dispatcher = new JsonRpcDispatcher(JSON, tools, new AsyncToolExecutor() {
            public CompletableFuture<Object> executeAsync(String name, JsonNode args, String host) {
                try { return CompletableFuture.completedFuture(tools.get(name).execute(args)); }
                catch (Exception e) { return CompletableFuture.failedFuture(e); }
            }
            public Object getStats() { return Map.of(); }
        }, () -> 1000, () -> 8081, () -> "offline contract fixture", new ToolDocumentationExporter(tools));
    }

    @After
    public void cleanup() throws Exception {
        try { for (McpTool tool : tools.values()) tool.close(); }
        finally { ObjectFactoryLocator.FACTORY = originalFactory; }
    }

    @Test
    public void proxyRequestResponseAndWebSocketQueuesMatchTheirDistinctShapes() throws Exception {
        String name = "burp_proxy_interceptor";
        call(name, "disable");
        call(name, "enable", "filter_path", "/contract");
        assertTrue(call(name, "enable").path("alreadyEnabled").asBoolean());
        call(name, "get_queue");
        call(name, "get_response_queue");
        call(name, "get_stats");

        HttpRequest request = fake(HttpRequest.class, Map.of("method", "POST", "url", "https://example.test/contract"));
        HttpResponse response = fake(HttpResponse.class, Map.of("statusCode", (short) 204));
        queue(ProxyInterceptorTool.class, "pendingQueue").add(construct(ProxyInterceptorTool.class, "PendingModification",
            new Class<?>[]{String.class, HttpRequest.class, long.class}, "req-1", request, System.currentTimeMillis()));
        queue(ProxyInterceptorTool.class, "pendingResponseQueue").add(construct(ProxyInterceptorTool.class, "PendingResponse",
            new Class<?>[]{String.class, HttpResponse.class, long.class}, "resp-1", response, System.currentTimeMillis()));
        queue(ProxyInterceptorTool.class, "pendingWebSocketQueue").add(construct(ProxyInterceptorTool.class, "PendingWebSocket",
            new Class<?>[]{String.class, HttpRequest.class, long.class}, "ws-1", request, System.currentTimeMillis()));
        JsonNode requests = call(name, "get_queue");
        assertEquals("req-1", requests.path("queue").get(0).path("requestId").asText());
        JsonNode responses = call(name, "get_response_queue");
        assertEquals(204, responses.path("queue").get(0).path("statusCode").asInt());
        call(name, "get_websocket_queue");
        JsonNode messages = call(name, "get_websocket_history");
        assertTrue(messages.path("messages").get(1).path("payloadTruncated").asBoolean());
        assertFalse(messages.path("messages").get(0).has("payloadTruncated"));

        for (String action : List.of("modify_request", "forward_request", "drop_request")) {
            map(ProxyInterceptorTool.class, "responseMap").put("req-1", new CompletableFuture<>());
            call(name, action, "request_id", "req-1", "modifications", Map.of("replace_body", "fixture"));
        }
        for (String action : List.of("modify_response", "forward_response", "drop_response")) {
            map(ProxyInterceptorTool.class, "responseDecisionMap").put("resp-1", new CompletableFuture<>());
            call(name, action, "response_id", "resp-1", "modifications", Map.of("status_code", 201));
        }
        ((AtomicLong) field(ProxyInterceptorTool.class, "interceptedCount")).set(3);
        ((AtomicLong) field(ProxyInterceptorTool.class, "modifiedCount")).set(1);
        assertEquals(33.3, call(name, "get_stats").path("modificationRatePercent").asDouble(), 0.001);
        call(name, "master_intercept_on");
        call(name, "master_intercept_off");
        call(name, "master_intercept_status");
        call(name, "clear_stats");
        call(name, "disable");
        call(name, "disable");

        ObjectNode invalid = requests.deepCopy();
        ((ObjectNode) invalid.path("queue").get(0)).put("ageMs", "old");
        assertThrows(AssertionError.class, () -> assertMatches(schemas.get(name), invalid));
        ObjectNode missing = responses.deepCopy();
        ((ObjectNode) missing.path("queue").get(0)).remove("statusCode");
        assertThrows(AssertionError.class, () -> assertMatches(schemas.get(name), missing));
    }

    @Test
    public void globalActionsTypeCountsRuleSummariesExportsAndNullableAuthentication() throws Exception {
        String name = "burp_global_interceptor";
        call(name, "disable");
        call(name, "enable");
        call(name, "enable");
        call(name, "get_status");
        call(name, "get_stats");
        JsonNode unset = call(name, "export_rules");
        assertTrue(unset.path("settings").path("authType").isNull());
        assertTrue(unset.path("settings").path("authValue").isNull());
        call(name, "set_auth", "auth_type", "bearer", "auth_value", "fixture-token");
        call(name, "add_header", "header_name", "X-Fixture", "header_value", "yes");
        call(name, "list_headers");

        Map<String, Object> requestRule = new LinkedHashMap<>();
        requestRule.put("description", null);
        requestRule.put("url_pattern", "example\\.test");
        requestRule.put("use_regex", true);
        requestRule.put("add_headers", Map.of("X-Rule", "yes"));
        requestRule.put("remove_headers", List.of("X-Remove"));
        call(name, "add_request_rule", "rule_id", "request", "rule", requestRule, "priority", 10);
        call(name, "add_response_rule", "rule_id", "response", "rule", Map.of("change_status", 201), "priority", 20);
        call(name, "add_websocket_rule", "rule_id", "ws", "rule", Map.of("description", "fixture", "match_pattern", "secret.*",
            "use_regex", true, "replace_text", "masked", "direction", "both", "drop", false), "priority", 30);
        assertTrue(call(name, "get_status").path("requestRules").isIntegralNumber());
        JsonNode summaries = call(name, "list_rules");
        assertTrue(summaries.path("requestRules").get(0).path("description").isNull());
        call(name, "list_websocket_rules");
        JsonNode exported = call(name, "export_rules");
        assertEquals("Bearer fixture-token", exported.path("settings").path("authValue").asText());
        assertTrue(exported.path("requestRules").get(0).path("config").isObject());
        call(name, "import_rules", "rules_data", JSON.convertValue(exported, Map.class));
        call(name, "set_mode", "mode", Map.of("intercept_requests", true, "intercept_responses", true,
            "intercept_websockets", true, "use_event_queue", false));
        call(name, "set_tool_filter", "tools", List.of("PROXY", "unknown-fixture-tool"));
        call(name, "get_tool_filter");
        call(name, "reset_tool_filter");
        call(name, "set_rate_limit", "delay", 25);
        assertFalse(call(name, "get_timing_data").has("avgMs"));
        queue(GlobalInterceptorTool.class, "timingHistory").add(construct(GlobalInterceptorTool.class, "TimingInfo",
            new Class<?>[]{String.class, String.class, long.class, String.class}, "GET", "https://example.test/", 25L, "PROXY"));
        assertEquals(25, call(name, "get_timing_data").path("avgMs").asInt());
        call(name, "remove_rule", "rule_id", "request");
        call(name, "remove_rule", "rule_id", "response");
        call(name, "remove_websocket_rule", "rule_id", "ws");
        call(name, "remove_header", "header_name", "X-Fixture");
        call(name, "clear_auth");
        call(name, "clear_stats");
        call(name, "disable");

        call(name, "import_rules", "rules_data", Map.of("settings", Map.of("authType", "custom", "rateLimitDelay", -1)));
        assertTrue(call(name, "get_status").path("authHeader").isNull());
        assertTrue(call(name, "export_rules").path("settings").path("authHeader").isNull());
        call(name, "import_rules", "rules_data", Map.of("requestRules", List.of(Map.of("priority", 1, "config", Map.of()))));
        assertTrue(call(name, "list_rules").path("requestRules").get(0).path("id").isNull());
        assertTrue(call(name, "export_rules").path("requestRules").get(0).path("id").isNull());

        ObjectNode invalid = exported.deepCopy();
        ((ObjectNode) invalid.path("requestRules").get(0)).put("priority", "high");
        assertThrows(AssertionError.class, () -> assertMatches(schemas.get(name), invalid));
        ObjectNode invalidHeaders = exported.deepCopy();
        ((ObjectNode) invalidHeaders.path("globalHeaders")).put("X-Fixture", 3);
        assertThrows(AssertionError.class, () -> assertMatches(schemas.get(name), invalidHeaders));
    }

    @Test
    public void webSocketClientCreatesSendsClosesAndReturnsTypedHistoryAndConnectionRows() throws Exception {
        String name = "burp_websocket";
        call(name, "list_connections");
        JsonNode created = call(name, "create", "url", "wss://example.test/socket");
        String id = created.path("connectionId").asText();
        call(name, "send", "connectionId", id, "message", "offline fixture");
        call(name, "send", "connectionId", id, "message", "AQI=", "messageType", "binary");
        assertEquals(2, call(name, "list_connections").path("connections").get(0).path("messageCount").asInt());
        JsonNode messages = call(name, "proxy_history");
        assertTrue(messages.path("messages").get(0).path("notes").isNull());
        call(name, "proxy_history", "filter", "short", "limit", 1);
        call(name, "close", "connectionId", id);
        assertEquals(0, call(name, "list_connections").path("activeCount").asInt());

        ObjectNode invalid = messages.deepCopy();
        ((ObjectNode) invalid.path("messages").get(0)).put("direction", "inbound");
        assertThrows(AssertionError.class, () -> assertMatches(schemas.get(name), invalid));
    }

    @Test
    public void webSocketInterceptionDistinguishesTextAndBinaryAndDocumentsRuleMaps() throws Exception {
        String name = "burp_websocket_interceptor";
        call(name, "status");
        call(name, "enable");
        call(name, "add_filter", "filter_name", "fixture", "filter_pattern", "example.*");
        call(name, "add_auto_modify", "rule_name", "mask", "search_pattern", "secret", "replace_with", "hidden");
        assertEquals("secret|||hidden", call(name, "status").path("autoModifyRules").path("mask").asText());
        pendingMessage("text-1", "text");
        pendingMessage("binary-1", "binary");
        JsonNode queued = call(name, "get_queue");
        assertEquals(2, queued.path("messages").size());
        call(name, "modify", "message_id", "binary-1", "new_payload", "AwQ=");
        call(name, "forward", "message_id", "text-1");
        pendingMessage("drop-1", "text");
        call(name, "drop", "message_id", "drop-1");
        call(name, "remove_filter", "filter_name", "fixture");
        call(name, "remove_auto_modify", "rule_name", "mask");
        pendingMessage("release-1", "text");
        assertEquals(1, call(name, "disable").path("messagesForwarded").asInt());

        ObjectNode invalid = queued.deepCopy();
        ObjectNode binary = null;
        for (JsonNode row : invalid.path("messages")) if (row.path("type").asText().equals("binary")) binary = (ObjectNode) row;
        assertNotNull(binary);
        binary.remove("size");
        assertThrows(AssertionError.class, () -> assertMatches(schemas.get(name), invalid));
    }

    @Test
    public void listedAnnotationsAndNormalizedVerboseErrorsMatchActualMixedActionTools() throws Exception {
        JsonNode listed = dispatcher.handle("tools/list", JSON.valueToTree(Map.of("id", 1)), "127.0.0.1").path("result").path("tools");
        for (JsonNode tool : listed) {
            JsonNode annotations = tool.path("annotations");
            assertFalse(annotations.path("readOnlyHint").asBoolean());
            assertTrue(annotations.path("destructiveHint").asBoolean());
            assertFalse(annotations.path("idempotentHint").asBoolean());
            assertTrue(annotations.path("openWorldHint").asBoolean());
            assertEquals(schemas.get(tool.path("name").asText()), tool.path("outputSchema"));
        }
        for (Map.Entry<String, String> entry : Map.of("burp_proxy_interceptor", "get_queue",
                "burp_global_interceptor", "get_status", "burp_websocket", "proxy_history",
                "burp_websocket_interceptor", "status").entrySet()) {
            assertTrue(call(entry.getKey(), entry.getValue(), "verbose", true).path("text").isTextual());
            JsonNode error = dispatch(entry.getKey(), Map.of("action", "unknown"));
            assertTrue(error.path("isError").asBoolean());
            assertDocumented(schemas.get(entry.getKey()), error.path("structuredContent"));
            assertTrue(error.path("structuredContent").path("text").isTextual());
        }
        assertNull(TrafficOutputSchemas.forTool("unrelated"));
    }

    private void add(McpTool tool) {
        String name = (String) tool.getToolInfo().get("name");
        tools.put(name, tool);
        schemas.put(name, JSON.valueToTree(AgentToolMetadata.forToolsList(name, tool.getToolInfo())).path("outputSchema"));
    }

    private JsonNode call(String name, String action, Object... options) throws Exception {
        Map<String, Object> args = new LinkedHashMap<>();
        args.put("action", action);
        for (int i = 0; i < options.length; i += 2) args.put((String) options[i], options[i + 1]);
        JsonNode result = dispatch(name, args);
        assertFalse(name + " " + args + ": " + result, result.path("isError").asBoolean());
        JsonNode data = result.path("structuredContent");
        assertTrue(data.toString(), data.isObject());
        assertDocumented(schemas.get(name), data);
        return data;
    }

    private JsonNode dispatch(String name, Map<String, Object> args) throws Exception {
        JsonNode response = dispatcher.handle("tools/call", JSON.valueToTree(Map.of("id", 1, "params", Map.of("name", name, "arguments", args))), "127.0.0.1");
        assertFalse(response.toString(), response.has("error"));
        return response.path("result");
    }

    private void pendingMessage(String id, String type) throws Exception {
        Object message = type.equals("text")
            ? construct(WebSocketInterceptorTool.class, "InterceptedMessage", new Class<?>[]{String.class, String.class, String.class, Direction.class},
                id, "fixture message", "text", Direction.CLIENT_TO_SERVER)
            : construct(WebSocketInterceptorTool.class, "InterceptedMessage", new Class<?>[]{String.class, byte[].class, Direction.class},
                id, new byte[]{1, 2}, Direction.SERVER_TO_CLIENT);
        map(WebSocketInterceptorTool.class, "pendingMessages").put(id, message);
    }

    private static Object construct(Class<?> owner, String nested, Class<?>[] parameterTypes, Object... args) throws Exception {
        Class<?> type = Class.forName(owner.getName() + "$" + nested);
        Constructor<?> constructor = type.getDeclaredConstructor(parameterTypes);
        constructor.setAccessible(true);
        return constructor.newInstance(args);
    }

    private static Object field(Class<?> owner, String name) throws Exception {
        Field field = owner.getDeclaredField(name);
        field.setAccessible(true);
        return field.get(null);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Class<?> owner, String name) throws Exception { return (Map<String, Object>) field(owner, name); }

    @SuppressWarnings("unchecked")
    private static Collection<Object> queue(Class<?> owner, String name) throws Exception { return (Collection<Object>) field(owner, name); }

    @SuppressWarnings("unchecked")
    private <T> T fake(Class<T> type, Map<String, Object> values) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, (proxy, method, args) -> {
            if (values.containsKey(method.getName())) return values.get(method.getName());
            if (method.getName().equals("webSocketHistory")) return history;
            if (method.getName().equals("webSocket")) return Optional.of(fake(ExtensionWebSocket.class, Map.of()));
            if (method.getName().equals("notes")) return null;
            Class<?> result = method.getReturnType();
            if (result == void.class) return null;
            if (result == boolean.class) return method.getName().equals("isRegistered");
            if (result == int.class) return 0;
            if (result == long.class) return 0L;
            if (result == short.class) return (short) 0;
            if (result == String.class) return "";
            if (result == byte[].class) return new byte[0];
            if (result.isEnum()) return result.getEnumConstants()[0];
            if (result == List.class) return List.of();
            if (result.isInterface()) return fake(result, Map.of());
            return null;
        });
    }
}
