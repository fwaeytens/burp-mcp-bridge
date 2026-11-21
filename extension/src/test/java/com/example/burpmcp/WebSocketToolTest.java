package com.example.burpmcp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Registration;
import burp.api.montoya.internal.MontoyaObjectFactory;
import burp.api.montoya.internal.ObjectFactoryLocator;
import burp.api.montoya.websocket.TextMessage;
import burp.api.montoya.websocket.extension.ExtensionWebSocket;
import burp.api.montoya.websocket.extension.ExtensionWebSocketMessageHandler;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.Test;

import java.lang.reflect.Field;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class WebSocketToolTest {
    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    @SuppressWarnings("unchecked")
    public void sendAfterCloseReturnsCleanExecutorShutdownError() throws Exception {
        WebSocketTool tool = new WebSocketTool(null);
        tool.close();

        Field activeConnectionsField = WebSocketTool.class.getDeclaredField("activeConnections");
        activeConnectionsField.setAccessible(true);
        Map<String, ExtensionWebSocket> activeConnections =
            (Map<String, ExtensionWebSocket>) activeConnectionsField.get(null);
        activeConnections.put("closed-tool-connection", new NoOpWebSocket());

        try {
            ObjectNode arguments = mapper.createObjectNode();
            arguments.put("action", "send");
            arguments.put("connectionId", "closed-tool-connection");
            arguments.put("message", "hello");

            Map<String, Object> response = (Map<String, Object>) tool.execute(arguments);
            assertEquals(true, response.get("isError"));

            String text = (String) ((Map<String, Object>) ((java.util.List<?>) response.get("content")).get(0)).get("text");
            assertTrue(text.contains("WebSocket send executor is shutting down"));
        } finally {
            activeConnections.clear();
        }
    }

    /**
     * Incoming messages are recorded on Burp's WebSocket callback thread while outgoing
     * ones are recorded on MCP worker threads, so the per-connection history is appended
     * to concurrently. The connection is created through the real create action so the
     * history under test is the one production code builds.
     */
    @Test
    public void concurrentIncomingAndOutgoingMessagesAreAllRecorded() throws Exception {
        final int receiverThreads = 8;
        final int receivedPerThread = 2000;
        final int senderThreads = 4;
        final int sentPerThread = 100;

        AtomicReference<ExtensionWebSocketMessageHandler> handler = new AtomicReference<>();
        ExtensionWebSocket socket = new NoOpWebSocket() {
            @Override
            public Registration registerMessageHandler(ExtensionWebSocketMessageHandler registered) {
                handler.set(registered);
                return null;
            }
        };
        MontoyaObjectFactory originalFactory = ObjectFactoryLocator.FACTORY;
        ObjectFactoryLocator.FACTORY = fake(MontoyaObjectFactory.class, Map.of());
        WebSocketTool tool = new WebSocketTool(fake(MontoyaApi.class, Map.of("webSocket", Optional.of(socket))));
        ExecutorService pool = Executors.newFixedThreadPool(receiverThreads + senderThreads);
        try {
            ObjectNode create = mapper.createObjectNode();
            create.put("action", "create");
            create.put("url", "wss://example.test/socket");
            String connectionId = structured(tool.execute(create)).path("connectionId").asText();
            assertTrue("create should register a message handler", handler.get() != null);

            TextMessage incoming = fake(TextMessage.class, Map.of("payload", "from-server"));
            ObjectNode send = mapper.createObjectNode();
            send.put("action", "send");
            send.put("connectionId", connectionId);
            send.put("message", "from-client");

            CountDownLatch start = new CountDownLatch(1);
            List<Future<?>> workers = new ArrayList<>();
            for (int t = 0; t < receiverThreads; t++) {
                workers.add(pool.submit(() -> {
                    start.await();
                    for (int i = 0; i < receivedPerThread; i++) handler.get().textMessageReceived(incoming);
                    return null;
                }));
            }
            for (int t = 0; t < senderThreads; t++) {
                workers.add(pool.submit(() -> {
                    start.await();
                    for (int i = 0; i < sentPerThread; i++) tool.execute(send);
                    return null;
                }));
            }
            start.countDown();
            for (Future<?> worker : workers) worker.get(60, TimeUnit.SECONDS);

            ObjectNode list = mapper.createObjectNode();
            list.put("action", "list_connections");
            JsonNode connections = structured(tool.execute(list)).path("connections");
            assertEquals(1, connections.size());
            assertEquals(receiverThreads * receivedPerThread + senderThreads * sentPerThread,
                connections.get(0).path("messageCount").asInt());
        } finally {
            pool.shutdownNow();
            tool.close();
            ObjectFactoryLocator.FACTORY = originalFactory;
        }
    }

    private JsonNode structured(Object response) {
        JsonNode node = mapper.valueToTree(response);
        assertTrue(node.toString(), !node.path("isError").asBoolean());
        return node.path("structuredContent");
    }

    /** Interface stub: named methods return the given values, everything else a harmless default. */
    @SuppressWarnings("unchecked")
    private static <T> T fake(Class<T> type, Map<String, Object> values) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, (proxy, method, args) -> {
            if (values.containsKey(method.getName())) return values.get(method.getName());
            Class<?> result = method.getReturnType();
            if (result == void.class) return null;
            if (result == boolean.class) return false;
            if (result == int.class) return 0;
            if (result == long.class) return 0L;
            if (result == String.class) return "";
            if (result.isEnum()) return result.getEnumConstants()[0];
            if (result.isInterface()) return fake(result, values);
            return null;
        });
    }

    private static class NoOpWebSocket implements ExtensionWebSocket {
        @Override
        public void sendTextMessage(String message) {
        }

        @Override
        public void sendBinaryMessage(ByteArray message) {
        }

        @Override
        public void close() {
        }

        @Override
        public Registration registerMessageHandler(ExtensionWebSocketMessageHandler handler) {
            return null;
        }
    }
}
