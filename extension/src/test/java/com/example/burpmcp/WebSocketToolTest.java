package com.example.burpmcp;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Registration;
import burp.api.montoya.websocket.extension.ExtensionWebSocket;
import burp.api.montoya.websocket.extension.ExtensionWebSocketMessageHandler;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.Test;

import java.lang.reflect.Field;
import java.util.Map;

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

    private static final class NoOpWebSocket implements ExtensionWebSocket {
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
