package com.example.burpmcp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.ProxyWebSocketMessage;
import burp.api.montoya.websocket.BinaryMessage;
import burp.api.montoya.websocket.TextMessage;
import burp.api.montoya.websocket.extension.ExtensionWebSocketCreation;
import burp.api.montoya.websocket.extension.ExtensionWebSocketMessageHandler;
import burp.api.montoya.websocket.extension.ExtensionWebSocket;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.core.ByteArray;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

public class WebSocketTool implements McpTool {
    private final MontoyaApi api;
    private static final AtomicInteger connectionCounter = new AtomicInteger(0);
    private static final Map<String, ExtensionWebSocket> activeConnections = new ConcurrentHashMap<>();
    private static final Map<String, List<Map<String, Object>>> messageHistory = new ConcurrentHashMap<>();
    
    public WebSocketTool(MontoyaApi api) {
        this.api = api;
    }

    @Override
    public Map<String, Object> getToolInfo() {
        Map<String, Object> tool = new HashMap<>();
        tool.put("name", "burp_websocket");
        tool.put("title", "WebSocket Client");
        tool.put("description", "View WebSocket proxy history and create WebSocket connections. " +
            "Use this to analyze captured WebSocket traffic, create new WebSocket connections, send messages, and manage connection lifecycle. " +
            "Actions: proxy_history (view captured messages), create (new connection), send (send message), close (disconnect), list_connections.");

        // MCP 2025-06-18 annotations
        Map<String, Object> annotations = new HashMap<>();
        annotations.put("readOnlyHint", false);
        annotations.put("destructiveHint", false);
        annotations.put("idempotentHint", false);
        annotations.put("openWorldHint", true);
        tool.put("annotations", annotations);
        
        Map<String, Object> inputSchema = new HashMap<>();
        inputSchema.put("type", "object");
        
        Map<String, Object> properties = new HashMap<>();
        
        properties.put("action", McpUtils.createEnumProperty("string", 
            "Action to perform", 
            List.of("proxy_history", "create", "send", "close", "list_connections"),
            "proxy_history"));
        
        // For creating connections
        properties.put("url", McpUtils.createProperty("string", "WebSocket URL (ws:// or wss://) for create action"));
        properties.put("upgradeRequest", McpUtils.createProperty("string", "Optional HTTP upgrade request for create action"));
        
        // For sending messages
        properties.put("connectionId", McpUtils.createProperty("string", "Connection ID for send/close actions"));
        properties.put("message", McpUtils.createProperty("string", "Message to send"));
        properties.put("messageType", McpUtils.createEnumProperty("string", "Type of message", List.of("text", "binary"), "text"));
        
        // For history
        properties.put("limit", McpUtils.createProperty("integer", "Maximum number of entries to return", 100));
        properties.put("filter", McpUtils.createProperty("string", "Filter messages by content"));
        
        inputSchema.put("properties", properties);
        inputSchema.put("required", List.of("action"));
        
        tool.put("inputSchema", inputSchema);
        return tool;
    }

    @Override
    public Object execute(JsonNode arguments) throws Exception {
        String action = McpUtils.getStringParam(arguments, "action", "proxy_history");
        
        switch (action) {
            case "create":
                return createWebSocket(arguments);
            case "send":
                return sendMessage(arguments);
            case "proxy_history":
                return getProxyWebSocketHistory(arguments);
            case "close":
                return closeConnection(arguments);
            case "list_connections":
                return listActiveConnections();
            default:
                return McpUtils.createErrorResponse("Unknown action: " + action);
        }
    }
    
    private Object createWebSocket(JsonNode arguments) {
        if (!arguments.has("url")) {
            return McpUtils.createErrorResponse("WebSocket URL is required for create action");
        }
        
        String url = arguments.get("url").asText();
        
        try {
            ExtensionWebSocketCreation creation;
            
            if (arguments.has("upgradeRequest")) {
                // Create from HTTP upgrade request
                String requestStr = arguments.get("upgradeRequest").asText();
                
                // Parse the host from the request to create HttpService
                String[] lines = requestStr.split("\r\n");
                String hostHeader = null;
                boolean isSecure = url.startsWith("wss://");
                
                for (String line : lines) {
                    if (line.toLowerCase().startsWith("host:")) {
                        hostHeader = line.substring(5).trim();
                        break;
                    }
                }
                
                if (hostHeader == null) {
                    return McpUtils.createErrorResponse("Host header not found in upgrade request");
                }
                
                // Parse host and port
                String host;
                int port;
                if (hostHeader.contains(":")) {
                    String[] hp = hostHeader.split(":");
                    host = hp[0];
                    try {
                        port = Integer.parseInt(hp[1]);
                    } catch (NumberFormatException e) {
                        port = isSecure ? 443 : 80;
                    }
                } else {
                    host = hostHeader;
                    port = isSecure ? 443 : 80;
                }
                
                HttpService service = HttpService.httpService(host, port, isSecure);
                HttpRequest request = HttpRequest.httpRequest(service, requestStr);
                creation = api.websockets().createWebSocket(request);
            } else {
                // Parse URL to create HttpService
                String host;
                int port;
                boolean secure = url.startsWith("wss://");
                
                String cleanUrl = url.replaceFirst("wss?://", "");
                String[] parts = cleanUrl.split("/", 2);
                String hostPort = parts[0];
                String path = parts.length > 1 ? "/" + parts[1] : "/";
                
                if (hostPort.contains(":")) {
                    String[] hp = hostPort.split(":");
                    host = hp[0];
                    try {
                        port = Integer.parseInt(hp[1]);
                    } catch (NumberFormatException e) {
                        return McpUtils.createErrorResponse("Invalid port number: " + hp[1]);
                    }
                } else {
                    host = hostPort;
                    port = secure ? 443 : 80;
                }
                
                HttpService service = HttpService.httpService(host, port, secure);
                creation = api.websockets().createWebSocket(service, path);
            }
            
            // Check if WebSocket was created successfully
            if (creation.webSocket().isPresent()) {
                ExtensionWebSocket webSocket = creation.webSocket().get();
                
                // Generate connection ID
                String connectionId = "ws-" + connectionCounter.incrementAndGet();
                activeConnections.put(connectionId, webSocket);
                messageHistory.put(connectionId, new ArrayList<>());
                
                // Register message handler to track messages
                webSocket.registerMessageHandler(new ExtensionWebSocketMessageHandler() {
                    @Override
                    public void textMessageReceived(TextMessage message) {
                        recordMessage(connectionId, "text", message.payload(), "SERVER_TO_CLIENT");
                    }
                    
                    @Override
                    public void binaryMessageReceived(BinaryMessage message) {
                        recordMessage(connectionId, "binary", 
                            Base64.getEncoder().encodeToString(message.payload().getBytes()), 
                            "SERVER_TO_CLIENT");
                    }
                    
                    @Override
                    public void onClose() {
                        // Handle close event if needed
                    }
                });
                
                StringBuilder result = new StringBuilder();
                result.append("✅ WebSocket connection created\n\n");
                result.append("**Connection ID:** ").append(connectionId).append("\n");
                result.append("**URL:** ").append(url).append("\n");
                result.append("**Status:** ").append(creation.status().name()).append("\n\n");
                result.append("Use this connection ID to send messages or close the connection.");
                
                return McpUtils.createSuccessResponse(result.toString());
            } else {
                return McpUtils.createErrorResponse("Failed to create WebSocket connection. Status: " + creation.status().name());
            }
            
        } catch (Exception e) {
            return McpUtils.createErrorResponse("Failed to create WebSocket: " + e.getMessage());
        }
    }
    
    private Object sendMessage(JsonNode arguments) {
        if (!arguments.has("connectionId") || !arguments.has("message")) {
            return McpUtils.createErrorResponse("Connection ID and message are required for send action");
        }
        
        String connectionId = arguments.get("connectionId").asText();
        String message = arguments.get("message").asText();
        String messageType = McpUtils.getStringParam(arguments, "messageType", "text");
        
        ExtensionWebSocket webSocket = activeConnections.get(connectionId);
        if (webSocket == null) {
            return McpUtils.createErrorResponse("Connection not found: " + connectionId);
        }
        
        try {
            if ("binary".equals(messageType)) {
                byte[] bytes = Base64.getDecoder().decode(message);
                webSocket.sendBinaryMessage(ByteArray.byteArray(bytes));
                recordMessage(connectionId, "binary", message, "CLIENT_TO_SERVER");
            } else {
                webSocket.sendTextMessage(message);
                recordMessage(connectionId, "text", message, "CLIENT_TO_SERVER");
            }
            
            return McpUtils.createSuccessResponse("Message sent successfully to " + connectionId);
            
        } catch (Exception e) {
            return McpUtils.createErrorResponse("Failed to send message: " + e.getMessage());
        }
    }
    
    private Object getProxyWebSocketHistory(JsonNode arguments) {
        int limit = McpUtils.getIntParam(arguments, "limit", 100);
        String filter = McpUtils.getStringParam(arguments, "filter", "");
        
        try {
            List<ProxyWebSocketMessage> history = api.proxy().webSocketHistory();
            
            StringBuilder result = new StringBuilder();
            result.append("## Proxy WebSocket History\n\n");
            result.append("**Total Messages:** ").append(history.size()).append("\n\n");
            
            int count = 0;
            for (int i = history.size() - 1; i >= 0 && count < limit; i--) {
                ProxyWebSocketMessage msg = history.get(i);
                String payload = msg.payload().toString();
                
                if (!filter.isEmpty() && !payload.toLowerCase().contains(filter.toLowerCase())) {
                    continue;
                }
                
                result.append("### Message ").append(count + 1).append("\n");
                result.append("**URL:** ").append(msg.upgradeRequest().url()).append("\n");
                result.append("**Direction:** ").append(msg.direction().name()).append("\n");
                result.append("**Payload:** ").append(McpUtils.truncateText(payload, 500)).append("\n");
                result.append("**Annotations:** ").append(msg.annotations().notes()).append("\n\n");
                count++;
            }
            
            if (count == 0) {
                result.append("No WebSocket messages found");
                if (!filter.isEmpty()) {
                    result.append(" matching filter: ").append(filter);
                }
            }
            
            return McpUtils.createSuccessResponse(result.toString());
            
        } catch (Exception e) {
            return McpUtils.createErrorResponse("Failed to retrieve WebSocket history: " + e.getMessage());
        }
    }
    
    private Object closeConnection(JsonNode arguments) {
        if (!arguments.has("connectionId")) {
            return McpUtils.createErrorResponse("Connection ID is required for close action");
        }
        
        String connectionId = arguments.get("connectionId").asText();
        ExtensionWebSocket webSocket = activeConnections.remove(connectionId);
        
        if (webSocket == null) {
            return McpUtils.createErrorResponse("Connection not found: " + connectionId);
        }
        
        try {
            webSocket.close();
            return McpUtils.createSuccessResponse("Connection " + connectionId + " closed successfully");
        } catch (Exception e) {
            return McpUtils.createErrorResponse("Failed to close connection: " + e.getMessage());
        }
    }
    
    private Object listActiveConnections() {
        StringBuilder result = new StringBuilder();
        result.append("## Active WebSocket Connections\n\n");
        
        if (activeConnections.isEmpty()) {
            result.append("No active connections");
        } else {
            for (Map.Entry<String, ExtensionWebSocket> entry : activeConnections.entrySet()) {
                String id = entry.getKey();
                List<Map<String, Object>> history = messageHistory.get(id);
                
                result.append("**ID:** ").append(id).append("\n");
                result.append("**Messages:** ").append(history != null ? history.size() : 0).append("\n\n");
            }
        }
        
        return McpUtils.createSuccessResponse(result.toString());
    }
    
    private void recordMessage(String connectionId, String type, String content, String direction) {
        List<Map<String, Object>> history = messageHistory.get(connectionId);
        if (history != null) {
            Map<String, Object> message = new HashMap<>();
            message.put("time", ZonedDateTime.now().format(DateTimeFormatter.ISO_INSTANT));
            message.put("type", type);
            message.put("content", content);
            message.put("direction", direction);
            history.add(message);
        }
    }
}