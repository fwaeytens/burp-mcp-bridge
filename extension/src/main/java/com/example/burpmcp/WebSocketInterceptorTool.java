package com.example.burpmcp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Registration;
import burp.api.montoya.proxy.websocket.*;
import burp.api.montoya.websocket.Direction;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

public class WebSocketInterceptorTool implements McpTool {
    private final MontoyaApi api;
    private static final AtomicBoolean interceptEnabled = new AtomicBoolean(false);
    private static Registration currentRegistration;
    private static final Queue<InterceptedMessage> messageQueue = new ConcurrentLinkedQueue<>();
    private static final AtomicInteger messageIdCounter = new AtomicInteger(0);
    private static final Map<String, InterceptedMessage> pendingMessages = new ConcurrentHashMap<>();
    private static final Map<String, Pattern> activeFilters = new ConcurrentHashMap<>();
    private static final Map<String, String> autoModifyRules = new ConcurrentHashMap<>();
    
    // Statistics
    private static final AtomicInteger totalIntercepted = new AtomicInteger(0);
    private static final AtomicInteger totalModified = new AtomicInteger(0);
    private static final AtomicInteger totalDropped = new AtomicInteger(0);
    
    public WebSocketInterceptorTool(MontoyaApi api) {
        this.api = api;
    }
    
    @Override
    public Map<String, Object> getToolInfo() {
        Map<String, Object> tool = new HashMap<>();
        tool.put("name", "burp_websocket_interceptor");
        tool.put("title", "WebSocket Interceptor");
        tool.put("description", "Intercept and modify WebSocket messages in real-time. " +
            "Use this for testing WebSocket-based applications by intercepting, modifying, and filtering messages. " +
            "Supports text and binary messages with match/replace rules. " +
            "Actions: enable/disable, status, get_queue, forward/drop/modify (message control), add/remove_filter, add/remove_auto_modify.");

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
            List.of("enable", "disable", "status", "get_queue", "forward", "drop", "modify", 
                    "add_filter", "remove_filter", "add_auto_modify", "remove_auto_modify"),
            "status"));
        
        // For message handling
        properties.put("message_id", McpUtils.createProperty("string", "Message ID for forward/drop/modify actions"));
        properties.put("new_payload", McpUtils.createProperty("string", 
            "New payload for modify action. For text messages: plain text. For binary messages: Base64 encoded data"));
        
        // For filters
        properties.put("filter_name", McpUtils.createProperty("string", "Name for the filter"));
        properties.put("filter_pattern", McpUtils.createProperty("string", 
            "Regex pattern to match messages. For binary messages, pattern is matched against hex representation"));
        
        // For auto-modify rules
        properties.put("rule_name", McpUtils.createProperty("string", "Name for the auto-modify rule (text messages only)"));
        properties.put("search_pattern", McpUtils.createProperty("string", "Pattern to search for in text messages"));
        properties.put("replace_with", McpUtils.createProperty("string", "Replacement text"));
        
        inputSchema.put("properties", properties);
        inputSchema.put("required", List.of("action"));
        
        tool.put("inputSchema", inputSchema);
        return tool;
    }
    
    @Override
    public Object execute(JsonNode arguments) throws Exception {
        String action = McpUtils.getStringParam(arguments, "action", "status");
        
        switch (action) {
            case "enable":
                return enableInterceptor();
            case "disable":
                return disableInterceptor();
            case "status":
                return getStatus();
            case "get_queue":
                return getMessageQueue();
            case "forward":
                return forwardMessage(arguments);
            case "drop":
                return dropMessage(arguments);
            case "modify":
                return modifyMessage(arguments);
            case "add_filter":
                return addFilter(arguments);
            case "remove_filter":
                return removeFilter(arguments);
            case "add_auto_modify":
                return addAutoModifyRule(arguments);
            case "remove_auto_modify":
                return removeAutoModifyRule(arguments);
            default:
                return McpUtils.createErrorResponse("Unknown action: " + action);
        }
    }
    
    private Object enableInterceptor() {
        if (interceptEnabled.get()) {
            return McpUtils.createErrorResponse("WebSocket interceptor is already enabled");
        }
        
        try {
            // Register WebSocket creation handler
            currentRegistration = api.proxy().registerWebSocketCreationHandler(creation -> {
                ProxyWebSocket proxyWebSocket = creation.proxyWebSocket();
                
                // Register message handler for this WebSocket
                proxyWebSocket.registerProxyMessageHandler(new ProxyMessageHandler() {
                    @Override
                    public TextMessageReceivedAction handleTextMessageReceived(InterceptedTextMessage message) {
                        return processTextMessageReceived(message, Direction.SERVER_TO_CLIENT);
                    }
                    
                    @Override
                    public TextMessageToBeSentAction handleTextMessageToBeSent(InterceptedTextMessage message) {
                        return processTextMessageToBeSent(message, Direction.CLIENT_TO_SERVER);
                    }
                    
                    @Override
                    public BinaryMessageReceivedAction handleBinaryMessageReceived(InterceptedBinaryMessage message) {
                        return processBinaryMessageReceived(message, Direction.SERVER_TO_CLIENT);
                    }
                    
                    @Override
                    public BinaryMessageToBeSentAction handleBinaryMessageToBeSent(InterceptedBinaryMessage message) {
                        return processBinaryMessageToBeSent(message, Direction.CLIENT_TO_SERVER);
                    }
                });
            });
            
            interceptEnabled.set(true);
            messageQueue.clear();
            pendingMessages.clear();
            
            return McpUtils.createSuccessResponse("✅ WebSocket interceptor enabled\n\n" +
                "All new WebSocket connections will be intercepted.\n" +
                "Use 'get_queue' to see intercepted messages.\n" +
                "Use 'forward', 'drop', or 'modify' to handle messages.");
            
        } catch (Exception e) {
            return McpUtils.createErrorResponse("Failed to enable interceptor: " + e.getMessage());
        }
    }
    
    private Object disableInterceptor() {
        if (!interceptEnabled.get()) {
            return McpUtils.createErrorResponse("WebSocket interceptor is not enabled");
        }
        
        if (currentRegistration != null) {
            currentRegistration.deregister();
            currentRegistration = null;
        }
        
        interceptEnabled.set(false);
        
        // Forward all pending messages
        int forwarded = 0;
        for (InterceptedMessage msg : pendingMessages.values()) {
            msg.action = MessageAction.FORWARD;
            forwarded++;
        }
        
        return McpUtils.createSuccessResponse("✅ WebSocket interceptor disabled\n\n" +
            "Forwarded " + forwarded + " pending messages.");
    }
    
    private Object getStatus() {
        StringBuilder result = new StringBuilder();
        result.append("## WebSocket Interceptor Status\n\n");
        result.append("**Enabled:** ").append(interceptEnabled.get() ? "✅ Yes" : "❌ No").append("\n");
        result.append("**Pending Messages:** ").append(pendingMessages.size()).append("\n");
        result.append("**Total Intercepted:** ").append(totalIntercepted.get()).append("\n");
        result.append("**Total Modified:** ").append(totalModified.get()).append("\n");
        result.append("**Total Dropped:** ").append(totalDropped.get()).append("\n\n");
        
        if (!activeFilters.isEmpty()) {
            result.append("### Active Filters\n");
            for (Map.Entry<String, Pattern> entry : activeFilters.entrySet()) {
                result.append("- **").append(entry.getKey()).append(":** `")
                      .append(entry.getValue().pattern()).append("`\n");
            }
            result.append("\n");
        }
        
        if (!autoModifyRules.isEmpty()) {
            result.append("### Auto-Modify Rules\n");
            for (Map.Entry<String, String> entry : autoModifyRules.entrySet()) {
                result.append("- **").append(entry.getKey()).append(":** ")
                      .append(entry.getValue()).append("\n");
            }
        }
        
        return McpUtils.createSuccessResponse(result.toString());
    }
    
    private Object getMessageQueue() {
        StringBuilder result = new StringBuilder();
        result.append("## Intercepted WebSocket Messages\n\n");
        
        if (pendingMessages.isEmpty()) {
            result.append("No messages in queue");
        } else {
            int count = 0;
            for (InterceptedMessage msg : pendingMessages.values()) {
                if (count++ >= 10) break; // Limit to 10 messages
                
                result.append("### Message ").append(msg.id).append("\n");
                result.append("**Direction:** ").append(msg.direction.name()).append("\n");
                result.append("**Type:** ").append(msg.type).append("\n");
                
                if ("binary".equals(msg.type)) {
                    result.append("**Payload (Base64):** ").append(McpUtils.truncateText(msg.payload, 200)).append("\n");
                    result.append("**Size:** ").append(msg.binaryPayload != null ? msg.binaryPayload.length : "N/A").append(" bytes\n");
                } else {
                    result.append("**Payload:** ").append(McpUtils.truncateText(msg.payload, 200)).append("\n");
                }
                
                result.append("**Status:** PENDING\n\n");
            }
            
            if (pendingMessages.size() > 10) {
                result.append("... and ").append(pendingMessages.size() - 10).append(" more messages\n");
            }
        }
        
        return McpUtils.createSuccessResponse(result.toString());
    }
    
    private Object forwardMessage(JsonNode arguments) {
        String messageId = McpUtils.getStringParam(arguments, "message_id", "");
        if (messageId.isEmpty()) {
            return McpUtils.createErrorResponse("message_id is required");
        }
        
        InterceptedMessage msg = pendingMessages.remove(messageId);
        if (msg == null) {
            return McpUtils.createErrorResponse("Message not found: " + messageId);
        }
        
        msg.action = MessageAction.FORWARD;
        return McpUtils.createSuccessResponse("Message " + messageId + " forwarded");
    }
    
    private Object dropMessage(JsonNode arguments) {
        String messageId = McpUtils.getStringParam(arguments, "message_id", "");
        if (messageId.isEmpty()) {
            return McpUtils.createErrorResponse("message_id is required");
        }
        
        InterceptedMessage msg = pendingMessages.remove(messageId);
        if (msg == null) {
            return McpUtils.createErrorResponse("Message not found: " + messageId);
        }
        
        msg.action = MessageAction.DROP;
        totalDropped.incrementAndGet();
        return McpUtils.createSuccessResponse("Message " + messageId + " dropped");
    }
    
    private Object modifyMessage(JsonNode arguments) {
        String messageId = McpUtils.getStringParam(arguments, "message_id", "");
        String newPayload = McpUtils.getStringParam(arguments, "new_payload", "");
        
        if (messageId.isEmpty() || newPayload.isEmpty()) {
            return McpUtils.createErrorResponse("message_id and new_payload are required");
        }
        
        InterceptedMessage msg = pendingMessages.remove(messageId);
        if (msg == null) {
            return McpUtils.createErrorResponse("Message not found: " + messageId);
        }
        
        // Handle binary messages - expect Base64 encoded payload
        if ("binary".equals(msg.type)) {
            try {
                msg.binaryPayload = Base64.getDecoder().decode(newPayload);
                msg.payload = newPayload; // Keep Base64 version for display
            } catch (IllegalArgumentException e) {
                return McpUtils.createErrorResponse("Invalid Base64 encoding for binary message: " + e.getMessage());
            }
        } else {
            msg.payload = newPayload;
        }
        
        msg.action = MessageAction.MODIFY;
        totalModified.incrementAndGet();
        
        return McpUtils.createSuccessResponse("Message " + messageId + " modified and forwarded");
    }
    
    private Object addFilter(JsonNode arguments) {
        String name = McpUtils.getStringParam(arguments, "filter_name", "");
        String pattern = McpUtils.getStringParam(arguments, "filter_pattern", "");
        
        if (name.isEmpty() || pattern.isEmpty()) {
            return McpUtils.createErrorResponse("filter_name and filter_pattern are required");
        }
        
        try {
            activeFilters.put(name, Pattern.compile(pattern));
            return McpUtils.createSuccessResponse("Filter '" + name + "' added");
        } catch (Exception e) {
            return McpUtils.createErrorResponse("Invalid regex pattern: " + e.getMessage());
        }
    }
    
    private Object removeFilter(JsonNode arguments) {
        String name = McpUtils.getStringParam(arguments, "filter_name", "");
        if (name.isEmpty()) {
            return McpUtils.createErrorResponse("filter_name is required");
        }
        
        if (activeFilters.remove(name) != null) {
            return McpUtils.createSuccessResponse("Filter '" + name + "' removed");
        }
        return McpUtils.createErrorResponse("Filter not found: " + name);
    }
    
    private Object addAutoModifyRule(JsonNode arguments) {
        String name = McpUtils.getStringParam(arguments, "rule_name", "");
        String search = McpUtils.getStringParam(arguments, "search_pattern", "");
        String replace = McpUtils.getStringParam(arguments, "replace_with", "");
        
        if (name.isEmpty() || search.isEmpty()) {
            return McpUtils.createErrorResponse("rule_name and search_pattern are required");
        }
        
        autoModifyRules.put(name, search + "|||" + replace);
        return McpUtils.createSuccessResponse("Auto-modify rule '" + name + "' added");
    }
    
    private Object removeAutoModifyRule(JsonNode arguments) {
        String name = McpUtils.getStringParam(arguments, "rule_name", "");
        if (name.isEmpty()) {
            return McpUtils.createErrorResponse("rule_name is required");
        }
        
        if (autoModifyRules.remove(name) != null) {
            return McpUtils.createSuccessResponse("Auto-modify rule '" + name + "' removed");
        }
        return McpUtils.createErrorResponse("Rule not found: " + name);
    }
    
    private TextMessageReceivedAction processTextMessageReceived(InterceptedTextMessage message, Direction direction) {
        String payload = message.payload();
        
        // Apply auto-modify rules
        for (String rule : autoModifyRules.values()) {
            String[] parts = rule.split("\\|\\|\\|");
            if (parts.length == 2) {
                payload = payload.replaceAll(parts[0], parts[1]);
            }
        }
        
        // Check filters
        boolean shouldIntercept = activeFilters.isEmpty();
        for (Pattern pattern : activeFilters.values()) {
            if (pattern.matcher(payload).find()) {
                shouldIntercept = true;
                break;
            }
        }
        
        if (!shouldIntercept) {
            return TextMessageReceivedAction.continueWith(payload);
        }
        
        // Create intercepted message
        String messageId = "msg-" + messageIdCounter.incrementAndGet();
        InterceptedMessage intercepted = new InterceptedMessage(messageId, payload, "text", direction);
        pendingMessages.put(messageId, intercepted);
        totalIntercepted.incrementAndGet();
        
        // Wait for user action
        long timeout = System.currentTimeMillis() + 30000; // 30 second timeout
        while (intercepted.action == MessageAction.PENDING && System.currentTimeMillis() < timeout) {
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                break;
            }
        }
        
        // Handle action
        switch (intercepted.action) {
            case DROP:
                return TextMessageReceivedAction.drop();
            case MODIFY:
                return TextMessageReceivedAction.continueWith(intercepted.payload);
            default:
                return TextMessageReceivedAction.continueWith(payload);
        }
    }
    
    private TextMessageToBeSentAction processTextMessageToBeSent(InterceptedTextMessage message, Direction direction) {
        // Similar logic but return TextMessageToBeSentAction
        String payload = message.payload();
        
        // Apply auto-modify rules
        for (String rule : autoModifyRules.values()) {
            String[] parts = rule.split("\\|\\|\\|");
            if (parts.length == 2) {
                payload = payload.replaceAll(parts[0], parts[1]);
            }
        }
        
        // Check filters
        boolean shouldIntercept = activeFilters.isEmpty();
        for (Pattern pattern : activeFilters.values()) {
            if (pattern.matcher(payload).find()) {
                shouldIntercept = true;
                break;
            }
        }
        
        if (!shouldIntercept) {
            return TextMessageToBeSentAction.continueWith(payload);
        }
        
        // Create intercepted message
        String messageId = "msg-" + messageIdCounter.incrementAndGet();
        InterceptedMessage intercepted = new InterceptedMessage(messageId, payload, "text", direction);
        pendingMessages.put(messageId, intercepted);
        totalIntercepted.incrementAndGet();
        
        // Wait for user action
        long timeout = System.currentTimeMillis() + 30000; // 30 second timeout
        while (intercepted.action == MessageAction.PENDING && System.currentTimeMillis() < timeout) {
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                break;
            }
        }
        
        // Handle action
        switch (intercepted.action) {
            case DROP:
                return TextMessageToBeSentAction.drop();
            case MODIFY:
                return TextMessageToBeSentAction.continueWith(intercepted.payload);
            default:
                return TextMessageToBeSentAction.continueWith(payload);
        }
    }
    
    private BinaryMessageReceivedAction processBinaryMessageReceived(InterceptedBinaryMessage message, Direction direction) {
        byte[] payload = message.payload().getBytes();
        
        // Check filters (convert to hex string for pattern matching)
        String hexPayload = bytesToHex(payload);
        boolean shouldIntercept = activeFilters.isEmpty();
        for (Pattern pattern : activeFilters.values()) {
            if (pattern.matcher(hexPayload).find()) {
                shouldIntercept = true;
                break;
            }
        }
        
        if (!shouldIntercept) {
            return BinaryMessageReceivedAction.continueWith(message);
        }
        
        // Create intercepted message
        String messageId = "msg-" + messageIdCounter.incrementAndGet();
        InterceptedMessage intercepted = new InterceptedMessage(messageId, payload, direction);
        pendingMessages.put(messageId, intercepted);
        totalIntercepted.incrementAndGet();
        
        // Wait for user action
        long timeout = System.currentTimeMillis() + 30000; // 30 second timeout
        while (intercepted.action == MessageAction.PENDING && System.currentTimeMillis() < timeout) {
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                break;
            }
        }
        
        // Handle action
        switch (intercepted.action) {
            case DROP:
                return BinaryMessageReceivedAction.drop();
            case MODIFY:
                return BinaryMessageReceivedAction.continueWith(
                    ByteArray.byteArray(intercepted.binaryPayload));
            default:
                return BinaryMessageReceivedAction.continueWith(message);
        }
    }
    
    private BinaryMessageToBeSentAction processBinaryMessageToBeSent(InterceptedBinaryMessage message, Direction direction) {
        byte[] payload = message.payload().getBytes();
        
        // Check filters (convert to hex string for pattern matching)
        String hexPayload = bytesToHex(payload);
        boolean shouldIntercept = activeFilters.isEmpty();
        for (Pattern pattern : activeFilters.values()) {
            if (pattern.matcher(hexPayload).find()) {
                shouldIntercept = true;
                break;
            }
        }
        
        if (!shouldIntercept) {
            return BinaryMessageToBeSentAction.continueWith(message);
        }
        
        // Create intercepted message
        String messageId = "msg-" + messageIdCounter.incrementAndGet();
        InterceptedMessage intercepted = new InterceptedMessage(messageId, payload, direction);
        pendingMessages.put(messageId, intercepted);
        totalIntercepted.incrementAndGet();
        
        // Wait for user action
        long timeout = System.currentTimeMillis() + 30000; // 30 second timeout
        while (intercepted.action == MessageAction.PENDING && System.currentTimeMillis() < timeout) {
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                break;
            }
        }
        
        // Handle action
        switch (intercepted.action) {
            case DROP:
                return BinaryMessageToBeSentAction.drop();
            case MODIFY:
                return BinaryMessageToBeSentAction.continueWith(
                    ByteArray.byteArray(intercepted.binaryPayload));
            default:
                return BinaryMessageToBeSentAction.continueWith(message);
        }
    }
    
    private static class InterceptedMessage {
        final String id;
        String payload;
        byte[] binaryPayload; // For binary messages
        final String type;
        final Direction direction;
        volatile MessageAction action = MessageAction.PENDING;
        
        InterceptedMessage(String id, String payload, String type, Direction direction) {
            this.id = id;
            this.payload = payload;
            this.type = type;
            this.direction = direction;
        }
        
        InterceptedMessage(String id, byte[] binaryPayload, Direction direction) {
            this.id = id;
            this.binaryPayload = binaryPayload;
            this.type = "binary";
            this.direction = direction;
            // Store as Base64 for display
            this.payload = Base64.getEncoder().encodeToString(binaryPayload);
        }
    }
    
    private enum MessageAction {
        PENDING, FORWARD, DROP, MODIFY
    }
    
    private static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }
}