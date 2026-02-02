package com.example.burpmcp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.util.thread.QueuedThreadPool;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

public class McpServer {
    private final MontoyaApi api;
    private final Logging logging;
    private final ObjectMapper objectMapper;
    private final BurpMcpConfig config;
    private final AsyncRequestHandler asyncHandler;
    private Server server;
    private final Map<String, McpTool> tools;
    private static final Set<String> DOCUMENTATION_TOOL_IDS = Set.of(
        "burp_help"
    );
    
    // Shared session management components
    private static burp.api.montoya.core.Registration sessionHandlerRegistration;
    private static Object customSessionHandler; // Store the handler object

    public McpServer(MontoyaApi api) {
        this.api = api;
        this.logging = api.logging();
        this.objectMapper = new ObjectMapper();
        this.config = BurpMcpConfig.getInstance();
        this.tools = new HashMap<>();

        // Load configuration from system properties/environment
        config.loadFromSystemProperties();

        // Initialize async handler
        this.asyncHandler = new AsyncRequestHandler(api);

        // Log configuration
        if (config.getLogLevel().ordinal() >= BurpMcpConfig.LogLevel.INFO.ordinal()) {
            logging.logToOutput("Burp MCP Bridge Configuration Loaded:");
            logging.logToOutput(config.getConfigSummary());
        }

        initializeTools();
        ToolDocumentationStore docStore = ToolDocumentationStore.getInstance();
        docStore.syncWithToolSchemas(tools);
        validateToolRegistration();
    }

    private void initializeTools() {
        // DOCUMENTATION TOOL FIRST - Critical for AI discovery
        tools.put("burp_help", new BurpHelpTool(api));
        
        // Core HTTP/Proxy Tools
        tools.put("burp_proxy_history", new ProxyHistoryTool(api));
        tools.put("burp_repeater", new RepeaterTool(api));
        tools.put("burp_proxy_interceptor", new ProxyInterceptorTool(api));
        
        // Scanning & Analysis
        tools.put("burp_scanner", new ScannerTool(api));
        tools.put("burp_intruder", new IntruderTool(api));
        
        // Issue Management
        tools.put("burp_add_issue", new AddIssueTool(api));
        
        // Session Management
        tools.put("burp_session_management", new SessionManagementTool(api));
        
        // Analysis & Comparison
        tools.put("burp_comparer", new ComparerTool(api));
        tools.put("burp_collaborator", new CollaboratorTool(api));
        
        // Site Mapping & Discovery - temporarily disabled
        // tools.put("burp_sitemap", new SiteMapTool(api));
        
        // Configuration & Utilities
        tools.put("burp_scope", new ScopeTool(api));
        tools.put("burp_organizer", new OrganizerTool(api));
        tools.put("burp_annotate", new AnnotateTool(api));
        
        // Site Map Analysis
        tools.put("burp_sitemap_analysis", new SiteMapAnalysisTool(api));
        
        // Advanced Filtering
        tools.put("burp_bambda", new BambdaTool(api));
        
        // Global Interceptor
        tools.put("burp_global_interceptor", new GlobalInterceptorTool(api));
        
        // Custom HTTP Tool - Full HTTP interface implementation
        tools.put("burp_custom_http", new CustomHttpTool(api));
        
        // Logging & Diagnostics
        tools.put("burp_logs", new LogsTool(api));
        
        // WebSocket Support
        tools.put("burp_websocket", new WebSocketTool(api));
        tools.put("burp_websocket_interceptor", new WebSocketInterceptorTool(api));
        
        // Response Analysis
        tools.put("burp_response_analyzer", new ResponseAnalysisTool(api));
        
        // Utilities
        tools.put("burp_utilities", new UtilitiesTool(api));
        
        // MCP Storage - temporarily disabled from MCP visibility
        // tools.put("burp_mcp_storage", storageTool);
    }

    private void validateToolRegistration() {
        ToolDocumentationStore docStore = ToolDocumentationStore.getInstance();
        Set<String> documentedTools = new TreeSet<>(docStore.getAllToolNames());
        Set<String> registeredTools = new TreeSet<>(tools.keySet());

        Set<String> missingRegistrations = new TreeSet<>(documentedTools);
        missingRegistrations.removeAll(registeredTools);

        Set<String> undocumentedTools = new TreeSet<>(registeredTools);
        undocumentedTools.removeAll(documentedTools);
        undocumentedTools.removeAll(DOCUMENTATION_TOOL_IDS);

        if (!missingRegistrations.isEmpty()) {
            logging.logToError("Tool registration mismatch - documented but not registered: " + String.join(", ", missingRegistrations));
        }

        if (!undocumentedTools.isEmpty()) {
            logging.logToError("Tool registration mismatch - registered without documentation: " + String.join(", ", undocumentedTools));
        }
    }

    public void start() throws Exception {
        // Configure thread pool for better concurrency
        QueuedThreadPool threadPool = new QueuedThreadPool(
            200,  // maxThreads - support many concurrent requests
            10,   // minThreads - keep some threads ready
            60000 // idleTimeout - 60 seconds
        );
        threadPool.setName("burp-mcp-server");

        server = new Server(threadPool);

        // Configure connector with proper timeouts
        ServerConnector connector = new ServerConnector(server);
        connector.setPort(config.getServerPort());
        connector.setHost(config.getServerHost());
        connector.setIdleTimeout(300000); // 5 minutes idle timeout
        connector.setAcceptQueueSize(100); // Queue size for pending connections
        server.addConnector(connector);

        ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
        context.setContextPath("/");
        server.setHandler(context);

        context.addServlet(new ServletHolder(new McpHttpServlet()), "/*");

        // Set graceful shutdown timeout
        server.setStopTimeout(5000); // 5 seconds

        server.start();
        logging.logToOutput("MCP Server listening on http://" + config.getServerHost() + ":" + config.getServerPort());
        logging.logToOutput("Server configured with " + threadPool.getMaxThreads() + " max threads, 5min idle timeout");
        
        // Log tool count
        logging.logToOutput("Loaded " + tools.size() + " tools with async processing enabled");
        
        // Add shutdown hook as safety measure
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            if (server != null && server.isRunning()) {
                try {
                    logging.logToOutput("Shutdown hook: stopping MCP Server");
                    server.stop();
                } catch (Exception e) {
                    // Log errors during shutdown
                    System.err.println("Error in shutdown hook: " + e.getMessage());
                }
            }
        }));
    }

    public Map<String, McpTool> getTools() {
        return tools;
    }

    public void stop() {
        if (server != null) {
            try {
                logging.logToOutput("Stopping MCP Server on port " + config.getServerPort() + "...");

                // Shutdown async handler first
                asyncHandler.shutdown();

                server.stop();
                server.join(); // Wait for server to fully stop
                server.destroy(); // Clean up resources
                server = null; // Clear reference
                logging.logToOutput("MCP Server stopped and resources cleaned up");
            } catch (Exception e) {
                logging.logToError("Error stopping MCP Server: " + McpUtils.sanitizeForLogging(e.getMessage()));
            }
        }
    }

    private class McpHttpServlet extends HttpServlet {
        @Override
        protected void doPost(HttpServletRequest request, HttpServletResponse response) 
                throws IOException {
            
            response.setContentType("application/json");

            String originHeader = request.getHeader("Origin");
            boolean originAllowed = originHeader == null || isOriginAllowed(originHeader);
            if (!originAllowed) {
                response.setStatus(403);
                objectMapper.writeValue(response.getOutputStream(),
                    createJsonRpcErrorResponse(null, -32000, "Origin not allowed"));
                return;
            }

            if (originHeader != null) {
                response.setHeader("Access-Control-Allow-Origin", originHeader);
                response.setHeader("Vary", "Origin");
            }
            response.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
            response.setHeader("Access-Control-Allow-Headers", "Content-Type");

            String clientHost = request.getRemoteAddr();

            JsonNode requestNode;
            try {
                byte[] body = readBoundedBody(request);
                requestNode = objectMapper.readTree(body);
            } catch (PayloadTooLargeException e) {
                response.setStatus(413);
                objectMapper.writeValue(response.getOutputStream(),
                    createJsonRpcErrorResponse(null, -32001, e.getMessage()));
                return;
            } catch (Exception e) {
                response.setStatus(400);
                objectMapper.writeValue(response.getOutputStream(),
                    createJsonRpcErrorResponse(null, -32700, "Invalid JSON payload: " + e.getMessage()));
                return;
            }

            JsonNode methodNode = requestNode.get("method");
            if (methodNode == null || !methodNode.isTextual()) {
                response.setStatus(400);
                objectMapper.writeValue(response.getOutputStream(),
                    createJsonRpcErrorResponse(requestNode.get("id"), -32600, "Missing or invalid 'method'"));
                return;
            }

            try {
                JsonNode responseNode = handleMcpRequest(methodNode.asText(), requestNode, clientHost);
                objectMapper.writeValue(response.getOutputStream(), responseNode);
            } catch (Exception e) {
                logging.logToError("Error handling MCP request: " + e.getMessage());
                response.setStatus(500);
                objectMapper.writeValue(response.getOutputStream(),
                    createJsonRpcErrorResponse(requestNode.get("id"), -32603, "Internal error: " + e.getMessage()));
            }
        }
        
        @Override
        protected void doOptions(HttpServletRequest request, HttpServletResponse response) {
            String originHeader = request.getHeader("Origin");
            boolean originAllowed = originHeader == null || isOriginAllowed(originHeader);
            if (!originAllowed) {
                response.setStatus(403);
                return;
            }

            if (originHeader != null) {
                response.setHeader("Access-Control-Allow-Origin", originHeader);
                response.setHeader("Vary", "Origin");
            }
            response.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
            response.setHeader("Access-Control-Allow-Headers", "Content-Type");
            response.setHeader("Access-Control-Max-Age", "600");
            response.setStatus(200);
        }
    }

    private JsonNode handleMcpRequest(String method, JsonNode request, String clientHost) throws Exception {
        Map<String, Object> response = new HashMap<>();
        
        // Add JSON-RPC fields
        response.put("jsonrpc", "2.0");
        if (request.has("id")) {
            response.put("id", request.get("id"));
        }
        
        Map<String, Object> result = new HashMap<>();
        
        switch (method) {
            case "initialize":
                result.put("protocolVersion", "2025-06-18");

                Map<String, Object> capabilities = new HashMap<>();
                capabilities.put("tools", Map.of());
                capabilities.put("logging", Map.of());
                result.put("capabilities", capabilities);

                Map<String, Object> serverInfo = new HashMap<>();
                serverInfo.put("name", "burp-mcp-bridge");
                serverInfo.put("version", "2.1.1");
                result.put("serverInfo", serverInfo);
                break;
                
            case "initialized":
                // Empty response for initialized notification
                return objectMapper.valueToTree(Map.of("jsonrpc", "2.0"));
                
            case "tools/list":
                result.put("tools", tools.values().stream()
                    .map(McpTool::getToolInfo)
                    .toArray());
                break;
                
            case "tools/call":
                return handleAsyncToolCall(request, clientHost);
                
            case "tools/call_sync":
                // Fallback synchronous tool call for compatibility
                JsonNode params = request.get("params");
                if (params == null || !params.has("name")) {
                    return createJsonRpcErrorResponse(request.get("id"), -32600, "Missing params.name");
                }
                String toolName = params.get("name").asText();
                JsonNode arguments = params.has("arguments") ? params.get("arguments") : objectMapper.createObjectNode();
                
                McpTool tool = tools.get(toolName);
                if (tool != null) {
                    result.put("content", tool.execute(arguments));
                } else {
                    return createJsonRpcErrorResponse(request.get("id"), -32601, "Unknown tool: " + toolName);
                }
                break;
                
            case "ping":
                // Simple ping/pong for keep-alive
                return objectMapper.valueToTree(Map.of("jsonrpc", "2.0", "id", request.get("id"), "result", Map.of()));
                
            case "stats":
                // Return server statistics
                Map<String, Object> stats = new HashMap<>();
                stats.put("asyncStats", asyncHandler.getStats().toString());
                stats.put("toolCount", tools.size());
                stats.put("serverPort", config.getServerPort());
                stats.put("configSummary", config.getConfigSummary());
                result.put("stats", stats);
                break;
                
            default:
                return createJsonRpcErrorResponse(request.get("id"), -32601, "Method not found: " + method);
        }
        
        response.put("result", result);
        return objectMapper.valueToTree(response);
    }
    
    /**
     * Handle asynchronous tool calls with timeout and rate limiting.
     */
    private JsonNode handleAsyncToolCall(JsonNode request, String clientHost) throws Exception {
        JsonNode params = request.get("params");
        if (params == null || !params.has("name")) {
            return createJsonRpcErrorResponse(request.get("id"), -32600, "Missing params.name");
        }
        String toolName = params.get("name").asText();
        JsonNode arguments = params.has("arguments") ? params.get("arguments") : objectMapper.createObjectNode();

        // Short-circuit unknown tools with a JSON-RPC error
        if (!tools.containsKey(toolName)) {
            return createJsonRpcErrorResponse(request.get("id"), -32601, "Unknown tool: " + toolName);
        }
        
        try {
            // Execute asynchronously with timeout
            CompletableFuture<Object> future = asyncHandler.executeAsync(toolName, arguments, clientHost);
            
            // Wait for result with configured timeout
            Object toolResult = future.get(config.getRequestTimeoutMs(), TimeUnit.MILLISECONDS);
            
            Map<String, Object> response = new HashMap<>();
            response.put("jsonrpc", "2.0");
            if (request.has("id")) {
                response.put("id", request.get("id"));
            }
            
            Map<String, Object> result = new HashMap<>();
            result.put("content", toolResult);
            response.put("result", result);
            
            return objectMapper.valueToTree(response);
            
        } catch (java.util.concurrent.TimeoutException e) {
            Map<String, Object> response = new HashMap<>();
            response.put("jsonrpc", "2.0");
            if (request.has("id")) {
                response.put("id", request.get("id"));
            }
            
            Map<String, Object> error = new HashMap<>();
            error.put("code", -32603);
            error.put("message", "Tool execution timed out after " + config.getRequestTimeoutMs() + "ms");
            response.put("error", error);
            
            return objectMapper.valueToTree(response);
            
        } catch (Exception e) {
            Map<String, Object> response = new HashMap<>();
            response.put("jsonrpc", "2.0");
            if (request.has("id")) {
                response.put("id", request.get("id"));
            }
            
            Map<String, Object> error = new HashMap<>();
            error.put("code", -32603);
            error.put("message", "Tool execution failed: " + e.getMessage());
            response.put("error", error);
            
            return objectMapper.valueToTree(response);
        }
    }

    private JsonNode createJsonRpcErrorResponse(JsonNode idNode, int code, String message) {
        Map<String, Object> response = new HashMap<>();
        response.put("jsonrpc", "2.0");
        if (idNode != null) {
            response.put("id", idNode);
        }
        Map<String, Object> error = new HashMap<>();
        error.put("code", code);
        error.put("message", message);
        response.put("error", error);
        return objectMapper.valueToTree(response);
    }

    private boolean isOriginAllowed(String originHeader) {
        try {
            URI uri = new URI(originHeader);
            String host = uri.getHost();
            if (host == null) {
                return false;
            }
            int port = uri.getPort();
            String hostPort = port > 0 ? host + ":" + port : host;
            boolean allowed = config.isHostAllowed(host) || config.isHostAllowed(hostPort);
            if (!allowed) {
                logging.logToError("CORS origin rejected: " + originHeader);
            }
            return allowed;
        } catch (URISyntaxException e) {
            logging.logToError("Invalid origin header: " + originHeader);
            return false;
        }
    }

    private byte[] readBoundedBody(HttpServletRequest request) throws IOException, PayloadTooLargeException {
        long maxBytes = config.getMaxRequestBytes();
        long contentLength = request.getContentLengthLong();
        if (contentLength > maxBytes) {
            throw new PayloadTooLargeException("Request body too large: " + contentLength + " bytes (max " + maxBytes + ")");
        }

        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] data = new byte[8192];
        long totalRead = 0;
        int nRead;
        while ((nRead = request.getInputStream().read(data, 0, data.length)) != -1) {
            totalRead += nRead;
            if (totalRead > maxBytes) {
                throw new PayloadTooLargeException("Request body exceeded limit of " + maxBytes + " bytes");
            }
            buffer.write(data, 0, nRead);
        }
        return buffer.toByteArray();
    }

    private static class PayloadTooLargeException extends Exception {
        public PayloadTooLargeException(String message) {
            super(message);
        }
    }
    
    /**
     * Static method to get tool instances for async handler.
     */
    public static McpTool getToolInstance(String toolName, MontoyaApi api) {
        // This is a simplified version for the async handler
        // In production, you might want to use a factory pattern
        switch (toolName) {
            // Documentation tools FIRST
            case "burp_help": return new BurpHelpTool(api);

            // Existing tools
            case "burp_proxy_history": return new ProxyHistoryTool(api);
            case "burp_repeater": return new RepeaterTool(api);
            case "burp_proxy_interceptor": return new ProxyInterceptorTool(api);
            case "burp_global_interceptor": return new GlobalInterceptorTool(api);
            case "burp_scanner": return new ScannerTool(api);
            case "burp_intruder": return new IntruderTool(api);
            case "burp_add_issue": return new AddIssueTool(api);
            case "burp_session_management": return new SessionManagementTool(api);
            case "burp_comparer": return new ComparerTool(api);
            case "burp_collaborator": return new CollaboratorTool(api);
            case "burp_scope": return new ScopeTool(api);
            case "burp_organizer": return new OrganizerTool(api);
            case "burp_annotate": return new AnnotateTool(api);
            case "burp_sitemap_analysis": return new SiteMapAnalysisTool(api);
            case "burp_bambda": return new BambdaTool(api);
            case "burp_custom_http": return new CustomHttpTool(api);
            case "burp_logs": return new LogsTool(api);
            case "burp_websocket": return new WebSocketTool(api);
            case "burp_websocket_interceptor": return new WebSocketInterceptorTool(api);
            case "burp_response_analyzer": return new ResponseAnalysisTool(api);
            case "burp_utilities": return new UtilitiesTool(api);
            // case "burp_mcp_storage": return sharedStorageTool; // Temporarily disabled
            default: return null;
        }
    }
    
    // Static methods for session handler persistence
    public static void setSessionHandler(burp.api.montoya.core.Registration registration, Object handler) {
        sessionHandlerRegistration = registration;
        customSessionHandler = handler;
    }
    
    public static burp.api.montoya.core.Registration getSessionHandlerRegistration() {
        return sessionHandlerRegistration;
    }
    
    public static Object getCustomSessionHandler() {
        return customSessionHandler;
    }
    
    public static void clearSessionHandler() {
        if (sessionHandlerRegistration != null) {
            sessionHandlerRegistration.deregister();
            sessionHandlerRegistration = null;
        }
        customSessionHandler = null;
    }
}
