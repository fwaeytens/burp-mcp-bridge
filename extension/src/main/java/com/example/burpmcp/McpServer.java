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
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

public class McpServer {
    private final MontoyaApi api;
    private final Logging logging;
    private final ObjectMapper objectMapper;
    private final BurpMcpConfig config;
    private final AsyncRequestHandler asyncHandler;
    private final JsonRpcDispatcher jsonRpcDispatcher;
    private Server server;
    private Thread shutdownHook;
    private final Map<String, McpTool> tools;
    private boolean stopped;
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
        this.tools = ToolRegistry.createTools(api);

        // Load configuration from system properties/environment
        config.loadFromSystemProperties();

        // Initialize async handler, sharing the registered tool instances
        this.asyncHandler = new AsyncRequestHandler(api, tools);

        // Log configuration
        if (config.getLogLevel().ordinal() >= BurpMcpConfig.LogLevel.INFO.ordinal()) {
            logging.logToOutput("Burp MCP Bridge Configuration Loaded:");
            logging.logToOutput(config.getConfigSummary());
        }

        ToolDocumentationStore docStore = ToolDocumentationStore.getInstance();
        docStore.syncWithToolSchemas(tools);
        this.jsonRpcDispatcher = new JsonRpcDispatcher(
            objectMapper,
            tools,
            asyncHandler,
            config::getRequestTimeoutMs,
            config::getServerPort,
            config::getConfigSummary,
            new ToolDocumentationExporter(tools)
        );
        validateToolRegistration();
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
        
        // Add shutdown hook as safety measure. Keep the reference so stop() can remove it
        // on extension unload/reload — otherwise each reload leaks a hook (and the old
        // McpServer instance it closes over) for the JVM's lifetime.
        shutdownHook = new Thread(() -> {
            logging.logToOutput("Shutdown hook: stopping MCP Server");
            stop();
        });
        Runtime.getRuntime().addShutdownHook(shutdownHook);
    }

    public Map<String, McpTool> getTools() {
        return tools;
    }

    public synchronized void stop() {
        if (stopped) {
            return;
        }
        stopped = true;

        // Remove the shutdown hook so a reload doesn't accumulate hooks referencing
        // stale McpServer instances. Ignore if shutdown is already underway.
        if (shutdownHook != null) {
            try { Runtime.getRuntime().removeShutdownHook(shutdownHook); }
            catch (IllegalStateException ignored) {}
            shutdownHook = null;
        }

        asyncHandler.shutdown();
        closeTools();

        if (server != null) {
            try {
                logging.logToOutput("Stopping MCP Server on port " + config.getServerPort() + "...");

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

    private void closeTools() {
        for (Map.Entry<String, McpTool> entry : tools.entrySet()) {
            try {
                entry.getValue().close();
            } catch (Exception e) {
                logging.logToError("Error closing tool " + entry.getKey() + ": " +
                    McpUtils.sanitizeForLogging(e.getMessage()));
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
                    jsonRpcDispatcher.createErrorResponse(null, -32000, "Origin not allowed"));
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
                    jsonRpcDispatcher.createErrorResponse(null, -32001, e.getMessage()));
                return;
            } catch (Exception e) {
                response.setStatus(400);
                objectMapper.writeValue(response.getOutputStream(),
                    jsonRpcDispatcher.createErrorResponse(null, -32700, "Invalid JSON payload: " + e.getMessage()));
                return;
            }

            // readTree returns null for an empty body (no exception) — guard before deref.
            if (requestNode == null) {
                response.setStatus(400);
                objectMapper.writeValue(response.getOutputStream(),
                    jsonRpcDispatcher.createErrorResponse(null, -32700, "Empty JSON payload"));
                return;
            }

            JsonNode methodNode = requestNode.get("method");
            if (methodNode == null || !methodNode.isTextual()) {
                response.setStatus(400);
                objectMapper.writeValue(response.getOutputStream(),
                    jsonRpcDispatcher.createErrorResponse(requestNode.get("id"), -32600, "Missing or invalid 'method'"));
                return;
            }

            try {
                JsonNode responseNode = jsonRpcDispatcher.handle(methodNode.asText(), requestNode, clientHost);
                objectMapper.writeValue(response.getOutputStream(), responseNode);
            } catch (Exception e) {
                logging.logToError("Error handling MCP request: " + e.getMessage());
                response.setStatus(500);
                objectMapper.writeValue(response.getOutputStream(),
                    jsonRpcDispatcher.createErrorResponse(requestNode.get("id"), -32603, "Internal error: " + e.getMessage()));
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
     * Factory that builds a FRESH tool instance per call.
     *
     * @deprecated Do NOT use for request dispatch. It discards per-tool in-memory state
     * (e.g. SessionManagementTool's token map, AnnotateTool's handler registry) because a
     * new instance is created every call. The async dispatcher now executes against the
     * registered singletons in {@link #tools} (passed to {@link AsyncRequestHandler}).
     * Retained only for tests / one-off standalone instantiation.
     */
    @Deprecated
    public static McpTool getToolInstance(String toolName, MontoyaApi api) {
        return ToolRegistry.createTool(toolName, api);
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
