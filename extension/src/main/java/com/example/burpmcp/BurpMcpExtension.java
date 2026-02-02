package com.example.burpmcp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.extension.ExtensionUnloadingHandler;

public class BurpMcpExtension implements BurpExtension {
    private MontoyaApi api;
    private Logging logging;
    private McpServer mcpServer;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.logging = api.logging();
        
        api.extension().setName("Burp MCP Bridge " + Version.getShortVersion());
        
        logging.logToOutput("=== Burp MCP Bridge Extension Loaded ===");
        logging.logToOutput(Version.getVersionInfo());
        
        // Log available API capabilities
        exploreApiCapabilities(api);
        
        try {
            // Load and display configuration
            BurpMcpConfig config = BurpMcpConfig.getInstance();
            config.loadFromSystemProperties();

            mcpServer = new McpServer(api);
            mcpServer.start();
            logging.logToOutput("MCP Server started on port " + config.getServerPort());
            logging.logToOutput("Configuration: " + (config.isEnableCaching() ? "Caching enabled" : "Caching disabled") + 
                               ", " + (config.isEnableRateLimiting() ? "Rate limiting enabled" : "Rate limiting disabled"));
            
            // Register context menu provider
            api.userInterface().registerContextMenuItemsProvider(new McpContextMenuProvider(api));
            logging.logToOutput("Context menu provider registered - right-click to send items to MCP Bridge");
            
            // List all available tools
            listAvailableTools();
            
            // Register shutdown handler to clean up resources when extension is unloaded
            api.extension().registerUnloadingHandler(new ExtensionUnloadingHandler() {
                @Override
                public void extensionUnloaded() {
                    shutdown();
                }
            });
            
        } catch (Exception e) {
            logging.logToError("Failed to start MCP Server: " + e.getMessage());
        }
    }
    
    private void exploreApiCapabilities(MontoyaApi api) {
        logging.logToOutput("\n=== Available Montoya API Capabilities ===");
        
        if (api.http() != null) {
            logging.logToOutput("✓ HTTP - Send requests, analyze responses");
        }
        if (api.proxy() != null) {
            logging.logToOutput("✓ Proxy - Access history, configure interceptor");
        }
        if (api.scanner() != null) {
            logging.logToOutput("✓ Scanner - Available but capabilities unknown");
        }
        if (api.scope() != null) {
            logging.logToOutput("✓ Scope - Manage target scope");
        }
        if (api.utilities() != null) {
            logging.logToOutput("✓ Utilities - URL/Base64 encoding, etc.");
        }
        if (api.logging() != null) {
            logging.logToOutput("✓ Logging - Output and error logging");
        }
        
        logging.logToOutput("=== End API Exploration ===\n");
    }
    
    private void listAvailableTools() {
        logging.logToOutput("=== Available MCP Tools ===");

        // Get tools dynamically from the MCP server
        java.util.Map<String, McpTool> tools = mcpServer.getTools();

        // Separate documentation and security tools
        java.util.List<String> docTools = new java.util.ArrayList<>();
        java.util.List<String> securityTools = new java.util.ArrayList<>();

        for (java.util.Map.Entry<String, McpTool> entry : tools.entrySet()) {
            String toolName = entry.getKey();
            McpTool tool = entry.getValue();

            try {
                java.util.Map<String, Object> toolInfo = tool.getToolInfo();
                String description = (String) toolInfo.getOrDefault("description", "No description");

                // Truncate long descriptions
                if (description.length() > 80) {
                    description = description.substring(0, 77) + "...";
                }

                String toolLine = toolName + " - " + description;

                // Categorize tools
                if (toolName.equals("burp_help")) {
                    docTools.add(toolLine);
                } else {
                    securityTools.add(toolLine);
                }
            } catch (Exception e) {
                logging.logToError("Failed to get info for tool: " + toolName);
            }
        }

        // Sort alphabetically
        java.util.Collections.sort(docTools);
        java.util.Collections.sort(securityTools);

        // Print documentation tools
        if (!docTools.isEmpty()) {
            logging.logToOutput("=== DOCUMENTATION TOOL ===");
            int counter = 1;
            for (String tool : docTools) {
                logging.logToOutput(String.format("%2d. %s", counter++, tool));
            }
            logging.logToOutput("");
        }

        // Print security tools
        if (!securityTools.isEmpty()) {
            logging.logToOutput("=== SECURITY TOOLS ===");
            int counter = docTools.size() + 1;
            for (String tool : securityTools) {
                logging.logToOutput(String.format("%2d. %s", counter++, tool));
            }
        }

        logging.logToOutput("");
        logging.logToOutput("Total: " + tools.size() + " tools available for AI integration");
        logging.logToOutput("=== End Tool List ===\n");
    }
    
    /**
     * Clean shutdown of the MCP server when extension is unloaded
     */
    private void shutdown() {
        logging.logToOutput("Burp MCP Bridge extension unloading...");
        
        if (mcpServer != null) {
            try {
                mcpServer.stop();
                BurpMcpConfig config = BurpMcpConfig.getInstance();
                logging.logToOutput("MCP Server stopped - port " + config.getServerPort() + " is now available");
            } catch (Exception e) {
                logging.logToError("Error stopping MCP Server: " + e.getMessage());
            }
        }
        
        logging.logToOutput("Burp MCP Bridge extension unloaded successfully");
    }
}