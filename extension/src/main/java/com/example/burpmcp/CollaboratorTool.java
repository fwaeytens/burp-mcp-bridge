package com.example.burpmcp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.collaborator.CollaboratorServer;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.collaborator.InteractionFilter;
import burp.api.montoya.collaborator.InteractionType;
import burp.api.montoya.collaborator.PayloadOption;
import burp.api.montoya.collaborator.SecretKey;
import burp.api.montoya.collaborator.HttpDetails;
import burp.api.montoya.collaborator.DnsDetails;
import burp.api.montoya.collaborator.SmtpDetails;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.ArrayList;
import java.util.Optional;
import java.net.InetAddress;

public class CollaboratorTool implements McpTool {
    private final MontoyaApi api;
    private CollaboratorClient collaboratorClient;
    private boolean clientLogged = false;
    private static final List<String> SUPPORTED_ACTIONS = List.of(
        "GENERATE_PAYLOAD",
        "CHECK_INTERACTIONS",
        "LIST_PAYLOADS",
        "CLEAR_INTERACTIONS",
        "STATUS",
        "GET_SECRET_KEY",
        "SERVER_INFO",
        "GENERATE_WITH_CUSTOM_DATA",
        "FILTER_INTERACTIONS"
    );
    
    public CollaboratorTool(MontoyaApi api) {
        this.api = api;
        try {
            this.collaboratorClient = api.collaborator().createClient();
        } catch (Exception e) {
            this.collaboratorClient = null;
            api.logging().logToError("Collaborator not available: " + e.getMessage());
        }
    }

    @Override
    public Map<String, Object> getToolInfo() {
        Map<String, Object> tool = new HashMap<>();
        tool.put("name", "burp_collaborator");
        tool.put("title", "Collaborator (OOB)");
        tool.put("description", "Generate payloads and monitor out-of-band interactions for blind vulnerability testing. " +
                "Use this for SSRF, blind XXE, blind SQL injection, and other vulnerabilities that require external callback verification. " +
                "Actions: GENERATE_PAYLOAD, CHECK_INTERACTIONS, LIST_PAYLOADS, CLEAR_INTERACTIONS, STATUS, GET_SECRET_KEY, SERVER_INFO, GENERATE_WITH_CUSTOM_DATA, FILTER_INTERACTIONS. " +
                "GENERATE_PAYLOAD/GENERATE_WITH_CUSTOM_DATA: create callback URLs. CHECK_INTERACTIONS/FILTER_INTERACTIONS: poll for callbacks. LIST_PAYLOADS/CLEAR_INTERACTIONS: manage. STATUS/SERVER_INFO: diagnostics. GET_SECRET_KEY: restore client session. " +
                "Professional license required. Supports DNS, HTTP, HTTPS, and SMTP interactions.");

        // MCP 2025-06-18 annotations
        Map<String, Object> annotations = new HashMap<>();
        annotations.put("readOnlyHint", false);
        annotations.put("destructiveHint", true);   // CLEAR_INTERACTIONS removes data
        annotations.put("idempotentHint", false);
        annotations.put("openWorldHint", true);
        annotations.put("title", "Collaborator (OOB)");
        tool.put("annotations", annotations);

        Map<String, Object> meta = new HashMap<>();
        meta.put("anthropic/searchHint", "out-of-band OAST SSRF blind XXE DNS interaction");
        tool.put("_meta", meta);

        Map<String, Object> inputSchema = new HashMap<>();
        inputSchema.put("type", "object");

        Map<String, Object> properties = new HashMap<>();
        
        Map<String, Object> actionProperty = new HashMap<>();
        actionProperty.put("type", "string");
        actionProperty.put("description", "Collaborator action to perform");
        actionProperty.put("enum", SUPPORTED_ACTIONS);
        properties.put("action", actionProperty);
        
        Map<String, Object> payloadTypeProperty = new HashMap<>();
        payloadTypeProperty.put("type", "string");
        payloadTypeProperty.put("description", "Type of payload to generate");
        payloadTypeProperty.put("enum", List.of("HOSTNAME", "HTTP_URL", "HTTPS_URL", "EMAIL"));
        payloadTypeProperty.put("default", "HOSTNAME");
        properties.put("payloadType", payloadTypeProperty);
        
        Map<String, Object> countProperty = new HashMap<>();
        countProperty.put("type", "integer");
        countProperty.put("description", "Number of payloads to generate");
        countProperty.put("default", 1);
        countProperty.put("minimum", 1);
        countProperty.put("maximum", 10);
        properties.put("count", countProperty);
        
        Map<String, Object> interactionTypeProperty = new HashMap<>();
        interactionTypeProperty.put("type", "string");
        interactionTypeProperty.put("description", "Filter interactions by type");
        interactionTypeProperty.put("enum", List.of("ALL", "DNS", "HTTP", "HTTPS", "SMTP"));
        interactionTypeProperty.put("default", "ALL");
        properties.put("interactionType", interactionTypeProperty);
        
        Map<String, Object> payloadIdProperty = new HashMap<>();
        payloadIdProperty.put("type", "string");
        payloadIdProperty.put("description", "Specific payload ID to check interactions for");
        properties.put("payloadId", payloadIdProperty);
        
        Map<String, Object> customDataProperty = new HashMap<>();
        customDataProperty.put("type", "string");
        customDataProperty.put("description", "Custom data to include with payload for tracking purposes");
        properties.put("customData", customDataProperty);
        
        Map<String, Object> includeServerProperty = new HashMap<>();
        includeServerProperty.put("type", "boolean");
        includeServerProperty.put("description", "Include server location in payload");
        includeServerProperty.put("default", true);
        properties.put("includeServerLocation", includeServerProperty);
        
        Map<String, Object> secretKeyProperty = new HashMap<>();
        secretKeyProperty.put("type", "string");
        secretKeyProperty.put("description", "Secret key for restoring a collaborator client session");
        properties.put("secretKey", secretKeyProperty);

        Map<String, Object> verboseProperty = new HashMap<>();
        verboseProperty.put("type", "boolean");
        verboseProperty.put("default", false);
        verboseProperty.put("description", "Return decorated markdown (for human debugging). Default returns compact JSON.");
        properties.put("verbose", verboseProperty);

        inputSchema.put("properties", properties);
        inputSchema.put("required", List.of("action"));
        
        tool.put("inputSchema", inputSchema);
        return tool;
    }

    @Override
    public Object execute(JsonNode arguments) throws Exception {
        McpUtils.ActionResolution actionResolution = McpUtils.resolveAction(arguments, SUPPORTED_ACTIONS);
        if (actionResolution.hasError()) {
            return McpUtils.createErrorResponse(actionResolution.getErrorMessage());
        }

        String action = actionResolution.getAction();
        
        // Log client info on first use
        if (!clientLogged && collaboratorClient != null) {
            clientLogged = true;
            api.logging().logToOutput("[Collaborator] Client active. Server: " + collaboratorClient.server().address());
        }

        // Check if Collaborator is available
        if (collaboratorClient == null) {
            Map<String, Object> errorResult = new HashMap<>();
            errorResult.put("type", "text");
            errorResult.put("text", "❌ Burp Collaborator is not available. This feature requires Burp Suite Professional.");
            
            return List.of(errorResult);
        }
        
        try {
            StringBuilder result = new StringBuilder();
            
            switch (action) {
                case "GENERATE_PAYLOAD":
                    return generatePayload(arguments, result);
                case "CHECK_INTERACTIONS":
                    return checkInteractions(arguments, result);
                case "LIST_PAYLOADS":
                    return listPayloads(arguments, result);
                case "CLEAR_INTERACTIONS":
                    return clearInteractions(arguments, result);
                case "STATUS":
                    return getStatus(arguments, result);
                case "GET_SECRET_KEY":
                    return getSecretKey(arguments, result);
                case "SERVER_INFO":
                    return getServerInfo(arguments, result);
                case "GENERATE_WITH_CUSTOM_DATA":
                    return generatePayloadWithCustomData(arguments, result);
                case "FILTER_INTERACTIONS":
                    return filterInteractions(arguments, result);
                default:
                    throw new IllegalArgumentException("Unknown action: " + action);
            }
            
        } catch (Exception e) {
            api.logging().logToError("Error in Collaborator tool: " + e.getMessage());
            
            Map<String, Object> errorResult = new HashMap<>();
            errorResult.put("type", "text");
            errorResult.put("text", "❌ Error in Collaborator operation: " + e.getMessage());
            
            return List.of(errorResult);
        }
    }
    
    private Object generatePayload(JsonNode arguments, StringBuilder result) {
        result.append("🎯 **COLLABORATOR PAYLOAD GENERATION**\n\n");
        
        String payloadType = arguments.has("payloadType") ? arguments.get("payloadType").asText() : "HOSTNAME";
        int count = arguments.has("count") ? arguments.get("count").asInt() : 1;
        boolean includeServer = arguments.has("includeServerLocation") ? arguments.get("includeServerLocation").asBoolean() : true;
        
        try {
            List<Map<String, String>> payloads = new ArrayList<>();
            
            for (int i = 0; i < count; i++) {
                CollaboratorPayload payload;
                
                // Generate payload with or without server location
                if (includeServer) {
                    payload = collaboratorClient.generatePayload();
                } else {
                    payload = collaboratorClient.generatePayload(PayloadOption.WITHOUT_SERVER_LOCATION);
                }
                
                Map<String, String> payloadInfo = new HashMap<>();
                String payloadString = "";
                
                switch (payloadType.toUpperCase()) {
                    case "HOSTNAME":
                        payloadString = payload.toString();
                        break;
                    case "HTTP_URL":
                        payloadString = "http://" + payload.toString();
                        break;
                    case "HTTPS_URL":
                        payloadString = "https://" + payload.toString();
                        break;
                    case "EMAIL":
                        payloadString = "test@" + payload.toString();
                        break;
                    default:
                        payloadString = payload.toString();
                        break;
                }
                
                payloadInfo.put("payload", payloadString);
                payloadInfo.put("id", payload.id().toString());
                api.logging().logToOutput("[Collaborator] Generated payload: " + payloadString + " (ID: " + payload.id() + ")");

                // Get server info if available
                Optional<CollaboratorServer> server = payload.server();
                if (server.isPresent()) {
                    payloadInfo.put("server", server.get().address());
                    payloadInfo.put("isLiteral", String.valueOf(server.get().isLiteralAddress()));
                }
                
                payloads.add(payloadInfo);
            }
            
            // Compact JSON by default
            if (!McpUtils.isVerbose(arguments)) {
                Map<String, Object> data = new HashMap<>();
                data.put("payloadType", payloadType.toUpperCase());
                data.put("count", count);
                data.put("includeServerLocation", includeServer);
                data.put("payloads", payloads);
                return McpUtils.createJsonResponse(data);
            }

            result.append("**Payload Type:** ").append(payloadType.toUpperCase()).append("\n");
            result.append("**Count:** ").append(count).append("\n");
            result.append("**Server Location:** ").append(includeServer ? "Included" : "Excluded").append("\n\n");

            result.append("**Generated Payloads:**\n");
            for (int i = 0; i < payloads.size(); i++) {
                Map<String, String> info = payloads.get(i);
                result.append(String.format("%d. `%s`\n", i + 1, info.get("payload")));
                result.append("   • **ID:** ").append(info.get("id")).append("\n");
                if (info.containsKey("server")) {
                    result.append("   • **Server:** ").append(info.get("server"))
                          .append(" (Literal: ").append(info.get("isLiteral")).append(")\n");
                }
            }

            result.append("\n💡 **Usage Tips:**\n");
            result.append("• Insert these payloads into vulnerable parameters\n");
            result.append("• Wait for the application to trigger out-of-band requests\n");
            result.append("• Use 'CHECK_INTERACTIONS' to monitor for callbacks\n");
            result.append("• Look for DNS, HTTP, or SMTP interactions\n");
            result.append("• Use payload IDs to track specific payloads\n");

        } catch (Exception e) {
            result.append("❌ Error generating payloads: ").append(e.getMessage()).append("\n");
        }

        Map<String, Object> resultMap = new HashMap<>();
        resultMap.put("type", "text");
        resultMap.put("text", result.toString());

        return List.of(resultMap);
    }
    
    private Object checkInteractions(JsonNode arguments, StringBuilder result) {
        result.append("🔍 **COLLABORATOR INTERACTIONS**\n\n");

        String interactionType = arguments.has("interactionType") ? arguments.get("interactionType").asText() : "ALL";

        try {
            List<Interaction> interactions = collaboratorClient.getAllInteractions();

            // Always log to Burp output
            for (Interaction ix : interactions) {
                String clientAddr = "unknown";
                try {
                    if (ix.clientIp() != null) clientAddr = ix.clientIp().getHostAddress();
                } catch (Exception ignored) {}
                api.logging().logToOutput("[Collaborator] Interaction detected: " + ix.type()
                    + " from " + clientAddr
                    + " at " + ix.timeStamp()
                    + " (ID: " + ix.id() + ")");
            }

            // Filter by type
            List<Interaction> filteredList = new ArrayList<>();
            for (Interaction interaction : interactions) {
                if (interactionType.equals("ALL") ||
                    interaction.type().toString().equalsIgnoreCase(interactionType)) {
                    filteredList.add(interaction);
                }
            }

            // Compact JSON by default
            if (!McpUtils.isVerbose(arguments)) {
                List<Map<String, Object>> jsonInteractions = new ArrayList<>();
                for (Interaction ix : filteredList) {
                    Map<String, Object> e = new HashMap<>();
                    e.put("id", ix.id().toString());
                    e.put("type", ix.type().toString());
                    e.put("timestamp", ix.timeStamp().toString());
                    try {
                        if (ix.clientIp() != null) e.put("clientIp", ix.clientIp().getHostAddress());
                    } catch (Exception ignored) {}
                    try {
                        e.put("clientPort", ix.clientPort());
                    } catch (Exception ignored) {}
                    ix.customData().ifPresent(cd -> e.put("customData", cd));
                    jsonInteractions.add(e);
                }
                Map<String, Object> data = new HashMap<>();
                data.put("totalInteractions", interactions.size());
                data.put("filter", interactionType);
                data.put("matchingCount", filteredList.size());
                data.put("interactions", jsonInteractions);
                return McpUtils.createJsonResponse(data);
            }

            result.append("**Total Interactions:** ").append(interactions.size()).append("\n");
            result.append("**Filter:** ").append(interactionType).append("\n\n");

            if (interactions.isEmpty()) {
                result.append("ℹ️ No interactions found. Payloads may not have been triggered yet.\n\n");
                result.append("💡 **Troubleshooting:**\n");
                result.append("• Ensure payloads were properly inserted\n");
                result.append("• Check if the application processes the vulnerable parameter\n");
                result.append("• Wait longer for asynchronous processing\n");
                result.append("• Verify network connectivity from target to Collaborator\n");
            } else {
                // Filter and display interactions
                List<Interaction> filteredInteractions = new ArrayList<>();
                for (Interaction interaction : interactions) {
                    if (interactionType.equals("ALL") || 
                        interaction.type().toString().equalsIgnoreCase(interactionType)) {
                        filteredInteractions.add(interaction);
                    }
                }
                
                result.append("**Filtered Interactions:** ").append(filteredInteractions.size()).append("\n\n");
                
                for (int i = 0; i < Math.min(10, filteredInteractions.size()); i++) {
                    Interaction interaction = filteredInteractions.get(i);
                    result.append("**").append(i + 1).append(". ").append(interaction.type()).append(" Interaction**\n");
                    result.append("• **ID:** ").append(interaction.id().toString()).append("\n");
                    result.append("• **Time:** ").append(interaction.timeStamp()).append("\n");
                    
                    // Add client IP and port information
                    try {
                        InetAddress clientIp = interaction.clientIp();
                        result.append("• **Client IP:** ").append(clientIp.getHostAddress()).append("\n");
                        result.append("• **Client Port:** ").append(interaction.clientPort()).append("\n");
                    } catch (Exception e) {
                        // Client info might not be available
                    }
                    
                    // Add custom data if present
                    Optional<String> customData = interaction.customData();
                    if (customData.isPresent()) {
                        result.append("• **Custom Data:** ").append(customData.get()).append("\n");
                    }
                    
                    // Add type-specific details
                    if (interaction.type() == InteractionType.HTTP) {
                        Optional<HttpDetails> httpDetails = interaction.httpDetails();
                        if (httpDetails.isPresent()) {
                            HttpDetails details = httpDetails.get();
                            result.append("• **Protocol:** ").append(details.protocol()).append("\n");
                            try {
                                result.append("• **Request Length:** ").append(
                                    details.requestResponse().request().toByteArray().length()).append(" bytes\n");
                            } catch (Exception e) {
                                // Request details might not be available
                            }
                        }
                    } else if (interaction.type() == InteractionType.DNS) {
                        Optional<DnsDetails> dnsDetails = interaction.dnsDetails();
                        if (dnsDetails.isPresent()) {
                            DnsDetails details = dnsDetails.get();
                            result.append("• **Query Type:** ").append(details.queryType()).append("\n");
                            result.append("• **Query Size:** ").append(details.query().length()).append(" bytes\n");
                        }
                    } else if (interaction.type() == InteractionType.SMTP) {
                        Optional<SmtpDetails> smtpDetails = interaction.smtpDetails();
                        if (smtpDetails.isPresent()) {
                            SmtpDetails details = smtpDetails.get();
                            result.append("• **Protocol:** ").append(details.protocol()).append("\n");
                            String conversation = details.conversation();
                            if (conversation != null && !conversation.isEmpty()) {
                                result.append("• **Conversation Preview:** ").append(
                                    conversation.substring(0, Math.min(100, conversation.length()))).append("...\n");
                            }
                        }
                    }
                    
                    result.append("\n");
                }
                
                if (filteredInteractions.size() > 10) {
                    result.append("... and ").append(filteredInteractions.size() - 10).append(" more interactions\n\n");
                }
                
                result.append("✅ **Vulnerability Confirmed!** Out-of-band interaction detected.\n");
            }
            
        } catch (Exception e) {
            result.append("❌ Error checking interactions: ").append(e.getMessage()).append("\n");
        }
        
        Map<String, Object> resultMap = new HashMap<>();
        resultMap.put("type", "text");
        resultMap.put("text", result.toString());
        
        return List.of(resultMap);
    }
    
    private Object listPayloads(JsonNode arguments, StringBuilder result) {
        if (!McpUtils.isVerbose(arguments)) {
            Map<String, Object> data = new HashMap<>();
            List<Map<String, String>> types = new ArrayList<>();
            String[][] typeData = {
                {"HOSTNAME", "abc123.collaborator.net", "DNS lookups, hostname injection"},
                {"HTTP_URL", "http://abc123.collaborator.net", "HTTP requests, URL injection"},
                {"HTTPS_URL", "https://abc123.collaborator.net", "HTTPS requests, secure URL injection"},
                {"EMAIL", "test@abc123.collaborator.net", "Email injection, SMTP testing"}
            };
            for (String[] t : typeData) {
                Map<String, String> tm = new HashMap<>();
                tm.put("type", t[0]);
                tm.put("format", t[1]);
                tm.put("useFor", t[2]);
                types.add(tm);
            }
            data.put("payloadTypes", types);
            data.put("attackScenarios", java.util.Arrays.asList("SSRF", "XXE", "DNS Exfiltration", "Blind SQLi", "LDAP Injection", "Email Injection"));
            return McpUtils.createJsonResponse(data);
        }

        result.append("📋 **COLLABORATOR PAYLOAD TYPES**\n\n");
        result.append("**Available Payload Types:**\n\n");
        result.append("**1. HOSTNAME**\n• Format: `abc123.collaborator.net`\n• Use for: DNS lookups, hostname injection\n\n");
        result.append("**2. HTTP_URL**\n• Format: `http://abc123.collaborator.net`\n• Use for: HTTP requests, URL injection\n\n");
        result.append("**3. HTTPS_URL**\n• Format: `https://abc123.collaborator.net`\n• Use for: HTTPS requests, secure URL injection\n\n");
        result.append("**4. EMAIL**\n• Format: `test@abc123.collaborator.net`\n• Use for: Email injection, SMTP testing\n\n");
        result.append("**🎯 Attack Scenarios:** SSRF, XXE, DNS Exfiltration, Blind SQLi, LDAP Injection, Email Injection\n");
        return McpUtils.createSuccessResponse(result.toString());
    }

    private Object clearInteractions(JsonNode arguments, StringBuilder result) {
        if (!McpUtils.isVerbose(arguments)) {
            Map<String, Object> data = new HashMap<>();
            data.put("action", "CLEAR_INTERACTIONS");
            data.put("supported", false);
            data.put("note", "No direct API to clear; use Burp UI Collaborator tab → Right-click → Clear interactions, or create a new client.");
            return McpUtils.createJsonResponse(data);
        }
        result.append("🗑️ **CLEAR COLLABORATOR INTERACTIONS**\n\n");
        result.append("⚠️ **Manual Action Required**\n");
        result.append("To clear Collaborator interactions:\n");
        result.append("1. Go to Burp Suite → Collaborator tab\n");
        result.append("2. Right-click in the interactions list\n");
        result.append("3. Select 'Clear interactions'\n\n");
        result.append("💡 Alternatively, create a new Collaborator client to start fresh.\n");
        return McpUtils.createSuccessResponse(result.toString());
    }

    private Object getStatus(JsonNode arguments, StringBuilder result) {
        if (collaboratorClient == null) {
            if (!McpUtils.isVerbose(arguments)) {
                Map<String, Object> data = new HashMap<>();
                data.put("active", false);
                data.put("error", "not_available");
                data.put("message", "Requires Burp Suite Professional");
                return McpUtils.createJsonResponse(data);
            }
            result.append("📊 **COLLABORATOR STATUS**\n\n");
            result.append("❌ **Collaborator Client:** Not available\n");
            result.append("This feature requires Burp Suite Professional.\n");
            return McpUtils.createSuccessResponse(result.toString());
        }

        List<Interaction> interactions = collaboratorClient.getAllInteractions();
        Map<InteractionType, Integer> typeCounts = new HashMap<>();
        for (Interaction interaction : interactions) {
            typeCounts.put(interaction.type(), typeCounts.getOrDefault(interaction.type(), 0) + 1);
        }

        if (!McpUtils.isVerbose(arguments)) {
            Map<String, Object> data = new HashMap<>();
            data.put("active", true);
            data.put("totalInteractions", interactions.size());
            if (!interactions.isEmpty()) {
                data.put("latestInteractionTime", interactions.get(interactions.size() - 1).timeStamp().toString());
            }
            Map<String, Integer> typeCountsStr = new HashMap<>();
            for (Map.Entry<InteractionType, Integer> e : typeCounts.entrySet()) {
                typeCountsStr.put(e.getKey().toString(), e.getValue());
            }
            data.put("interactionsByType", typeCountsStr);
            return McpUtils.createJsonResponse(data);
        }

        result.append("📊 **COLLABORATOR STATUS**\n\n");
        result.append("✅ **Collaborator Client:** Active\n");
        result.append("**Total Interactions:** ").append(interactions.size()).append("\n");
        if (!interactions.isEmpty()) {
            result.append("**Latest Interaction:** ").append(interactions.get(interactions.size() - 1).timeStamp()).append("\n");
        }
        if (!typeCounts.isEmpty()) {
            result.append("\n**Interactions by Type:**\n");
            for (Map.Entry<InteractionType, Integer> entry : typeCounts.entrySet()) {
                result.append("• ").append(entry.getKey()).append(": ").append(entry.getValue()).append("\n");
            }
        }
        return McpUtils.createSuccessResponse(result.toString());
    }

    private Object getSecretKey(JsonNode arguments, StringBuilder result) {
        try {
            SecretKey secretKey = collaboratorClient.getSecretKey();
            if (!McpUtils.isVerbose(arguments)) {
                Map<String, Object> data = new HashMap<>();
                data.put("secretKey", secretKey.toString());
                data.put("usage", "Save to restore Collaborator session later via restoreClient()");
                return McpUtils.createJsonResponse(data);
            }
            result.append("🔑 **COLLABORATOR SECRET KEY**\n\n");
            result.append("**Secret Key:** `").append(secretKey.toString()).append("`\n\n");
            result.append("💡 **Usage:**\n");
            result.append("• Save this key to restore your Collaborator session later\n");
            result.append("• Use with `restoreClient()` to reconnect to existing payloads\n");
            return McpUtils.createSuccessResponse(result.toString());
        } catch (Exception e) {
            if (!McpUtils.isVerbose(arguments)) {
                Map<String, Object> data = new HashMap<>();
                data.put("error", e.getMessage());
                return McpUtils.createJsonResponse(data);
            }
            result.append("❌ Error getting secret key: ").append(e.getMessage()).append("\n");
            return McpUtils.createSuccessResponse(result.toString());
        }
    }

    private Object getServerInfo(JsonNode arguments, StringBuilder result) {
        try {
            CollaboratorServer server = collaboratorClient.server();
            if (!McpUtils.isVerbose(arguments)) {
                Map<String, Object> data = new HashMap<>();
                data.put("address", server.address());
                data.put("isLiteralAddress", server.isLiteralAddress());
                data.put("supportedProtocols", java.util.Arrays.asList("DNS", "HTTP", "HTTPS", "SMTP"));
                return McpUtils.createJsonResponse(data);
            }
            result.append("🖥️ **COLLABORATOR SERVER INFO**\n\n");
            result.append("**Server Address:** `").append(server.address()).append("`\n");
            result.append("**Is Literal Address:** ").append(server.isLiteralAddress()).append("\n\n");
            result.append("**Supported Protocols:** DNS (53), HTTP (80), HTTPS (443), SMTP (25/587)\n");
            return McpUtils.createSuccessResponse(result.toString());
        } catch (Exception e) {
            if (!McpUtils.isVerbose(arguments)) {
                Map<String, Object> data = new HashMap<>();
                data.put("error", e.getMessage());
                return McpUtils.createJsonResponse(data);
            }
            result.append("❌ Error getting server info: ").append(e.getMessage()).append("\n");
            return McpUtils.createSuccessResponse(result.toString());
        }
    }
    
    private Object generatePayloadWithCustomData(JsonNode arguments, StringBuilder result) {
        result.append("🎯 **COLLABORATOR PAYLOAD WITH CUSTOM DATA**\n\n");
        
        String customData = arguments.has("customData") ? arguments.get("customData").asText() : "test";
        String payloadType = arguments.has("payloadType") ? arguments.get("payloadType").asText() : "HOSTNAME";
        int count = arguments.has("count") ? arguments.get("count").asInt() : 1;
        
        // Sanitize and truncate custom data to meet API requirements (16 alphanumeric chars max)
        customData = customData.replaceAll("[^a-zA-Z0-9]", "");
        if (customData.length() > 14) { // Leave room for index
            customData = customData.substring(0, 14);
        }
        
        try {
            List<Map<String, String>> payloads = new ArrayList<>();
            
            for (int i = 0; i < count; i++) {
                // Generate payload with custom data
                String customDataWithIndex = customData + i;
                if (customDataWithIndex.length() > 16) {
                    customDataWithIndex = customDataWithIndex.substring(0, 16);
                }
                CollaboratorPayload payload = collaboratorClient.generatePayload(customDataWithIndex);
                
                Map<String, String> payloadInfo = new HashMap<>();
                String payloadString = "";
                
                switch (payloadType.toUpperCase()) {
                    case "HOSTNAME":
                        payloadString = payload.toString();
                        break;
                    case "HTTP_URL":
                        payloadString = "http://" + payload.toString();
                        break;
                    case "HTTPS_URL":
                        payloadString = "https://" + payload.toString();
                        break;
                    case "EMAIL":
                        payloadString = "test@" + payload.toString();
                        break;
                    default:
                        payloadString = payload.toString();
                        break;
                }
                
                payloadInfo.put("payload", payloadString);
                payloadInfo.put("id", payload.id().toString());
                payloadInfo.put("customData", customDataWithIndex);
                
                payloads.add(payloadInfo);
            }
            
            if (!McpUtils.isVerbose(arguments)) {
                Map<String, Object> data = new HashMap<>();
                data.put("payloadType", payloadType.toUpperCase());
                data.put("count", count);
                data.put("customData", customData);
                data.put("payloads", payloads);
                return McpUtils.createJsonResponse(data);
            }

            result.append("**Payload Type:** ").append(payloadType.toUpperCase()).append("\n");
            result.append("**Count:** ").append(count).append("\n");
            result.append("**Custom Data (sanitized):** ").append(customData).append("\n");
            result.append("**Note:** Custom data must be 16 chars max, alphanumeric only\n\n");

            result.append("**Generated Payloads with Custom Data:**\n");
            for (int i = 0; i < payloads.size(); i++) {
                Map<String, String> info = payloads.get(i);
                result.append(String.format("%d. `%s`\n", i + 1, info.get("payload")));
                result.append("   • **ID:** ").append(info.get("id")).append("\n");
                result.append("   • **Custom Data:** ").append(info.get("customData")).append("\n");
            }

        } catch (Exception e) {
            result.append("❌ Error generating payloads with custom data: ").append(e.getMessage()).append("\n");
        }

        Map<String, Object> resultMap = new HashMap<>();
        resultMap.put("type", "text");
        resultMap.put("text", result.toString());

        return List.of(resultMap);
    }
    
    private Object filterInteractions(JsonNode arguments, StringBuilder result) {
        result.append("🔍 **FILTERED COLLABORATOR INTERACTIONS**\n\n");
        
        String payloadId = arguments.has("payloadId") ? arguments.get("payloadId").asText() : null;
        String interactionType = arguments.has("interactionType") ? arguments.get("interactionType").asText() : "ALL";
        
        try {
            List<Interaction> interactions;
            String filterDesc;

            if (payloadId != null) {
                InteractionFilter filter = InteractionFilter.interactionPayloadFilter(payloadId);
                interactions = collaboratorClient.getInteractions(filter);
                filterDesc = "payloadId=" + payloadId;
            } else {
                interactions = collaboratorClient.getAllInteractions();
                filterDesc = interactionType;
            }

            // Always log to Burp output
            for (Interaction ix : interactions) {
                String clientAddr = "unknown";
                try {
                    if (ix.clientIp() != null) clientAddr = ix.clientIp().getHostAddress();
                } catch (Exception ignored) {}
                api.logging().logToOutput("[Collaborator] Filtered interaction: " + ix.type()
                    + " from " + clientAddr
                    + " at " + ix.timeStamp()
                    + " (ID: " + ix.id() + ")");
            }

            // Apply type filter
            List<Interaction> filteredList = new ArrayList<>();
            for (Interaction interaction : interactions) {
                if (interactionType.equals("ALL") ||
                    interaction.type().toString().equalsIgnoreCase(interactionType)) {
                    filteredList.add(interaction);
                }
            }

            // Type counts
            Map<InteractionType, Integer> typeCounts = new HashMap<>();
            for (Interaction interaction : filteredList) {
                typeCounts.put(interaction.type(), typeCounts.getOrDefault(interaction.type(), 0) + 1);
            }

            if (!McpUtils.isVerbose(arguments)) {
                List<Map<String, Object>> jsonInteractions = new ArrayList<>();
                for (Interaction ix : filteredList) {
                    Map<String, Object> e = new HashMap<>();
                    e.put("id", ix.id().toString());
                    e.put("type", ix.type().toString());
                    e.put("timestamp", ix.timeStamp().toString());
                    ix.customData().ifPresent(cd -> e.put("customData", cd));
                    jsonInteractions.add(e);
                }
                Map<String, Integer> typeCountsStr = new HashMap<>();
                for (Map.Entry<InteractionType, Integer> e : typeCounts.entrySet()) {
                    typeCountsStr.put(e.getKey().toString(), e.getValue());
                }
                Map<String, Object> data = new HashMap<>();
                data.put("filter", filterDesc);
                data.put("totalMatching", interactions.size());
                data.put("filteredCount", filteredList.size());
                data.put("typeCounts", typeCountsStr);
                data.put("interactions", jsonInteractions);
                return McpUtils.createJsonResponse(data);
            }

            result.append("**Filter:** ").append(filterDesc).append("\n");
            result.append("**Total Matching:** ").append(interactions.size()).append("\n\n");

            if (interactions.isEmpty()) {
                result.append("ℹ️ No matching interactions found.\n");
            } else {
                result.append("**Filtered Results:** ").append(filteredList.size()).append(" interactions\n\n");

                if (!typeCounts.isEmpty()) {
                    result.append("**Summary by Type:**\n");
                    for (Map.Entry<InteractionType, Integer> entry : typeCounts.entrySet()) {
                        result.append("• ").append(entry.getKey()).append(": ").append(entry.getValue()).append("\n");
                    }
                    result.append("\n");
                }

                for (int i = 0; i < Math.min(5, filteredList.size()); i++) {
                    Interaction interaction = filteredList.get(i);
                    result.append("**").append(i + 1).append(". ").append(interaction.type()).append(" Interaction**\n");
                    result.append("• **ID:** ").append(interaction.id().toString()).append("\n");
                    result.append("• **Time:** ").append(interaction.timeStamp()).append("\n");
                    Optional<String> customData = interaction.customData();
                    if (customData.isPresent()) {
                        result.append("• **Custom Data:** ").append(customData.get()).append("\n");
                    }
                    result.append("\n");
                }

                if (filteredList.size() > 5) {
                    result.append("... and ").append(filteredList.size() - 5).append(" more interactions\n");
                }
            }

        } catch (Exception e) {
            result.append("❌ Error filtering interactions: ").append(e.getMessage()).append("\n");
        }

        Map<String, Object> resultMap = new HashMap<>();
        resultMap.put("type", "text");
        resultMap.put("text", result.toString());

        return List.of(resultMap);
    }
}
