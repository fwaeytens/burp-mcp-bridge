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
                "Actions: GENERATE_PAYLOAD (create unique callback URLs), CHECK_INTERACTIONS (poll for callbacks), LIST_PAYLOADS, SERVER_INFO. " +
                "Professional license required. Supports DNS, HTTP, HTTPS, and SMTP interactions.");

        // MCP 2025-06-18 annotations
        Map<String, Object> annotations = new HashMap<>();
        annotations.put("readOnlyHint", false);
        annotations.put("destructiveHint", true);   // CLEAR_INTERACTIONS removes data
        annotations.put("idempotentHint", false);
        annotations.put("openWorldHint", true);
        tool.put("annotations", annotations);
        
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
                    return listPayloads(result);
                case "CLEAR_INTERACTIONS":
                    return clearInteractions(result);
                case "STATUS":
                    return getStatus(result);
                case "GET_SECRET_KEY":
                    return getSecretKey(result);
                case "SERVER_INFO":
                    return getServerInfo(result);
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
                
                // Get server info if available
                Optional<CollaboratorServer> server = payload.server();
                if (server.isPresent()) {
                    payloadInfo.put("server", server.get().address());
                    payloadInfo.put("isLiteral", String.valueOf(server.get().isLiteralAddress()));
                }
                
                payloads.add(payloadInfo);
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
    
    private Object listPayloads(StringBuilder result) {
        result.append("📋 **COLLABORATOR PAYLOAD TYPES**\n\n");
        
        result.append("**Available Payload Types:**\n\n");
        
        result.append("**1. HOSTNAME**\n");
        result.append("• Format: `abc123.collaborator.net`\n");
        result.append("• Use for: DNS lookups, hostname injection\n");
        result.append("• Example: `nslookup abc123.collaborator.net`\n\n");
        
        result.append("**2. HTTP_URL**\n");
        result.append("• Format: `http://abc123.collaborator.net`\n");
        result.append("• Use for: HTTP requests, URL injection\n");
        result.append("• Example: `curl http://abc123.collaborator.net`\n\n");
        
        result.append("**3. HTTPS_URL**\n");
        result.append("• Format: `https://abc123.collaborator.net`\n");
        result.append("• Use for: HTTPS requests, secure URL injection\n");
        result.append("• Example: `wget https://abc123.collaborator.net`\n\n");
        
        result.append("**4. EMAIL**\n");
        result.append("• Format: `test@abc123.collaborator.net`\n");
        result.append("• Use for: Email injection, SMTP testing\n");
        result.append("• Example: Contact form with email field\n\n");
        
        result.append("**🎯 Attack Scenarios:**\n");
        result.append("• **SSRF:** Server-Side Request Forgery testing\n");
        result.append("• **XXE:** XML External Entity injection\n");
        result.append("• **DNS Exfiltration:** Data extraction via DNS\n");
        result.append("• **Blind SQLi:** Out-of-band SQL injection\n");
        result.append("• **LDAP Injection:** Directory service attacks\n");
        result.append("• **Email Injection:** SMTP header manipulation\n");
        
        Map<String, Object> resultMap = new HashMap<>();
        resultMap.put("type", "text");
        resultMap.put("text", result.toString());
        
        return List.of(resultMap);
    }
    
    private Object clearInteractions(StringBuilder result) {
        result.append("🗑️ **CLEAR COLLABORATOR INTERACTIONS**\n\n");
        
        try {
            // Note: There might not be a direct API to clear interactions
            // This is a placeholder for the functionality
            result.append("⚠️ **Manual Action Required**\n");
            result.append("To clear Collaborator interactions:\n");
            result.append("1. Go to Burp Suite → Collaborator tab\n");
            result.append("2. Right-click in the interactions list\n");
            result.append("3. Select 'Clear interactions'\n\n");
            
            result.append("💡 Alternatively, create a new Collaborator client to start fresh.\n");
            
        } catch (Exception e) {
            result.append("❌ Error clearing interactions: ").append(e.getMessage()).append("\n");
        }
        
        Map<String, Object> resultMap = new HashMap<>();
        resultMap.put("type", "text");
        resultMap.put("text", result.toString());
        
        return List.of(resultMap);
    }
    
    private Object getStatus(StringBuilder result) {
        result.append("📊 **COLLABORATOR STATUS**\n\n");
        
        try {
            if (collaboratorClient != null) {
                result.append("✅ **Collaborator Client:** Active\n");
                
                // Get interaction count
                List<Interaction> interactions = collaboratorClient.getAllInteractions();
                result.append("**Total Interactions:** ").append(interactions.size()).append("\n");
                
                if (!interactions.isEmpty()) {
                    result.append("**Latest Interaction:** ").append(interactions.get(interactions.size() - 1).timeStamp()).append("\n");
                }
                
                // Count by type
                Map<InteractionType, Integer> typeCounts = new HashMap<>();
                for (Interaction interaction : interactions) {
                    typeCounts.put(interaction.type(), typeCounts.getOrDefault(interaction.type(), 0) + 1);
                }
                
                if (!typeCounts.isEmpty()) {
                    result.append("\n**Interactions by Type:**\n");
                    for (Map.Entry<InteractionType, Integer> entry : typeCounts.entrySet()) {
                        result.append("• ").append(entry.getKey()).append(": ").append(entry.getValue()).append("\n");
                    }
                }
                
                result.append("\n💡 **Tips:**\n");
                result.append("• Generate payloads with 'GENERATE_PAYLOAD'\n");
                result.append("• Monitor interactions with 'CHECK_INTERACTIONS'\n");
                result.append("• Use different payload types for various attack vectors\n");
                
            } else {
                result.append("❌ **Collaborator Client:** Not available\n");
                result.append("This feature requires Burp Suite Professional.\n");
            }
            
        } catch (Exception e) {
            result.append("❌ Error getting status: ").append(e.getMessage()).append("\n");
        }
        
        Map<String, Object> resultMap = new HashMap<>();
        resultMap.put("type", "text");
        resultMap.put("text", result.toString());
        
        return List.of(resultMap);
    }
    
    private Object getSecretKey(StringBuilder result) {
        result.append("🔑 **COLLABORATOR SECRET KEY**\n\n");
        
        try {
            SecretKey secretKey = collaboratorClient.getSecretKey();
            result.append("**Secret Key:** `").append(secretKey.toString()).append("`\n\n");
            
            result.append("💡 **Usage:**\n");
            result.append("• Save this key to restore your Collaborator session later\n");
            result.append("• Use with `restoreClient()` to reconnect to existing payloads\n");
            result.append("• Useful for persistent monitoring across Burp sessions\n");
            result.append("• Keep this key secure - it provides access to your interactions\n");
            
        } catch (Exception e) {
            result.append("❌ Error getting secret key: ").append(e.getMessage()).append("\n");
        }
        
        Map<String, Object> resultMap = new HashMap<>();
        resultMap.put("type", "text");
        resultMap.put("text", result.toString());
        
        return List.of(resultMap);
    }
    
    private Object getServerInfo(StringBuilder result) {
        result.append("🖥️ **COLLABORATOR SERVER INFO**\n\n");
        
        try {
            CollaboratorServer server = collaboratorClient.server();
            
            result.append("**Server Address:** `").append(server.address()).append("`\n");
            result.append("**Is Literal Address:** ").append(server.isLiteralAddress()).append("\n\n");
            
            result.append("💡 **Information:**\n");
            if (server.isLiteralAddress()) {
                result.append("• This is a literal IP address or hostname\n");
                result.append("• Direct connection without DNS resolution\n");
            } else {
                result.append("• This is a domain-based Collaborator server\n");
                result.append("• DNS resolution will be used for connections\n");
            }
            
            result.append("\n**Supported Protocols:**\n");
            result.append("• DNS (port 53)\n");
            result.append("• HTTP (port 80)\n");
            result.append("• HTTPS (port 443)\n");
            result.append("• SMTP (port 25/587)\n");
            
        } catch (Exception e) {
            result.append("❌ Error getting server info: ").append(e.getMessage()).append("\n");
        }
        
        Map<String, Object> resultMap = new HashMap<>();
        resultMap.put("type", "text");
        resultMap.put("text", result.toString());
        
        return List.of(resultMap);
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
            
            result.append("\n💡 **Benefits of Custom Data:**\n");
            result.append("• Track which payload was triggered by which test\n");
            result.append("• Correlate interactions with specific injection points\n");
            result.append("• Organize testing campaigns with meaningful labels\n");
            result.append("• Identify vulnerable parameters more easily\n");
            
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
            
            if (payloadId != null) {
                // Filter by payload ID
                InteractionFilter filter = InteractionFilter.interactionPayloadFilter(payloadId);
                interactions = collaboratorClient.getInteractions(filter);
                result.append("**Filter:** Payload ID = ").append(payloadId).append("\n");
            } else {
                // Get all interactions
                interactions = collaboratorClient.getAllInteractions();
                result.append("**Filter:** ").append(interactionType).append(" interactions\n");
            }
            
            result.append("**Total Matching:** ").append(interactions.size()).append("\n\n");
            
            if (interactions.isEmpty()) {
                result.append("ℹ️ No matching interactions found.\n");
            } else {
                // Apply type filter if specified
                List<Interaction> filteredInteractions = new ArrayList<>();
                for (Interaction interaction : interactions) {
                    if (interactionType.equals("ALL") || 
                        interaction.type().toString().equalsIgnoreCase(interactionType)) {
                        filteredInteractions.add(interaction);
                    }
                }
                
                result.append("**Filtered Results:** ").append(filteredInteractions.size()).append(" interactions\n\n");
                
                // Group by type for summary
                Map<InteractionType, Integer> typeCounts = new HashMap<>();
                for (Interaction interaction : filteredInteractions) {
                    typeCounts.put(interaction.type(), typeCounts.getOrDefault(interaction.type(), 0) + 1);
                }
                
                if (!typeCounts.isEmpty()) {
                    result.append("**Summary by Type:**\n");
                    for (Map.Entry<InteractionType, Integer> entry : typeCounts.entrySet()) {
                        result.append("• ").append(entry.getKey()).append(": ").append(entry.getValue()).append("\n");
                    }
                    result.append("\n");
                }
                
                // Show first few interactions with details
                for (int i = 0; i < Math.min(5, filteredInteractions.size()); i++) {
                    Interaction interaction = filteredInteractions.get(i);
                    result.append("**").append(i + 1).append(". ").append(interaction.type()).append(" Interaction**\n");
                    result.append("• **ID:** ").append(interaction.id().toString()).append("\n");
                    result.append("• **Time:** ").append(interaction.timeStamp()).append("\n");
                    
                    Optional<String> customData = interaction.customData();
                    if (customData.isPresent()) {
                        result.append("• **Custom Data:** ").append(customData.get()).append("\n");
                    }
                    
                    result.append("\n");
                }
                
                if (filteredInteractions.size() > 5) {
                    result.append("... and ").append(filteredInteractions.size() - 5).append(" more interactions\n");
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
