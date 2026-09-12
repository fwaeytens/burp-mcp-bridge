package com.example.burpmcp;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class AgentToolMetadataTest {
    @Test
    public void everyRegisteredToolHasConciseDiscoveryMetadataAndStructuredOutputSchema() {
        for (ToolDescriptor descriptor : ToolRegistry.descriptors()) {
            Map<String, Object> listed = AgentToolMetadata.forToolsList(
                descriptor.getName(),
                toolInfo(descriptor.getName(), List.of())
            );

            String shortDescription = AgentToolMetadata.shortDescriptionFor(descriptor.getName());
            assertNotNull(descriptor.getName(), shortDescription);
            assertEquals(shortDescription, listed.get("description"));
            assertTrue(descriptor.getName(), shortDescription.length() < 220);

            Map<String, Object> outputSchema = map(listed.get("outputSchema"));
            assertEquals("object", outputSchema.get("type"));
            assertEquals(Boolean.TRUE, outputSchema.get("additionalProperties"));
            Map<String, Object> outputProperties = map(outputSchema.get("properties"));
            assertTrue(outputProperties.containsKey("text"));
            assertTrue(outputProperties.containsKey("items"));
            assertTrue(outputProperties.containsKey("truncated"));
            assertTrue(outputProperties.containsKey("originalChars"));
            assertTrue(outputProperties.containsKey("limitChars"));

            Map<String, Object> meta = map(listed.get("_meta"));
            assertEquals(descriptor.getCategory(), meta.get("burp/category"));
            assertTrue(meta.get("burp/help").toString().contains(descriptor.getName()));
        }
    }

    @Test
    public void actionRequirementsIncludeNoArgActionsAndCuratedFields() {
        Map<String, Object> raw = toolInfo("burp_websocket",
            List.of("proxy_history", "create", "send", "close", "list_connections"));

        Map<String, List<String>> requirements = AgentToolMetadata.actionRequirementsFor("burp_websocket", raw);

        assertEquals(List.of(), requirements.get("proxy_history"));
        assertEquals(List.of("url"), requirements.get("create"));
        assertEquals(List.of("connectionId", "message"), requirements.get("send"));
        assertEquals(List.of("connectionId"), requirements.get("close"));
        assertEquals(List.of(), requirements.get("list_connections"));

        Map<String, Object> enriched = AgentToolMetadata.enrichToolInfo("burp_websocket", raw);
        Map<String, Object> inputSchema = map(enriched.get("inputSchema"));
        assertEquals(requirements, inputSchema.get(AgentToolMetadata.ACTION_REQUIREMENTS_KEY));
        assertEquals(requirements, map(enriched.get("_meta")).get("burp/actionRequirements"));
    }

    @Test
    public void nestedSchemasDescribeRuntimeObjectsInsteadOfOpaqueObjects() {
        Map<String, Object> global = AgentToolMetadata.enrichToolInfo(
            "burp_global_interceptor",
            toolInfoWithProperties("burp_global_interceptor", List.of("add_request_rule"), "rule", "mode", "tools", "rules_data")
        );
        Map<String, Object> globalProperties = properties(global);
        Map<String, Object> ruleProperties = map(map(globalProperties.get("rule")).get("properties"));
        assertTrue(ruleProperties.containsKey("url_pattern"));
        assertTrue(ruleProperties.containsKey("body_search"));
        assertTrue(ruleProperties.containsKey("match_pattern"));
        assertTrue(ruleProperties.containsKey("direction"));
        assertTrue(map(map(globalProperties.get("mode")).get("properties")).containsKey("intercept_requests"));
        assertEquals("string", map(map(globalProperties.get("tools")).get("items")).get("type"));
        assertTrue(map(map(globalProperties.get("rules_data")).get("properties")).containsKey("requestRules"));

        Map<String, Object> proxy = AgentToolMetadata.enrichToolInfo(
            "burp_proxy_interceptor",
            toolInfoWithProperties("burp_proxy_interceptor", List.of("modify_request"), "modifications", "options")
        );
        Map<String, Object> proxyProperties = properties(proxy);
        assertEquals("string", map(proxyProperties.get("response_id")).get("type"));
        Map<String, Object> modificationProperties = map(map(proxyProperties.get("modifications")).get("properties"));
        assertTrue(modificationProperties.containsKey("add_headers"));
        assertTrue(modificationProperties.containsKey("replace_body"));
        assertTrue(modificationProperties.containsKey("status_code"));
        assertTrue(map(map(proxyProperties.get("options")).get("properties")).containsKey("highlight_color"));
    }

    @Test
    public void existingOutputSchemasKeepSpecificFieldsAndGainVerboseFallbackFields() {
        Map<String, Object> raw = toolInfo("burp_scanner", List.of("GET_STATUS"));
        raw.put("outputSchema", Map.of(
            "type", "object",
            "properties", Map.of("scanId", Map.of("type", "string"))
        ));

        Map<String, Object> enriched = AgentToolMetadata.enrichToolInfo("burp_scanner", raw);
        Map<String, Object> properties = map(map(enriched.get("outputSchema")).get("properties"));

        assertTrue(properties.containsKey("scanId"));
        assertTrue(properties.containsKey("text"));
        assertTrue(properties.containsKey("items"));
        assertTrue(properties.containsKey("truncated"));
    }

    @Test
    public void genericArrayFallbackAllowsPrimitiveItemsAndClosedSchemasStayClosed() {
        Map<String, Object> raw = toolInfo("burp_scanner", List.of("GET_STATUS"));
        raw.put("outputSchema", Map.of(
            "type", "object",
            "additionalProperties", false,
            "properties", Map.of("scanId", Map.of("type", "string"))
        ));

        Map<String, Object> enriched = AgentToolMetadata.enrichToolInfo("burp_scanner", raw);
        Map<String, Object> outputSchema = map(enriched.get("outputSchema"));
        Map<String, Object> properties = map(outputSchema.get("properties"));
        Map<String, Object> genericItems = map(map(properties.get("items")).get("items"));

        assertEquals(Boolean.FALSE, outputSchema.get("additionalProperties"));
        assertEquals("Array item.", genericItems.get("description"));
        assertFalse(genericItems.containsKey("type"));
    }

    @Test
    public void exportedAuthenticationCanRoundTripThroughImportSchema() throws Exception {
        GlobalInterceptorTool tool = new GlobalInterceptorTool(null);
        ObjectMapper mapper = new ObjectMapper();
        try {
            tool.close();
            assertAuthenticationRoundTrip(tool, mapper, null, null);

            tool.execute(mapper.valueToTree(Map.of(
                "action", "set_auth", "auth_type", "bearer", "auth_value", "test-token")));
            assertAuthenticationRoundTrip(tool, mapper, "bearer", "Bearer test-token");

            tool.execute(mapper.valueToTree(Map.of("action", "clear_auth")));
            assertAuthenticationRoundTrip(tool, mapper, null, null);

            tool.execute(mapper.valueToTree(Map.of("action", "import_rules", "rules_data", Map.of(
                "settings", Map.of(), "requestRules", List.of(Map.of("priority", 0, "config", Map.of()))))));
            assertAuthenticationRoundTrip(tool, mapper, null, null);
        } finally {
            tool.close();
        }
    }

    private void assertAuthenticationRoundTrip(GlobalInterceptorTool tool,
                                               ObjectMapper mapper,
                                               String expectedType,
                                               String expectedValue) throws Exception {
        Map<String, Object> exported = map(map(tool.execute(
            mapper.valueToTree(Map.of("action", "export_rules")))).get("structuredContent"));
        Map<String, Object> settings = map(exported.get("settings"));
        assertEquals(expectedType, settings.get("authType"));
        assertEquals(expectedValue, settings.get("authValue"));

        Map<String, Object> toolInfo = AgentToolMetadata.forToolsList(
            "burp_global_interceptor", tool.getToolInfo());
        OutputSchemaAssertions.assertMatches(mapper.valueToTree(properties(toolInfo).get("rules_data")), mapper.valueToTree(exported));
        Map<String, Object> rulesProperties = map(map(properties(toolInfo).get("rules_data")).get("properties"));
        Map<String, Object> settingSchemas = map(map(rulesProperties.get("settings")).get("properties"));
        for (String field : List.of("authType", "authValue", "authHeader")) {
            Object declaredTypes = map(settingSchemas.get(field)).get("type");
            List<?> allowedTypes = declaredTypes instanceof List<?> types ? types : List.of(declaredTypes);
            String exportedType = settings.get(field) == null ? "null" : "string";
            assertTrue("Exported " + field + " must satisfy the import schema", allowedTypes.contains(exportedType));
        }

        Map<String, Object> imported = map(tool.execute(mapper.valueToTree(Map.of(
            "action", "import_rules", "rules_data", exported))));
        assertEquals(Boolean.TRUE, map(imported.get("structuredContent")).get("success"));
        Map<String, Object> reexported = map(map(tool.execute(
            mapper.valueToTree(Map.of("action", "export_rules")))).get("structuredContent"));
        assertEquals(exported, reexported);
    }

    private Map<String, Object> toolInfo(String name, List<String> actions) {
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("name", name);
        info.put("description", "Long detailed description that should stay available outside concise discovery mode.");
        Map<String, Object> inputSchema = new LinkedHashMap<>();
        inputSchema.put("type", "object");
        Map<String, Object> properties = new LinkedHashMap<>();
        if (!actions.isEmpty()) {
            properties.put("action", Map.of("type", "string", "enum", actions));
        }
        inputSchema.put("properties", properties);
        info.put("inputSchema", inputSchema);
        return info;
    }

    private Map<String, Object> toolInfoWithProperties(String name, List<String> actions, String... propertyNames) {
        Map<String, Object> info = toolInfo(name, actions);
        Map<String, Object> properties = properties(info);
        for (String propertyName : propertyNames) {
            properties.put(propertyName, Map.of("type", "object", "description", "opaque"));
        }
        return info;
    }

    private Map<String, Object> properties(Map<String, Object> toolInfo) {
        return map(map(toolInfo.get("inputSchema")).get("properties"));
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> map(Object value) {
        return (Map<String, Object>) value;
    }
}
