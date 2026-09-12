package com.example.burpmcp;

import burp.api.montoya.MontoyaApi;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.*;

/** Exercises the catalog agents receive, including the curated argument/result examples. */
public class ToolCatalogContractTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Set<String> GENERIC_FIELDS = Set.of("text", "items", "truncated", "originalChars", "limitChars");
    private static final Set<String> ENRICHED_TOOLS = Set.of("burp_repeater", "burp_intruder", "burp_add_issue",
        "burp_session_management", "burp_collaborator", "burp_scope", "burp_config", "burp_organizer", "burp_annotate",
        "burp_logs", "burp_utilities", "burp_proxy_interceptor", "burp_global_interceptor", "burp_websocket",
        "burp_websocket_interceptor", "burp_comparer", "burp_bambda", "burp_response_analyzer");
    private Map<String, McpTool> tools;
    private String originalHome;
    private Path temporaryHome;

    @Before
    public void setUp() throws Exception {
        originalHome = System.getProperty("user.home");
        temporaryHome = Files.createTempDirectory("burp-catalog-test-");
        System.setProperty("user.home", temporaryHome.toString());
        tools = ToolRegistry.createTools((MontoyaApi) fake(MontoyaApi.class));
        ToolDocumentationStore.getInstance().syncWithToolSchemas(tools);
    }

    @After
    public void close() throws Exception {
        if (tools != null) for (McpTool tool : tools.values()) tool.close();
        if (originalHome != null) System.setProperty("user.home", originalHome);
        if (temporaryHome != null) try (var files = Files.walk(temporaryHome)) {
            for (Path file : files.sorted(java.util.Comparator.reverseOrder()).toList()) Files.deleteIfExists(file);
        }
    }

    @Test
    public void everyToolPublishesDomainFieldsAndCompatibleFallbackResults() {
        assertEquals(24, tools.size());
        for (Map.Entry<String, McpTool> entry : tools.entrySet()) {
            JsonNode info = info(entry.getKey());
            JsonNode output = info.path("outputSchema");
            Set<String> fields = new HashSet<>();
            output.path("properties").fieldNames().forEachRemaining(fields::add);
            fields.removeAll(GENERIC_FIELDS);
            assertFalse(entry.getKey() + " still has only generic output fields", fields.isEmpty());
            OutputSchemaAssertions.assertMatches(output, JSON.valueToTree(Map.of("text", "Diagnostic")));
            OutputSchemaAssertions.assertMatches(output, JSON.valueToTree(Map.of("text", "Partial response", "truncated", true,
                "originalChars", 100000, "limitChars", 95000)));
            assertNotNull(info.path("annotations").get("readOnlyHint"));
            assertNotNull(info.path("annotations").get("openWorldHint"));
        }
    }

    @Test
    public void curatedExamplesAgreeWithPublishedInputsOutputsAndActionRequirements() {
        int examples = 0;
        List<String> failures = new java.util.ArrayList<>();
        for (ToolDocumentation doc : ToolDocumentationStore.getInstance().getAllDocumentation()) {
            JsonNode info = info(doc.getName());
            for (Map<String, Object> example : doc.getExamples()) {
                JsonNode input = JSON.valueToTree(example.get("input"));
                if (input.path("note").asText().equals("this is a Playwright call, not a burp tool")) continue;
                String label = doc.getName() + ": " + example.get("title");
                try {
                    OutputSchemaAssertions.assertMatches(info.path("inputSchema"), input);
                    String action = input.path("action").asText(input.path("operation").asText());
                    for (String required : doc.getActionRequirements().getOrDefault(action, List.of())) {
                        assertTrue("Missing " + required, java.util.Arrays.stream(required.split("\\|")).anyMatch(input::hasNonNull));
                    }
                    for (Map<String, Object> rule : doc.getConditionalRequirements()) {
                        JsonNode condition = JSON.valueToTree(rule);
                        if (action.equals(condition.path("action").asText())
                            && java.util.stream.StreamSupport.stream(condition.path("when_present").spliterator(), false).allMatch(p -> input.has(p.asText()))) {
                            for (JsonNode required : condition.path("required")) assertTrue(input.hasNonNull(required.asText()));
                        }
                    }
                    if ("burp_http_jobs".equals(doc.getName()) && "START".equals(action)) HttpJobRequests.validate(input);
                    if (input.path("request").isTextual()) assertFalse("Raw request contains literal CRLF escape text", input.get("request").asText().contains("\\r\\n"));
                    JsonNode output = JSON.valueToTree(example.get("output"));
                    if (ENRICHED_TOOLS.contains(doc.getName())) OutputSchemaAssertions.assertDocumented(info.path("outputSchema"), output);
                    else OutputSchemaAssertions.assertMatches(info.path("outputSchema"), output);
                } catch (AssertionError failure) {
                    failures.add(label + ": " + failure.getMessage());
                }
                examples++;
            }
        }
        assertTrue("Expected the full operational example catalog", examples >= 83);
        assertTrue(String.join("\n", failures), failures.isEmpty());
    }

    @Test
    public void scannerConditionalTlsRequirementsReachToolsListAndHelp() throws Exception {
        JsonNode info = info("burp_scanner");
        JsonNode requirements = info.path("_meta").path("burp/conditionalRequirements");
        assertEquals(JSON.valueToTree(List.of(Map.of("action", "ADD_TO_SCAN", "when_present", List.of("request"),
            "required", List.of("useHttps")))), requirements);
        assertEquals(requirements, info.path("inputSchema").path(AgentToolMetadata.CONDITIONAL_REQUIREMENTS_KEY));
        for (String section : List.of("full", "parameters")) {
            JsonNode response = JSON.valueToTree(tools.get("burp_help").execute(JSON.valueToTree(Map.of("tool", "burp_scanner", "section", section))));
            assertFalse(response.path("isError").asBoolean());
            assertEquals(requirements, response.path("structuredContent").path("conditional_requirements"));
        }
        assertEquals(JSON.valueToTree(List.of("scanId", "urls|request")),
            info.path("_meta").path("burp/actionRequirements").path("ADD_TO_SCAN"));
    }

    @Test
    public void unsupportedAndNetworkActionsHaveAccurateDiscovery() {
        assertTrue(info("burp_bambda").path("description").asText().contains("unavailable"));
        for (String name : List.of("burp_comparer", "burp_response_analyzer", "burp_custom_http", "burp_http_jobs", "burp_session_management")) {
            JsonNode annotations = info(name).path("annotations");
            assertFalse(name, annotations.path("readOnlyHint").asBoolean(true));
            assertTrue(name, annotations.path("openWorldHint").asBoolean());
        }
    }

    private JsonNode info(String name) {
        return JSON.valueToTree(AgentToolMetadata.forToolsList(name, tools.get(name).getToolInfo()));
    }

    private static Object fake(Class<?> type) {
        return Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, (proxy, method, args) -> {
            if (method.getDeclaringClass() == Object.class) return switch (method.getName()) {
                case "toString" -> "Catalog-test " + type.getSimpleName();
                case "hashCode" -> System.identityHashCode(proxy);
                case "equals" -> proxy == args[0];
                default -> null;
            };
            if (method.getName().equals("collaborator")) throw new UnsupportedOperationException("No external Collaborator in catalog tests");
            Class<?> result = method.getReturnType();
            if (result == void.class) return null;
            if (result == boolean.class) return false;
            if (result.isInterface()) return fake(result);
            throw new UnsupportedOperationException("Catalog test does not execute " + method);
        });
    }
}
