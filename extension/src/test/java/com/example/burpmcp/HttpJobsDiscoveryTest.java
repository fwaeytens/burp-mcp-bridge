package com.example.burpmcp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/** Exercises the same help and metadata paths clients use, without creating a native execution. */
public class HttpJobsDiscoveryTest {
    private static final String TOOL = "burp_http_jobs";
    private static final List<String> ACTIONS = List.of("START", "LIST", "STATUS", "RESULTS", "PAUSE", "RESUME", "CANCEL");
    private static final Map<String, List<String>> REQUIREMENTS = Map.of(
        "START", List.of("requests"), "LIST", List.of(), "STATUS", List.of("job_id"),
        "RESULTS", List.of("job_id"), "PAUSE", List.of("job_id"),
        "RESUME", List.of("job_id"), "CANCEL", List.of("job_id"));
    private final ObjectMapper mapper = new ObjectMapper();
    private HttpJobsTool jobs;
    private BurpHelpTool help;
    private JsonNode listed;

    @Before
    public void setUp() {
        jobs = new HttpJobsTool(null);
        ToolDocumentationStore.getInstance().syncWithToolSchemas(Map.of(TOOL, jobs));
        help = new BurpHelpTool(null);
        listed = mapper.valueToTree(AgentToolMetadata.forToolsList(TOOL, jobs.getToolInfo()));
    }

    @After
    public void close() {
        jobs.close();
    }

    @Test
    public void helpFindsJobsForBackgroundControlAndPaginationQueries() throws Exception {
        for (String query : List.of("background HTTP batch", "pause jobs", "resume jobs",
                "pause/resume jobs", "paginated HTTP results")) {
            JsonNode result = help(Map.of("capability", query));
            boolean found = false;
            for (JsonNode candidate : result.path("tools")) {
                if (TOOL.equals(candidate.path("tool").asText())) found = true;
            }
            assertTrue("burp_help did not discover HTTP jobs for: " + query, found);
        }
    }

    @Test
    public void toolsListPublishesAccurateRequirementsForEveryAction() {
        JsonNode schema = listed.path("inputSchema");
        assertEquals(TOOL, listed.path("name").asText());
        assertEquals(mapper.valueToTree(ACTIONS), schema.path("properties").path("action").path("enum"));
        // START-only and job-ID requirements must not make the parameterless LIST action invalid.
        assertEquals(mapper.valueToTree(List.of("action")), schema.path("required"));
        assertEquals(mapper.valueToTree(REQUIREMENTS), schema.path(AgentToolMetadata.ACTION_REQUIREMENTS_KEY));
        assertEquals(mapper.valueToTree(REQUIREMENTS), listed.path("_meta").path("burp/actionRequirements"));
        assertEquals("Core HTTP/Proxy", listed.path("_meta").path("burp/category").asText());
        assertTrue(listed.path("_meta").path("burp/help").asText().contains(TOOL));
        assertTrue(listed.path("_meta").path("anthropic/searchHint").asText().contains("background"));
        assertTrue(listed.path("_meta").path("anthropic/searchHint").asText().contains("jobs"));
        assertEquals(mapper.valueToTree(Map.of("readOnlyHint", false, "destructiveHint", true,
            "idempotentHint", false, "openWorldHint", true)), listed.path("annotations"));
        assertTrue(listed.path("description").asText().contains("burp_custom_http"));
        assertTrue(listed.path("description").asText().length() <= 220);
        assertTrue(AgentToolMetadata.shortDescriptionFor("burp_custom_http").contains(TOOL));
        assertFalse(schema.path("additionalProperties").asBoolean(true));

        for (Map.Entry<String, List<String>> entry : REQUIREMENTS.entrySet()) {
            for (String required : entry.getValue()) {
                assertTrue(entry.getKey() + " refers to an undocumented parameter: " + required,
                    schema.path("properties").has(required));
            }
        }
    }

    @Test
    public void tlsOverrideIsOptionalWithoutAPublishedDefaultThatDisablesInference() {
        JsonNode property = listed.path("inputSchema").path("properties").path("use_https");
        assertEquals("boolean", property.path("type").asText());
        assertFalse("A default TLS override would suppress Host-port inference", property.has("default"));
        String description = property.path("description").asText();
        assertTrue(description.contains("omitted"));
        assertTrue(description.contains("port 80"));
        assertTrue(description.contains("schemes take precedence"));

        var arguments = mapper.createObjectNode().put("action", "START");
        arguments.set("requests", mapper.valueToTree(List.of("GET / HTTP/1.1\r\nHost: example.test:80\r\n\r\n")));
        HttpJobRequests.validate(arguments);
        arguments.putNull("use_https");
        org.junit.Assert.assertThrows(IllegalArgumentException.class, () -> HttpJobRequests.validate(arguments));
    }

    @Test
    public void fullAndSectionHelpAgreeWithPublishedParametersAndReturns() throws Exception {
        JsonNode full = help(Map.of("tool", TOOL, "section", "full"));
        JsonNode parameters = help(Map.of("tool", TOOL, "section", "parameters"));
        JsonNode examples = help(Map.of("tool", TOOL, "section", "examples"));
        JsonNode schema = listed.path("inputSchema");

        assertEquals(TOOL, full.path("tool").asText());
        assertEquals(mapper.valueToTree(jobs.getToolInfo().get("description")), full.path("description"));
        assertEquals(schema.path("required"), full.path("required_params"));
        assertEquals(mapper.valueToTree(REQUIREMENTS), full.path("action_requirements"));
        assertEquals(listed.path("outputSchema"), full.path("returns"));
        for (String sectionField : List.of("parameters", "required_params", "action_requirements", "returns")) {
            assertEquals(sectionField, full.path(sectionField), parameters.path(sectionField));
        }
        assertEquals(full.path("examples"), examples.path("examples"));

        Set<String> documented = new HashSet<>();
        Set<String> required = strings(schema.path("required"));
        for (JsonNode parameter : full.path("parameters")) {
            String name = parameter.path("name").asText();
            assertTrue("Duplicate parameter in help: " + name, documented.add(name));
            JsonNode property = schema.path("properties").path(name);
            assertFalse("Undocumented tools/list parameter: " + name, property.isMissingNode());
            assertEquals(name, required.contains(name), parameter.path("required").asBoolean());
            for (String field : List.of("type", "description", "default", "enum", "items", "properties",
                    "minimum", "maximum", "minItems", "maxItems", "minLength", "maxLength", "pattern", "format")) {
                if (property.has(field)) assertEquals(name + "." + field, property.get(field), parameter.get(field));
            }
        }
        assertEquals(fieldNames(schema.path("properties")), documented);
    }

    @Test
    public void curatedExamplesCoverAllActionsAndMeetAdvertisedInputContracts() throws Exception {
        JsonNode full = help(Map.of("tool", TOOL, "section", "full"));
        JsonNode schema = listed.path("inputSchema");
        Set<String> exampleActions = new HashSet<>();
        for (JsonNode example : full.path("examples")) {
            String title = example.path("title").asText();
            assertFalse("Every curated example needs a title", title.isBlank());
            JsonNode input = example.path("input");
            assertInputSchema(schema, input, title);
            String action = input.path("action").asText();
            assertTrue(title + " has an unsupported action", REQUIREMENTS.containsKey(action));
            exampleActions.add(action);
            for (String required : REQUIREMENTS.get(action)) {
                assertTrue(title + " is missing " + required, input.hasNonNull(required));
            }
            // Pure validation checks real request preparation rules without invoking Montoya factories.
            if ("START".equals(action)) HttpJobRequests.validate(input);
        }
        assertEquals(new HashSet<>(ACTIONS), exampleActions);
    }

    private JsonNode help(Map<String, Object> arguments) throws Exception {
        JsonNode response = mapper.valueToTree(help.execute(mapper.valueToTree(arguments)));
        assertFalse(response.toString(), response.path("isError").asBoolean());
        assertTrue("burp_help must return structured documentation", response.path("structuredContent").isObject());
        return response.path("structuredContent");
    }

    /** Validate the input-schema features advertised by this tool, plus action requirements above. */
    private void assertInputSchema(JsonNode schema, JsonNode value, String path) {
        switch (schema.path("type").asText()) {
            case "object" -> {
                assertTrue(path + " must be an object", value.isObject());
                for (JsonNode required : schema.path("required")) {
                    assertTrue(path + " is missing " + required.asText(), value.has(required.asText()));
                }
                Iterator<String> fields = value.fieldNames();
                while (fields.hasNext()) {
                    String field = fields.next();
                    JsonNode property = schema.path("properties").path(field);
                    if (property.isMissingNode()) {
                        assertTrue(path + " contains unsupported " + field, schema.path("additionalProperties").asBoolean(true));
                    } else {
                        assertInputSchema(property, value.get(field), path + "." + field);
                    }
                }
            }
            case "array" -> {
                assertTrue(path + " must be an array", value.isArray());
                if (schema.has("minItems")) assertTrue(path, value.size() >= schema.get("minItems").asInt());
                if (schema.has("maxItems")) assertTrue(path, value.size() <= schema.get("maxItems").asInt());
                for (JsonNode item : value) assertInputSchema(schema.path("items"), item, path + "[]");
            }
            case "string" -> {
                assertTrue(path + " must be a string", value.isTextual());
                if (schema.has("minLength")) assertTrue(path, value.asText().length() >= schema.get("minLength").asInt());
                if (schema.has("maxLength")) assertTrue(path, value.asText().length() <= schema.get("maxLength").asInt());
            }
            case "integer" -> assertTrue(path + " must be an integer", value.isIntegralNumber());
            case "boolean" -> assertTrue(path + " must be a boolean", value.isBoolean());
            default -> throw new AssertionError("Unhandled input schema type at " + path + ": " + schema);
        }
        if (schema.has("enum")) {
            boolean found = false;
            for (JsonNode allowed : schema.get("enum")) if (allowed.equals(value)) found = true;
            assertTrue(path + " is not an advertised enum value", found);
        }
        if (schema.has("minimum")) assertTrue(path, value.asDouble() >= schema.get("minimum").asDouble());
        if (schema.has("maximum")) assertTrue(path, value.asDouble() <= schema.get("maximum").asDouble());
    }

    private static Set<String> fieldNames(JsonNode object) {
        Set<String> names = new HashSet<>();
        object.fieldNames().forEachRemaining(names::add);
        return names;
    }

    private static Set<String> strings(JsonNode array) {
        Set<String> values = new HashSet<>();
        for (JsonNode value : array) values.add(value.asText());
        return values;
    }
}
