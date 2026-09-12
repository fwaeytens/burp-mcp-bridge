package com.example.burpmcp;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.After;
import org.junit.Test;

import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;
import java.util.function.Consumer;

import static org.junit.Assert.*;

/** Validate real structured results against the schema exposed to MCP clients. */
public class HttpJobsOutputSchemaTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private final FakeEngine engine = new FakeEngine();
    private final HttpJobsTool tool = new HttpJobsTool(engine,
        args -> Arrays.stream(JSON.convertValue(args.path("requests"), String[].class))
                .map(url -> proxy(HttpRequest.class, (method, values) -> "url".equals(method) ? url : null)).toList(),
        () -> 1000L, new HttpJobsTool.Limits(4, 20, 50, 24, 16, 3_600_000));
    private final JsonNode schema = JSON.valueToTree(AgentToolMetadata.forToolsList("burp_http_jobs", tool.getToolInfo())).path("outputSchema");

    @After
    public void close() {
        tool.close();
    }

    @Test
    public void realLifecycleAndPaginatedResultsMatchThePublishedOutputContract() {
        JsonNode inventory = call(Map.of("action", "LIST"), false);
        assertTrue(inventory.path("available").asBoolean());
        assertEquals(16, inventory.path("limits").path("response_preview_bytes").asInt());
        String id = start();
        assertEquals("running", call(Map.of("action", "STATUS", "job_id", id), false).path("state").asText());
        call(Map.of("action", "LIST"), false); // Validate nested job summaries as well.
        call(Map.of("action", "PAUSE", "job_id", id), false);
        call(Map.of("action", "RESUME", "job_id", id), false);

        // Complete index 2 before index 0: pages still follow the submitted input indices.
        engine.emit(2, "RESPONDED", "HTTP/1.1 404 Not Found\r\n\r\nmissing");
        engine.emit(0, "TIMED_OUT", null);
        JsonNode first = call(Map.of("action", "RESULTS", "job_id", id, "limit", 2), false);
        assertEquals(2, first.path("next_offset").asInt());
        assertEquals(0, first.path("results").get(0).path("index").asInt());
        assertEquals("PENDING", first.path("results").get(1).path("status").asText());
        JsonNode last = call(Map.of("action", "RESULTS", "job_id", id, "offset", 2, "include_response", true), false);
        assertTrue(last.path("next_offset").isNull());
        assertFalse(last.path("has_more").asBoolean());
        assertEquals("running", last.path("state").asText()); // End of pagination is not completion.
        JsonNode response = last.path("results").get(0);
        assertEquals(2, response.path("index").asInt());
        assertEquals(404, response.path("status_code").asInt());
        assertTrue(response.path("response_truncated").asBoolean());
        assertEquals(response.path("preview_bytes").asInt(), Base64.getDecoder().decode(response.path("response_base64").asText()).length);
        JsonNode summaryOnly = call(Map.of("action", "RESULTS", "job_id", id, "offset", 2), false);
        assertFalse(summaryOnly.path("results").get(0).has("response_base64"));

        call(Map.of("action", "CANCEL", "job_id", id), false);
        engine.emit(1, "DROPPED", null);
        engine.complete(true);
        JsonNode terminal = call(Map.of("action", "RESULTS", "job_id", id), false);
        assertEquals("cancelled", terminal.path("state").asText());
        assertEquals("DROPPED", terminal.path("results").get(1).path("status").asText());
        assertEquals(3, terminal.path("progress").path("requested").asInt());
        assertEquals(0, terminal.path("progress").path("pending").asInt());
        assertTrue(terminal.has("finished_at"));
        assertTrue(terminal.has("expires_at"));
    }

    @Test
    public void errorAvailabilityAndUnknownOutcomeEnvelopesAlsoValidate() {
        assertEquals("invalid_arguments", call(Map.of("action", "RESULTS"), true).path("error").asText());
        assertEquals("unknown_job", call(Map.of("action", "STATUS", "job_id", "missing"), true).path("error").asText());
        HttpJobsTool unavailable = new HttpJobsTool(null);
        try {
            JsonNode list = JSON.valueToTree(unavailable.execute(JSON.valueToTree(Map.of("action", "LIST"))));
            assertFalse(list.path("isError").asBoolean());
            assertContract(schema, list.path("structuredContent"), "$", true);
            assertFalse(list.path("structuredContent").path("available").asBoolean());
            JsonNode failure = JSON.valueToTree(unavailable.execute(JSON.valueToTree(Map.of("action", "START", "requests", List.of("https://example.test/")))));
            assertTrue(failure.path("isError").asBoolean());
            assertContract(schema, failure.path("structuredContent"), "$", true);
        } finally {
            unavailable.close();
        }
        String id = start();
        engine.complete(false); // Native completion without individual callbacks leaves uncertain outcomes.
        JsonNode results = call(Map.of("action", "RESULTS", "job_id", id), false);
        assertEquals("UNKNOWN", results.path("results").get(0).path("status").asText());
        assertContract(schema, JSON.valueToTree(Map.of("text", "Partial response", "truncated", true,
            "originalChars", 100000, "limitChars", 95000)), "$", true);
        tool.close();
        assertEquals("closed", call(Map.of("action", "LIST"), true).path("error").asText());
    }

    @Test
    public void contractRejectsMalformedPaginationProgressAndResultRows() {
        String id = start();
        ObjectNode result = (ObjectNode) call(Map.of("action", "RESULTS", "job_id", id), false);
        ObjectNode badOffset = result.deepCopy();
        badOffset.put("next_offset", "done");
        assertThrows(AssertionError.class, () -> assertContract(schema, badOffset, "$", true));
        ObjectNode badIndex = result.deepCopy();
        ((ObjectNode) badIndex.path("results").get(0)).put("index", "0");
        assertThrows(AssertionError.class, () -> assertContract(schema, badIndex, "$", true));
        ObjectNode missingStatus = result.deepCopy();
        ((ObjectNode) missingStatus.path("results").get(0)).remove("status");
        assertThrows(AssertionError.class, () -> assertContract(schema, missingStatus, "$", true));
        ObjectNode negativeProgress = result.deepCopy();
        ((ObjectNode) negativeProgress.path("progress")).put("pending", -1);
        assertThrows(AssertionError.class, () -> assertContract(schema, negativeProgress, "$", true));
    }

    private String start() {
        return call(Map.of("action", "START", "requests", List.of("https://example.test/a", "https://example.test/b", "https://example.test/c")), false).path("job_id").asText();
    }

    private JsonNode call(Map<String, Object> arguments, boolean isError) {
        JsonNode response = JSON.valueToTree(tool.execute(JSON.valueToTree(arguments)));
        assertEquals(response.toString(), isError, response.path("isError").asBoolean());
        JsonNode data = response.path("structuredContent");
        assertTrue(data.isObject());
        assertContract(schema, data, "$", true);
        return data;
    }

    /** Implements only the JSON Schema keywords used by this output contract. */
    private static void assertContract(JsonNode schema, JsonNode value, String path, boolean documented) {
        JsonNode types = schema.path("type");
        boolean validType = types.isArray()
            ? java.util.stream.StreamSupport.stream(types.spliterator(), false).anyMatch(t -> isType(t.asText(), value))
            : isType(types.asText(), value);
        assertTrue(path + " violates type " + types + ": " + value, validType);
        if (schema.has("enum")) {
            assertTrue(path + " has undocumented value " + value,
                java.util.stream.StreamSupport.stream(schema.get("enum").spliterator(), false).anyMatch(value::equals));
        }
        if (value.isNumber() && schema.has("minimum")) assertTrue(path, value.asDouble() >= schema.path("minimum").asDouble());
        if (value.isObject()) {
            for (JsonNode required : schema.path("required")) assertTrue(path + " missing " + required, value.has(required.asText()));
            value.fields().forEachRemaining(field -> {
                JsonNode property = schema.path("properties").path(field.getKey());
                if (property.isMissingNode()) {
                    assertFalse(path + "." + field.getKey() + " lacks discovery documentation", documented);
                    assertTrue(path, schema.path("additionalProperties").asBoolean(true));
                } else assertContract(property, field.getValue(), path + "." + field.getKey(), documented);
            });
        } else if (value.isArray()) {
            for (int i = 0; i < value.size(); i++) assertContract(schema.path("items"), value.get(i), path + "[" + i + "]", documented);
        }
    }

    private static boolean isType(String type, JsonNode value) {
        return switch (type) {
            case "object" -> value.isObject();
            case "array" -> value.isArray();
            case "string" -> value.isTextual();
            case "integer" -> value.isIntegralNumber();
            case "number" -> value.isNumber();
            case "boolean" -> value.isBoolean();
            case "null" -> value.isNull();
            default -> throw new AssertionError("Unhandled output schema type: " + type);
        };
    }

    @SuppressWarnings("unchecked")
    private static <T> T proxy(Class<T> type, BiFunction<String, Object[], Object> invoke) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, (p, method, args) -> invoke.apply(method.getName(), args));
    }

    private static ByteArray bytes(byte[] data) {
        return proxy(ByteArray.class, (method, args) -> switch (method) {
            case "length" -> data.length;
            case "getBytes" -> data.clone();
            case "subArray" -> bytes(Arrays.copyOfRange(data, (Integer) args[0], (Integer) args[1]));
            default -> null;
        });
    }

    private static final class FakeEngine implements HttpJobEngine, HttpJobEngine.Execution {
        private Consumer<Result> result;
        private Consumer<Completion> completion;
        private int requested;
        private int completed;
        private int failed;

        public Execution start(List<HttpRequest> requests, Options options, Consumer<Result> result, Consumer<Completion> completion) {
            this.requested = requests.size();
            this.result = result;
            this.completion = completion;
            return this;
        }

        void emit(int index, String status, String raw) {
            HttpRequestResponse exchange = null;
            if (raw != null) {
                byte[] data = raw.getBytes(StandardCharsets.ISO_8859_1);
                HttpResponse response = proxy(HttpResponse.class, (method, args) -> switch (method) {
                    case "statusCode" -> (short) 404;
                    case "toByteArray" -> bytes(data);
                    case "bodyOffset" -> raw.indexOf("\r\n\r\n") + 4;
                    default -> null;
                });
                exchange = proxy(HttpRequestResponse.class, (method, args) -> "response".equals(method) ? response : null);
                completed++;
            } else failed++;
            result.accept(new Result(index, status, exchange));
        }

        void complete(boolean cancelled) { completion.accept(new Completion(cancelled, stats())); }
        public void pause() { }
        public void resume() { }
        public void cancel() { }
        public Stats stats() { return new Stats(requested, completed, failed, 0, requested - completed - failed, 100); }
    }
}
