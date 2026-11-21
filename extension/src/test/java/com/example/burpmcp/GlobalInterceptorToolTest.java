package com.example.burpmcp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.After;
import org.junit.Test;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class GlobalInterceptorToolTest {
    private final ObjectMapper mapper = new ObjectMapper();
    private final GlobalInterceptorTool tool = new GlobalInterceptorTool(null);

    @After
    public void tearDown() {
        tool.close();
    }

    @Test
    public void setAuthWithDifferentHeaderReplacesPreviousAuthHeader() throws Exception {
        tool.execute(setAuth("api_key", "first", "X-Token-A"));
        tool.execute(setAuth("api_key", "second", "X-Token-B"));

        Map<String, String> headers = globalHeaders();
        assertFalse(headers.containsKey("X-Token-A"));
        assertEquals("second", headers.get("X-Token-B"));
        assertEquals(1, headers.size());

        tool.execute(setAuth("bearer", "tok", null));
        headers = globalHeaders();
        assertFalse(headers.containsKey("X-Token-B"));
        assertEquals("Bearer tok", headers.get("Authorization"));
        assertEquals(1, headers.size());
    }

    @Test
    @SuppressWarnings("unchecked")
    public void unsupportedAuthTypeIsRejectedAndLeavesStateUnchanged() throws Exception {
        tool.execute(setAuth("api_key", "keep", "X-Keep"));
        Map<String, Object> response = (Map<String, Object>) tool.execute(setAuth("bogus", "x", null));

        assertEquals(true, response.get("isError"));
        Map<String, String> headers = globalHeaders();
        assertEquals("keep", headers.get("X-Keep"));
        assertEquals(1, headers.size());
    }

    // ---- Concurrency -------------------------------------------------------------------
    // MCP workers run tool calls in parallel, so auth changes can overlap. These are stress
    // checks of invariants that must hold however the calls interleave; they cannot force a
    // particular interleaving.

    private static final int ROUNDS = 2000;

    @Test
    public void concurrentSetAuthLeavesExactlyTheReportedAuthHeader() throws Exception {
        final int callers = 4;
        for (int round = 0; round < ROUNDS; round++) {
            List<Callable<JsonNode>> calls = new ArrayList<>();
            for (int c = 0; c < callers; c++) {
                String header = "X-Caller-" + c;
                String value = "value-" + c;
                calls.add(() -> {
                    JsonNode response = structured(tool.execute(setAuth("api_key", value, header)));
                    assertEquals("a set_auth response must describe its own call", header, response.path("authHeader").asText());
                    return response;
                });
            }
            runTogether(calls);

            String reported = structured(tool.execute(action("get_status"))).path("authHeader").asText();
            assertTrue("round " + round + ": unexpected reported auth header '" + reported + "'", reported.startsWith("X-Caller-"));
            assertEquals("round " + round, Map.of(reported, "value-" + reported.substring("X-Caller-".length())),
                new HashMap<>(globalHeaders()));
            tool.close();
        }
    }

    @Test
    public void concurrentSetAndClearAgreeOnWhetherAuthIsInstalled() throws Exception {
        for (int round = 0; round < ROUNDS; round++) {
            runTogether(List.of(
                () -> structured(tool.execute(setAuth("api_key", "value", "X-Race"))),
                () -> structured(tool.execute(action("clear_auth")))));

            boolean reported = structured(tool.execute(action("get_status"))).has("authType");
            Map<String, String> headers = new HashMap<>(globalHeaders());
            assertEquals("round " + round + ": status and installed headers disagree: " + headers,
                reported ? Map.of("X-Race", "value") : Map.of(), headers);
            tool.close();
        }
    }

    @Test
    public void concurrentSetAndImportLeaveHeadersMatchingTheAuthSettings() throws Exception {
        ObjectNode imported = action("import_rules");
        ObjectNode rules = imported.putObject("rules_data");
        rules.putObject("globalHeaders").put("X-Imported", "imported-value");
        rules.putObject("settings").put("authType", "api_key").put("authValue", "imported-value").put("authHeader", "X-Imported");

        for (int round = 0; round < ROUNDS; round++) {
            runTogether(List.of(
                () -> structured(tool.execute(setAuth("api_key", "set-value", "X-Set"))),
                () -> structured(tool.execute(imported))));

            assertExportIsSelfConsistent("round " + round, structured(tool.execute(action("export_rules"))));
            tool.close();
        }
    }

    @Test
    public void exportTakenDuringSetAuthIsSelfConsistent() throws Exception {
        tool.execute(setAuth("api_key", "value-a", "X-Token-A"));
        AtomicBoolean writing = new AtomicBoolean(true);
        AtomicBoolean stop = new AtomicBoolean(false);
        ExecutorService writer = Executors.newSingleThreadExecutor();
        try {
            Future<?> writes = writer.submit(() -> {
                try {
                    for (int i = 0; i < 20_000 && !stop.get(); i++) {
                        tool.execute(i % 2 == 0 ? setAuth("api_key", "value-b", "X-Token-B") : setAuth("api_key", "value-a", "X-Token-A"));
                    }
                    return null;
                } finally {
                    writing.set(false);
                }
            });
            int exports = 0;
            while (writing.get()) {
                assertExportIsSelfConsistent("export " + exports++, structured(tool.execute(action("export_rules"))));
            }
            writes.get(60, TimeUnit.SECONDS);
        } finally {
            // The writer must be gone before tearDown resets the shared static state.
            stop.set(true);
            writer.shutdown();
            assertTrue("writer did not stop", writer.awaitTermination(30, TimeUnit.SECONDS));
        }
    }

    /** The exported headers must be exactly the header the exported auth settings describe. */
    private void assertExportIsSelfConsistent(String label, JsonNode export) {
        JsonNode settings = export.path("settings");
        assertTrue(label + ": no auth exported: " + export, settings.path("authType").isTextual());
        Map<String, String> expected = Map.of(settings.path("authHeader").asText(), settings.path("authValue").asText());
        assertEquals(label + ": exported headers and auth settings disagree", expected,
            mapper.convertValue(export.path("globalHeaders"), Map.class));
    }

    /** Runs the calls on separate threads, released together, and rethrows any failure. */
    private static void runTogether(List<Callable<JsonNode>> calls) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(calls.size());
        try {
            CyclicBarrier start = new CyclicBarrier(calls.size());
            List<Future<JsonNode>> pending = new ArrayList<>();
            for (Callable<JsonNode> call : calls) {
                pending.add(pool.submit(() -> {
                    start.await(10, TimeUnit.SECONDS);
                    return call.call();
                }));
            }
            for (Future<JsonNode> future : pending) future.get(30, TimeUnit.SECONDS);
        } finally {
            // Every caller must be gone before the next round or tearDown touches shared state.
            pool.shutdown();
            assertTrue("callers did not finish", pool.awaitTermination(30, TimeUnit.SECONDS));
        }
    }

    private JsonNode structured(Object response) {
        JsonNode node = mapper.valueToTree(response);
        assertFalse(node.toString(), node.path("isError").asBoolean());
        return node.path("structuredContent");
    }

    private ObjectNode action(String name) {
        ObjectNode args = mapper.createObjectNode();
        args.put("action", name);
        return args;
    }

    private ObjectNode setAuth(String type, String value, String headerName) {
        ObjectNode args = mapper.createObjectNode();
        args.put("action", "set_auth");
        args.put("auth_type", type);
        args.put("auth_value", value);
        if (headerName != null) args.put("header_name", headerName);
        return args;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, String> globalHeaders() throws Exception {
        Field f = GlobalInterceptorTool.class.getDeclaredField("globalHeaders");
        f.setAccessible(true);
        return (Map<String, String>) f.get(null);
    }
}
