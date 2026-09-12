package com.example.burpmcp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.burpsuite.BurpSuite;
import burp.api.montoya.core.BurpSuiteEdition;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.After;
import org.junit.Test;

import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

import static org.junit.Assert.*;

public class HttpJobsToolTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private final FakeEngine engine = new FakeEngine();
    private final AtomicLong now = new AtomicLong(1000);
    private final AtomicInteger preparations = new AtomicInteger();
    private HttpJobsTool tool = tool(new HttpJobsTool.Limits(4, 20, 50, 10 * 1024 * 1024, 16 * 1024, 3_600_000));

    @After
    public void close() {
        tool.close();
    }

    @Test
    public void startReturnsImmediatelyAndResultsStayInInputOrder() throws Exception {
        String id = start(3);
        assertEquals("running", call("STATUS", id).path("state").asText());
        FakeExecution run = engine.runs.get(0);
        run.emit(2, "RESPONDED", "HTTP/1.1 404 Not Found\r\n\r\nmissing");
        run.emit(0, "TIMED_OUT", null);

        JsonNode rows = call("RESULTS", id).path("results");
        assertEquals(0, rows.get(0).path("index").asInt());
        assertEquals("TIMED_OUT", rows.get(0).path("status").asText());
        assertEquals("PENDING", rows.get(1).path("status").asText());
        assertEquals(404, rows.get(2).path("status_code").asInt());
        assertFalse(rows.get(2).has("response_base64"));

        run.emit(1, "CONNECTION_FAILED", null);
        run.complete(false);
        JsonNode status = call("STATUS", id);
        assertEquals("completed", status.path("state").asText());
        assertEquals(1, status.path("progress").path("completed").asInt());
        assertEquals(2, status.path("progress").path("failed").asInt());
    }

    @Test
    public void pauseResumeAndCancelKeepInFlightWorkAndPartialResults() throws Exception {
        String id = start(3);
        FakeExecution run = engine.runs.get(0);
        assertEquals("paused", call("PAUSE", id).path("state").asText());
        assertTrue(run.paused);
        assertEquals("running", call("RESUME", id).path("state").asText());
        assertFalse(run.paused);
        assertEquals("cancelling", call("CANCEL", id).path("state").asText());
        assertTrue(run.cancelled);
        assertError(Map.of("action", "RESUME", "job_id", id), "cancelling");
        run.emit(1, "RESPONDED", "HTTP/1.1 200 OK\r\n\r\nfinished in flight");
        run.emit(0, "DROPPED", null);
        run.emit(2, "DROPPED", null);
        run.complete(true);
        assertEquals("cancelled", call("STATUS", id).path("state").asText());
        assertEquals("DROPPED", call("RESULTS", id).path("results").get(0).path("status").asText());
        assertEquals("RESPONDED", call("RESULTS", id).path("results").get(1).path("status").asText());
        assertEquals("cancelled", call("CANCEL", id).path("state").asText());
    }

    @Test
    public void dashboardCancellationIsReflectedOnCompletion() throws Exception {
        String id = start(1);
        engine.runs.get(0).emit(0, "DROPPED", null);
        engine.runs.get(0).complete(true);
        assertEquals("cancelled", call("STATUS", id).path("state").asText());
    }

    @Test
    public void boundsPreviewsAndRetainedBytesWithoutLosingOutcomeSummaries() throws Exception {
        tool.close();
        tool = tool(new HttpJobsTool.Limits(4, 20, 50, 10, 8, 1000));
        String id = start(3);
        FakeExecution run = engine.runs.get(0);
        for (int i = 0; i < 3; i++) run.emit(i, "RESPONDED", "HTTP/1.1 200 OK\r\n\r\nbody");
        // A duplicate callback must not count or store a second preview.
        run.emit(0, "RESPONDED", "HTTP/1.1 200 OK\r\n\r\nbody");
        JsonNode result = call(Map.of("action", "RESULTS", "job_id", id, "include_response", true));
        assertEquals(10, result.path("retained_response_bytes").asInt());
        assertEquals(3, result.path("truncated_results").asInt());
        JsonNode rows = result.path("results");
        assertEquals(8, rows.get(0).path("preview_bytes").asInt());
        assertEquals(2, rows.get(1).path("preview_bytes").asInt());
        assertEquals(0, rows.get(2).path("preview_bytes").asInt());
        assertTrue(rows.get(2).path("response_truncated").asBoolean());
        assertEquals(200, rows.get(2).path("status_code").asInt());
        assertEquals("HTTP/1.1", new String(java.util.Base64.getDecoder().decode(rows.get(0).path("response_base64").asText()), StandardCharsets.ISO_8859_1));
    }

    @Test
    public void paginatedPreviewsFitTheActualBridgeLimitAndCoverEveryIndex() throws Exception {
        String id = start(10);
        for (int i = 0; i < 10; i++) engine.runs.get(0).emit(i, "RESPONDED", "HTTP/1.1 200 OK\r\n\r\n" + "x".repeat(20_000));
        int offset = 0;
        int seen = 0;
        while (offset < 10) {
            Object result = tool.execute(JSON.valueToTree(Map.of("action", "RESULTS", "job_id", id,
                "offset", offset, "limit", 100, "include_response", true)));
            assertTrue(JSON.writeValueAsString(result).length() < 95_000);
            JsonNode data = JSON.valueToTree(result).path("structuredContent");
            assertTrue(data.path("returned").asInt() > 0);
            for (JsonNode row : data.path("results")) assertEquals(seen++, row.path("index").asInt());
            if (data.path("next_offset").isNull()) break;
            int next = data.path("next_offset").asInt();
            assertTrue(next > offset);
            offset = next;
        }
        assertEquals(10, seen);
        assertTrue(call(Map.of("action", "RESULTS", "job_id", id, "offset", 10)).path("results").isEmpty());
    }

    @Test
    public void rejectsUnsupportedOptionsAndInvalidLimitsBeforePreparingOrSending() throws Exception {
        for (Map<String, Object> args : List.<Map<String, Object>>of(
            Map.of("action", "START", "requests", List.of("https://example.test/"), "route_via_proxy", false),
            Map.of("action", "START", "requests", List.of("https://example.test/"), "http_mode", "AUTO"),
            Map.of("action", "START", "requests", List.of("https://example.test/"), "max_concurrency", 0),
            Map.of("action", "START", "requests", List.of("https://example.test/"), "response_timeout", 0),
            Map.of("action", "START", "requests", List.of("https://example.test/"), "response_timeout", 1.5),
            Map.of("action", "START", "requests", List.of("https://example.test/"), "max_retries", 4))) {
            assertError(args, "invalid_arguments");
        }
        assertEquals(0, preparations.get());
        assertTrue(engine.runs.isEmpty());
    }

    @Test
    public void validationFailureInPreparationSubmitsNothing() throws Exception {
        tool.close();
        tool = new HttpJobsTool(engine, args -> { throw new IllegalArgumentException("Malformed second request"); }, now::get,
            new HttpJobsTool.Limits(4, 20, 50, 1000, 100, 1000));
        assertError(Map.of("action", "START", "requests", List.of("valid", "invalid")), "invalid_arguments");
        assertTrue(engine.runs.isEmpty());
        assertTrue(call(Map.of("action", "LIST")).path("jobs").isEmpty());
    }

    @Test
    public void boundsAggregateConcurrencyUntilCancellationActuallyCompletes() throws Exception {
        String id = call(Map.of("action", "START", "requests", List.of("https://example.test/"), "max_concurrency", 45)).path("job_id").asText();
        assertError(Map.of("action", "START", "requests", List.of("https://example.test/")), "capacity");
        call("CANCEL", id);
        assertError(Map.of("action", "START", "requests", List.of("https://example.test/")), "capacity");
        engine.runs.get(0).emit(0, "DROPPED", null);
        engine.runs.get(0).complete(true);
        assertFalse(start(1).isBlank());
    }

    @Test
    public void simultaneousStartsRespectActiveJobLimit() throws Exception {
        var pool = Executors.newFixedThreadPool(8);
        CountDownLatch go = new CountDownLatch(1);
        try {
            var futures = new ArrayList<java.util.concurrent.Future<Boolean>>();
            for (int i = 0; i < 8; i++) futures.add(pool.submit(() -> {
                go.await();
                JsonNode response = JSON.valueToTree(tool.execute(JSON.valueToTree(Map.of("action", "START", "requests", List.of("https://example.test/"), "max_concurrency", 1))));
                return !response.path("isError").asBoolean();
            }));
            go.countDown();
            int accepted = 0;
            for (var future : futures) if (future.get(5, TimeUnit.SECONDS)) accepted++;
            assertEquals(4, accepted);
            assertEquals(4, engine.runs.size());
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    public void completedJobsExpireAndOldestCompletedJobIsEvictedAtCapacity() throws Exception {
        tool.close();
        tool = tool(new HttpJobsTool.Limits(4, 2, 50, 1000, 100, 100));
        String first = start(1);
        engine.runs.get(0).emit(0, "RESPONDED", "HTTP/1.1 200 OK\r\n\r\n");
        engine.runs.get(0).complete(false);
        now.addAndGet(10);
        String second = start(1);
        engine.runs.get(1).emit(0, "DROPPED", null);
        engine.runs.get(1).complete(true);
        String active = start(1);
        assertError(Map.of("action", "STATUS", "job_id", first), "unknown_job");
        assertEquals("cancelled", call("STATUS", second).path("state").asText());
        now.addAndGet(100);
        assertError(Map.of("action", "STATUS", "job_id", second), "unknown_job");
        assertEquals("running", call("STATUS", active).path("state").asText());
        assertEquals(1, call(Map.of("action", "LIST")).path("jobs").size());
    }

    @Test
    public void synchronousCompletionIsNotOverwrittenByStartReturn() throws Exception {
        engine.completeInline = true;
        String id = start(1);
        assertEquals("completed", call("STATUS", id).path("state").asText());
        assertEquals("RESPONDED", call("RESULTS", id).path("results").get(0).path("status").asText());
        tool.close();
        assertFalse(engine.runs.get(0).cancelled);
    }

    @Test
    public void submissionFailureRetainsInspectableJobWithoutAutomaticRetry() throws Exception {
        engine.failStart = true;
        Object result = tool.execute(JSON.valueToTree(Map.of("action", "START", "requests", List.of("https://example.test/"))));
        JsonNode response = JSON.valueToTree(result);
        assertTrue(response.path("isError").asBoolean());
        JsonNode data = response.path("structuredContent");
        assertEquals("start_failed", data.path("error").asText());
        assertEquals("failed", call("STATUS", data.path("job_id").asText()).path("state").asText());
        assertEquals(1, engine.runs.size());
    }

    @Test
    public void postSubmissionFailureKeepsCapacityUntilNativeStatsConfirmDrain() throws Exception {
        engine.failSubmission = true;
        JsonNode response = JSON.valueToTree(tool.execute(JSON.valueToTree(Map.of("action", "START",
            "requests", List.of("https://example.test/"), "max_concurrency", 45))));
        assertTrue(response.path("isError").asBoolean());
        JsonNode data = response.path("structuredContent");
        String id = data.path("job_id").asText();
        assertEquals("submission_failed", data.path("error").asText());
        assertEquals("cancelling", data.path("state").asText());
        engine.failSubmission = false;
        assertError(Map.of("action", "START", "requests", List.of("https://example.test/")), "capacity");
        // Completion registration failed, so only polled native statistics report drain.
        engine.runs.get(0).failed = 1;
        assertEquals("failed", call("STATUS", id).path("state").asText());
        assertTrue(engine.runs.get(0).detached);
        assertEquals("UNKNOWN", call("RESULTS", id).path("results").get(0).path("status").asText());
        assertFalse(start(1).isBlank());
    }

    @Test
    public void uncertainSubmissionWithoutHandleCannotReleaseCapacityOrBeResent() throws Exception {
        engine.failSubmission = true;
        engine.missingHandle = true;
        JsonNode response = JSON.valueToTree(tool.execute(JSON.valueToTree(Map.of("action", "START",
            "requests", List.of("https://example.test/"), "max_concurrency", 45))));
        JsonNode data = response.path("structuredContent");
        assertEquals("submission_uncertain", data.path("state").asText());
        assertError(Map.of("action", "CANCEL", "job_id", data.path("job_id").asText()), "submission_uncertain");
        engine.failSubmission = false;
        now.addAndGet(10_000_000);
        assertError(Map.of("action", "START", "requests", List.of("https://example.test/")), "capacity");
        assertEquals(1, engine.runs.size());
    }

    @Test
    public void unloadCancelsEveryActiveRunAndIgnoresLateCallbacks() throws Exception {
        start(1);
        start(1);
        tool.close();
        tool.close();
        for (FakeExecution run : engine.runs) {
            assertTrue(run.cancelled);
            assertTrue(run.detached);
            run.emit(0, "RESPONDED", "HTTP/1.1 200 OK\r\n\r\nlate");
            run.complete(true);
        }
        assertError(Map.of("action", "LIST"), "closed");
        assertError(Map.of("action", "START", "requests", List.of("https://example.test/")), "closed");
        assertEquals(2, engine.runs.size());
    }

    @Test
    public void unavailableRuntimeStillOffersDiscoveryAndStructuredErrors() throws Exception {
        tool.close();
        tool = new HttpJobsTool(null);
        assertEquals("burp_http_jobs", tool.getToolInfo().get("name"));
        assertFalse(call(Map.of("action", "LIST")).path("available").asBoolean());
        assertError(Map.of("action", "START", "requests", List.of("https://example.test/")), "unavailable");
    }

    @Test
    public void failedAvailabilityLookupRecoversAndCachesOnlySuccess() throws Exception {
        AtomicInteger probes = new AtomicInteger();
        tool.close();
        tool = new HttpJobsTool(apiWithInitialLookupFailure(probes,
            () -> { throw new IllegalStateException("Burp is initializing"); }));

        JsonNode first = call(Map.of("action", "LIST"));
        assertFalse(first.path("available").asBoolean());
        assertEquals("Burp is initializing", first.path("unavailable_reason").asText());
        JsonNode recovered = call(Map.of("action", "LIST"));
        assertTrue(recovered.path("available").asBoolean());
        assertFalse(recovered.has("unavailable_reason"));
        assertTrue(call(Map.of("action", "LIST")).path("available").asBoolean());
        assertEquals(2, probes.get());
    }

    @Test
    public void failedStartLookupCanRetryWithoutReservingAJob() throws Exception {
        AtomicInteger probes = new AtomicInteger();
        tool.close();
        tool = new HttpJobsTool(apiWithInitialLookupFailure(probes,
            () -> { throw new UnsupportedOperationException("Engine temporarily unavailable"); }));

        assertError(Map.of("action", "START", "requests", List.of("https://example.test/")), "unavailable");
        // Reaching request validation proves START retried discovery. No request
        // factories or network activity are needed for this recovery check.
        assertError(Map.of("action", "START", "requests", List.of("https:///missing-host")), "invalid_arguments");
        JsonNode listing = call(Map.of("action", "LIST"));
        assertTrue(listing.path("available").asBoolean());
        assertEquals(0, listing.path("jobs").size());
        assertEquals(2, probes.get());
    }

    @Test
    public void linkageFailureDoesNotPermanentlyDisableDiscovery() throws Exception {
        AtomicInteger probes = new AtomicInteger();
        tool.close();
        tool = new HttpJobsTool(apiWithInitialLookupFailure(probes,
            () -> { throw new NoClassDefFoundError("temporary lookup failure"); }));

        assertFalse(call(Map.of("action", "LIST")).path("available").asBoolean());
        assertTrue(call(Map.of("action", "LIST")).path("available").asBoolean());
        assertEquals(2, probes.get());
    }

    private static MontoyaApi apiWithInitialLookupFailure(AtomicInteger probes, Runnable failOnce) {
        burp.api.montoya.core.Version version = proxy(burp.api.montoya.core.Version.class,
            (method, args) -> "edition".equals(method) ? BurpSuiteEdition.PROFESSIONAL : null);
        BurpSuite suite = proxy(BurpSuite.class, (method, args) -> "version".equals(method) ? version : null);
        return proxy(MontoyaApi.class, (method, args) -> {
            if (!"burpSuite".equals(method)) throw new AssertionError("Unexpected API access: " + method);
            if (probes.getAndIncrement() == 0) failOnce.run();
            return suite;
        });
    }

    private HttpJobsTool tool(HttpJobsTool.Limits limits) {
        return new HttpJobsTool(engine, args -> {
            preparations.incrementAndGet();
            List<HttpRequest> requests = new ArrayList<>();
            for (JsonNode url : args.path("requests")) requests.add(request(url.asText()));
            return requests;
        }, now::get, limits);
    }

    private String start(int count) throws Exception {
        List<String> urls = new ArrayList<>();
        for (int i = 0; i < count; i++) urls.add("https://example.test/" + i);
        return call(Map.of("action", "START", "requests", urls)).path("job_id").asText();
    }

    private JsonNode call(String action, String id) throws Exception {
        return call(Map.of("action", action, "job_id", id));
    }

    private JsonNode call(Map<String, Object> args) throws Exception {
        JsonNode result = JSON.valueToTree(tool.execute(JSON.valueToTree(args)));
        assertFalse(result.toString(), result.path("isError").asBoolean());
        return result.path("structuredContent");
    }

    private void assertError(Map<String, Object> args, String error) throws Exception {
        JsonNode result = JSON.valueToTree(tool.execute(JSON.valueToTree(args)));
        assertTrue(result.toString(), result.path("isError").asBoolean());
        assertEquals(error, result.path("structuredContent").path("error").asText());
    }

    private static HttpRequest request(String url) {
        return proxy(HttpRequest.class, (method, args) -> switch (method) {
            case "url" -> url;
            default -> null;
        });
    }

    private static HttpRequestResponse exchange(String raw) {
        if (raw == null) return null;
        byte[] bytes = raw.getBytes(StandardCharsets.ISO_8859_1);
        HttpResponse response = proxy(HttpResponse.class, (method, args) -> switch (method) {
            case "statusCode" -> Short.parseShort(raw.split(" ")[1]);
            case "toByteArray" -> bytes(bytes);
            case "bodyOffset" -> raw.indexOf("\r\n\r\n") + 4;
            default -> null;
        });
        return proxy(HttpRequestResponse.class, (method, args) -> "response".equals(method) ? response : null);
    }

    private static ByteArray bytes(byte[] bytes) {
        return proxy(ByteArray.class, (method, args) -> switch (method) {
            case "length" -> bytes.length;
            case "getBytes" -> bytes.clone();
            case "subArray" -> bytes(Arrays.copyOfRange(bytes, (Integer) args[0], (Integer) args[1]));
            default -> null;
        });
    }

    @SuppressWarnings("unchecked")
    private static <T> T proxy(Class<T> type, java.util.function.BiFunction<String, Object[], Object> invoke) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, (p, method, args) -> invoke.apply(method.getName(), args));
    }

    private static final class FakeEngine implements HttpJobEngine {
        final List<FakeExecution> runs = new ArrayList<>();
        boolean completeInline;
        boolean failStart;
        boolean failSubmission;
        boolean missingHandle;

        @Override
        public Execution start(List<HttpRequest> requests, Options options, Consumer<Result> onResult, Consumer<Completion> onComplete) {
            FakeExecution run = new FakeExecution(requests.size(), onResult, onComplete);
            runs.add(run);
            if (failStart) throw new IllegalStateException("test submission failure");
            if (failSubmission) throw new HttpJobEngine.SubmissionException(missingHandle ? null : run, new IllegalStateException("native submission failure"));
            if (completeInline) {
                for (int i = 0; i < requests.size(); i++) run.emit(i, "RESPONDED", "HTTP/1.1 200 OK\r\n\r\n");
                run.complete(false);
            }
            return run;
        }
    }

    private static final class FakeExecution implements HttpJobEngine.Execution {
        final int count;
        final Consumer<HttpJobEngine.Result> onResult;
        final Consumer<HttpJobEngine.Completion> onComplete;
        boolean paused;
        boolean cancelled;
        boolean detached;
        int responded;
        int failed;

        FakeExecution(int count, Consumer<HttpJobEngine.Result> onResult, Consumer<HttpJobEngine.Completion> onComplete) {
            this.count = count;
            this.onResult = onResult;
            this.onComplete = onComplete;
        }

        void emit(int index, String status, String raw) {
            if ("RESPONDED".equals(status)) responded++; else failed++;
            onResult.accept(new HttpJobEngine.Result(index, status, exchange(raw)));
        }

        void complete(boolean cancelled) {
            onComplete.accept(new HttpJobEngine.Completion(cancelled, stats()));
        }

        @Override public void pause() { paused = true; }
        @Override public void resume() { paused = false; }
        @Override public void cancel() { cancelled = true; }
        @Override public void detach() { detached = true; }
        @Override public HttpJobEngine.Stats stats() { return new HttpJobEngine.Stats(count, responded, failed, 0, count - responded - failed, 100); }
    }
}
