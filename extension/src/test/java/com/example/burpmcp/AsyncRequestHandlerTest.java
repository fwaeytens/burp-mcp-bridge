package com.example.burpmcp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.lang.reflect.Proxy;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.*;

public class AsyncRequestHandlerTest {
    private final ObjectMapper mapper = new ObjectMapper();
    private final BurpMcpConfig config = BurpMcpConfig.getInstance();
    private final Map<String, McpTool> tools = new LinkedHashMap<>();
    private AsyncRequestHandler handler;
    private int oldTimeout;
    private int oldPoolSize;
    private int oldRateLimit;
    private boolean oldRateLimiting;
    private boolean oldAuditLogging;
    private Set<String> oldAllowedHosts;

    @Before
    public void setUp() {
        oldTimeout = config.getRequestTimeoutMs();
        oldPoolSize = config.getThreadPoolSize();
        oldRateLimit = config.getRateLimitRequestsPerMinute();
        oldRateLimiting = config.isEnableRateLimiting();
        oldAuditLogging = config.isEnableAuditLogging();
        oldAllowedHosts = config.getAllowedHosts();
        config.setThreadPoolSize(1);
        config.setRequestTimeoutMs(5000);
        config.setEnableRateLimiting(false);
        config.setEnableAuditLogging(false);
        config.setAllowedHosts(Set.of("127.0.0.1"));

        Logging logging = (Logging) Proxy.newProxyInstance(
            Logging.class.getClassLoader(), new Class<?>[]{Logging.class},
            (proxy, method, args) -> null);
        MontoyaApi api = (MontoyaApi) Proxy.newProxyInstance(
            MontoyaApi.class.getClassLoader(), new Class<?>[]{MontoyaApi.class},
            (proxy, method, args) -> method.getName().equals("logging") ? logging : null);
        handler = new AsyncRequestHandler(api, tools);
        tools.put("fast", tool(() -> McpUtils.createJsonResponse(Map.of("ok", true))));
    }

    @After
    public void tearDown() {
        try {
            handler.shutdown();
        } finally {
            config.setRequestTimeoutMs(oldTimeout);
            config.setThreadPoolSize(oldPoolSize);
            config.setRateLimitRequestsPerMinute(oldRateLimit);
            config.setEnableRateLimiting(oldRateLimiting);
            config.setEnableAuditLogging(oldAuditLogging);
            config.setAllowedHosts(oldAllowedHosts);
        }
    }

    @Test(timeout = 10000)
    public void timeoutInterruptsRunningToolAndReleasesSingleWorker() throws Exception {
        config.setRequestTimeoutMs(200);
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch interrupted = new CountDownLatch(1);
        tools.put("blocking", blockingTool(entered, interrupted));

        CompletableFuture<Object> result = execute("blocking");
        assertTrue(entered.await(2, TimeUnit.SECONDS));
        assertFailure(result, TimeoutException.class);
        assertTrue("Timed-out tool must be interrupted", interrupted.await(2, TimeUnit.SECONDS));
        assertFastCallWorks();
        assertEquals(0, handler.getStats().pendingRequests);
    }

    @Test(timeout = 10000)
    public void callerCancellationInterruptsRunningTool() throws Exception {
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch interrupted = new CountDownLatch(1);
        tools.put("blocking", blockingTool(entered, interrupted));

        CompletableFuture<Object> result = execute("blocking");
        assertTrue(entered.await(2, TimeUnit.SECONDS));
        assertTrue(result.cancel(true));
        assertTrue(interrupted.await(2, TimeUnit.SECONDS));
        assertFastCallWorks();
        assertEquals(0, handler.getStats().pendingRequests);
    }

    @Test(timeout = 10000)
    public void queuedRequestNeverExecutesAfterItsTimeout() throws Exception {
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicInteger queuedExecutions = new AtomicInteger();
        tools.put("blocking", tool(() -> {
            entered.countDown();
            release.await();
            return "released";
        }));
        tools.put("queued", tool(queuedExecutions::incrementAndGet));

        CompletableFuture<Object> running = execute("blocking");
        try {
            assertTrue(entered.await(2, TimeUnit.SECONDS));
            config.setRequestTimeoutMs(100);
            assertFailure(execute("queued"), TimeoutException.class);
        } finally {
            release.countDown();
        }
        assertEquals("released", running.get(2, TimeUnit.SECONDS));
        assertFastCallWorks();
        assertEquals(0, queuedExecutions.get());
    }

    @Test(timeout = 10000)
    public void shutdownInterruptsActiveWorkAndCompletesQueuedCalls() throws Exception {
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch interrupted = new CountDownLatch(1);
        AtomicInteger queuedExecutions = new AtomicInteger();
        tools.put("blocking", blockingTool(entered, interrupted));
        tools.put("queued", tool(queuedExecutions::incrementAndGet));

        CompletableFuture<Object> running = execute("blocking");
        assertTrue(entered.await(2, TimeUnit.SECONDS));
        CompletableFuture<Object> queued = execute("queued");
        handler.shutdown();

        assertTrue(interrupted.await(2, TimeUnit.SECONDS));
        assertTrue(running.isCancelled());
        assertTrue(queued.isCancelled());
        assertEquals(0, queuedExecutions.get());
        assertEquals(0, handler.getStats().pendingRequests);
        assertFailure(execute("fast"), java.util.concurrent.RejectedExecutionException.class);
        assertEquals(0, handler.getStats().pendingRequests);
    }

    @Test(timeout = 10000)
    public void workerFailureCompletesResultWithoutWaitingForTimeout() throws Exception {
        tools.put("failure", tool(() -> { throw new AssertionError("test failure"); }));
        assertFailure(execute("failure"), AssertionError.class);
        assertFastCallWorks();
    }

    @Test(timeout = 10000)
    public void shutdownRejectsRequestsSubmittedByCancellationCallbacks() throws Exception {
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch interrupted = new CountDownLatch(1);
        AtomicInteger executions = new AtomicInteger();
        tools.put("blocking", blockingTool(entered, interrupted));
        tools.put("counted", tool(executions::incrementAndGet));

        CompletableFuture<Object> running = execute("blocking");
        assertTrue(entered.await(2, TimeUnit.SECONDS));
        java.util.concurrent.atomic.AtomicReference<CompletableFuture<Object>> submittedDuringShutdown =
            new java.util.concurrent.atomic.AtomicReference<>();
        running.whenComplete((result, failure) -> submittedDuringShutdown.set(execute("counted")));

        handler.shutdown();

        assertNotNull(submittedDuringShutdown.get());
        assertFailure(submittedDuringShutdown.get(), java.util.concurrent.RejectedExecutionException.class);
        assertTrue(interrupted.await(2, TimeUnit.SECONDS));
        assertEquals(0, executions.get());
        assertEquals(0, handler.getStats().pendingRequests);
    }

    @Test(timeout = 10000)
    public void bothDispatchMethodsRejectDisallowedHostsBeforeExecutingTools() throws Exception {
        AtomicInteger executions = new AtomicInteger();
        tools.put("counted", tool(executions::incrementAndGet));
        JsonRpcDispatcher dispatcher = dispatcher(5000);

        for (String method : new String[]{"tools/call", "tools/call_sync"}) {
            JsonNode response = dispatcher.handle(method, request(method, "counted"), "192.0.2.1");
            assertTrue(response.path("result").path("isError").asBoolean());
            assertTrue(response.toString().contains("Host not allowed: 192.0.2.1"));
        }
        assertEquals(0, executions.get());
    }

    @Test(timeout = 10000)
    public void switchingDispatchMethodsDoesNotBypassRateLimit() throws Exception {
        config.setEnableRateLimiting(true);
        config.setRateLimitRequestsPerMinute(1);
        AtomicInteger executions = new AtomicInteger();
        tools.put("counted", tool(() -> McpUtils.createJsonResponse(Map.of("count", executions.incrementAndGet()))));
        JsonRpcDispatcher dispatcher = dispatcher(5000);

        JsonNode first = dispatcher.handle("tools/call_sync", request("tools/call_sync", "counted"), "127.0.0.1");
        assertEquals(1, first.path("result").path("structuredContent").path("count").asInt());
        for (String method : new String[]{"tools/call", "tools/call_sync"}) {
            JsonNode response = dispatcher.handle(method, request(method, "counted"), "127.0.0.1");
            assertTrue(response.path("result").path("isError").asBoolean());
            assertTrue(response.toString().contains("Rate limit exceeded"));
        }
        assertEquals(1, executions.get());
    }

    @Test(timeout = 10000)
    public void dispatcherDeadlineCancelsWorkBeforeExecutorDeadline() throws Exception {
        for (String method : new String[]{"tools/call", "tools/call_sync"}) {
            CountDownLatch entered = new CountDownLatch(1);
            CountDownLatch interrupted = new CountDownLatch(1);
            tools.put("blocking", blockingTool(entered, interrupted));

            JsonNode response = dispatcher(200).handle(method, request(method, "blocking"), "127.0.0.1");
            assertEquals(0, entered.getCount());
            assertTrue(response.path("error").path("message").asText().contains("timed out"));
            assertTrue(interrupted.await(2, TimeUnit.SECONDS));
            assertFastCallWorks();
        }
    }

    private CompletableFuture<Object> execute(String name) {
        return handler.executeAsync(name, mapper.createObjectNode(), "127.0.0.1");
    }

    private void assertFastCallWorks() throws Exception {
        JsonNode result = mapper.valueToTree(execute("fast").get(2, TimeUnit.SECONDS));
        assertTrue(result.path("structuredContent").path("ok").asBoolean());
    }

    private void assertFailure(CompletableFuture<Object> result, Class<? extends Throwable> type) throws Exception {
        try {
            result.get(2, TimeUnit.SECONDS);
            fail("Expected " + type.getSimpleName());
        } catch (ExecutionException e) {
            assertTrue("Unexpected failure: " + e.getCause(), type.isInstance(e.getCause()));
        }
    }

    private JsonRpcDispatcher dispatcher(int timeoutMs) {
        return new JsonRpcDispatcher(mapper, tools, handler, () -> timeoutMs,
            config::getServerPort, config::getConfigSummary, new ToolDocumentationExporter(tools));
    }

    private ObjectNode request(String method, String toolName) {
        ObjectNode request = mapper.createObjectNode().put("jsonrpc", "2.0").put("id", 1).put("method", method);
        request.putObject("params").put("name", toolName).putObject("arguments");
        return request;
    }

    private McpTool blockingTool(CountDownLatch entered, CountDownLatch interrupted) {
        return tool(() -> {
            entered.countDown();
            try {
                new CountDownLatch(1).await();
            } catch (InterruptedException e) {
                interrupted.countDown();
                throw e;
            }
            return null;
        });
    }

    private McpTool tool(Operation operation) {
        return new McpTool() {
            @Override
            public Map<String, Object> getToolInfo() {
                return Map.of("name", "test", "inputSchema", Map.of("type", "object"));
            }

            @Override
            public Object execute(JsonNode arguments) throws Exception {
                return operation.execute();
            }
        };
    }

    private interface Operation {
        Object execute() throws Exception;
    }
}
