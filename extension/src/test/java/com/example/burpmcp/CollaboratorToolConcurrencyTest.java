package com.example.burpmcp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.Collaborator;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.collaborator.SecretKey;
import burp.api.montoya.internal.MontoyaObjectFactory;
import burp.api.montoya.internal.ObjectFactoryLocator;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * RESTORE_CLIENT swaps the Collaborator client while other MCP workers may be using it.
 * Stub clients tag every payload and secret with their own name so a test can tell which
 * session an operation actually ran against.
 */
public class CollaboratorToolConcurrencyTest {
    @Rule public TemporaryFolder temporary = new TemporaryFolder();
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String INITIAL = "initial";

    private MontoyaObjectFactory originalFactory;
    private String originalHome;
    private Path home;
    private CollaboratorTool tool;

    /** Set by a test to pause the initial client's first payload generation. */
    private volatile CountDownLatch firstPayloadGenerated;
    private volatile CountDownLatch resumeGeneration;

    @Before
    public void setUp() throws Exception {
        originalFactory = ObjectFactoryLocator.FACTORY;
        ObjectFactoryLocator.FACTORY = stub(MontoyaObjectFactory.class, (proxy, method, args) ->
            method.getName().equals("secretKey") ? secret((String) args[0]) : defaultValue(method.getReturnType()));

        originalHome = System.getProperty("user.home");
        home = temporary.newFolder("collaborator-home").toPath();
        System.setProperty("user.home", home.toString());

        Collaborator collaborator = stub(Collaborator.class, (proxy, method, args) -> switch (method.getName()) {
            case "createClient" -> client(INITIAL);
            case "restoreClient" -> client(args[0].toString());
            default -> defaultValue(method.getReturnType());
        });
        MontoyaApi api = stub(MontoyaApi.class, (proxy, method, args) ->
            method.getName().equals("collaborator") ? collaborator : defaultValue(method.getReturnType()));
        tool = new CollaboratorTool(api);
    }

    @After
    public void tearDown() {
        System.setProperty("user.home", originalHome);
        ObjectFactoryLocator.FACTORY = originalFactory;
    }

    @Test
    public void restoreDuringPayloadGenerationDoesNotSplitTheBatchAcrossSessions() throws Exception {
        assertBatchStaysOnOneSession(Map.of("action", "GENERATE_PAYLOAD", "count", 4));
    }

    @Test
    public void restoreDuringCustomDataGenerationDoesNotSplitTheBatchAcrossSessions() throws Exception {
        assertBatchStaysOnOneSession(Map.of("action", "GENERATE_WITH_CUSTOM_DATA", "customData", "tag", "count", 4));
    }

    /**
     * Forces the interleaving: generation pauses after its first payload, another worker
     * restores a different client, generation resumes.
     */
    private void assertBatchStaysOnOneSession(Map<String, Object> generate) throws Exception {
        firstPayloadGenerated = new CountDownLatch(1);
        resumeGeneration = new CountDownLatch(1);
        ExecutorService worker = Executors.newSingleThreadExecutor();
        try {
            Future<JsonNode> batch = worker.submit(() -> call(generate));
            assertTrue("generation never started", firstPayloadGenerated.await(10, TimeUnit.SECONDS));

            call(Map.of("action", "RESTORE_CLIENT", "secretKey", "restored"));
            resumeGeneration.countDown();

            JsonNode payloads = batch.get(10, TimeUnit.SECONDS).path("payloads");
            assertEquals(4, payloads.size());
            for (JsonNode payload : payloads) {
                String value = payload.path("payload").asText();
                assertTrue("batch mixed Collaborator sessions: " + payloads, value.startsWith(INITIAL + "-"));
            }
            assertEquals("restored", call(Map.of("action", "GET_SECRET_KEY")).path("secretKey").asText());
        } finally {
            resumeGeneration.countDown();
            worker.shutdownNow();
        }
    }

    /**
     * Stress check, not a forced interleaving: after competing restores the client the tool
     * holds and the secret persisted for the next reload must be the same session.
     */
    @Test
    public void competingRestoresLeaveMemoryAndPersistedSecretInAgreement() throws Exception {
        final int threads = 8;
        final int rounds = 200;
        Path secretFile = home.resolve(".config").resolve("burp-mcp-bridge").resolve("collaborator-secret");
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        try {
            for (int round = 0; round < rounds; round++) {
                CyclicBarrier start = new CyclicBarrier(threads);
                List<Future<JsonNode>> restores = new ArrayList<>();
                for (int t = 0; t < threads; t++) {
                    String secretKey = "round" + round + "thread" + t;
                    restores.add(pool.submit(() -> {
                        start.await(10, TimeUnit.SECONDS);
                        return call(Map.of("action", "RESTORE_CLIENT", "secretKey", secretKey));
                    }));
                }
                for (Future<JsonNode> restore : restores) restore.get(10, TimeUnit.SECONDS);

                String inMemory = call(Map.of("action", "GET_SECRET_KEY")).path("secretKey").asText();
                String persisted = Files.readString(secretFile).trim();
                assertEquals("round " + round + ": persisted secret differs from the active client", inMemory, persisted);
            }
        } finally {
            pool.shutdownNow();
        }
    }

    private JsonNode call(Map<String, Object> arguments) throws Exception {
        JsonNode response = JSON.valueToTree(tool.execute(JSON.valueToTree(arguments)));
        assertFalse(arguments + " -> " + response, response.path("isError").asBoolean());
        JsonNode data = response.path("structuredContent");
        assertTrue(arguments + " produced no structured result: " + response, data.isObject());
        return data;
    }

    private CollaboratorClient client(String name) {
        AtomicInteger generated = new AtomicInteger();
        return stub(CollaboratorClient.class, (proxy, method, args) -> switch (method.getName()) {
            case "getSecretKey" -> secret(name);
            case "generatePayload" -> {
                int number = generated.incrementAndGet();
                CountDownLatch started = firstPayloadGenerated;
                if (name.equals(INITIAL) && number == 1 && started != null) {
                    started.countDown();
                    resumeGeneration.await(10, TimeUnit.SECONDS);
                }
                yield payload(name + "-" + number);
            }
            case "getAllInteractions", "getInteractions" -> List.of();
            default -> defaultValue(method.getReturnType());
        });
    }

    private static CollaboratorPayload payload(String label) {
        return stub(CollaboratorPayload.class, (proxy, method, args) -> switch (method.getName()) {
            case "toString" -> label + ".collaborator.test";
            case "server" -> Optional.empty();
            default -> defaultValue(method.getReturnType());
        });
    }

    private static SecretKey secret(String value) {
        return stub(SecretKey.class, (proxy, method, args) ->
            method.getName().equals("toString") ? value : defaultValue(method.getReturnType()));
    }

    private static Object defaultValue(Class<?> type) {
        if (type == void.class) return null;
        if (type == boolean.class) return false;
        if (type == int.class) return 0;
        if (type == long.class) return 0L;
        if (type == String.class) return "";
        if (type == Optional.class) return Optional.empty();
        if (type == List.class) return List.of();
        if (type.isInterface()) {
            return stub(type, (proxy, method, args) ->
                method.getName().equals("toString") ? type.getSimpleName() : defaultValue(method.getReturnType()));
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private static <T> T stub(Class<T> type, InvocationHandler handler) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, handler);
    }
}
