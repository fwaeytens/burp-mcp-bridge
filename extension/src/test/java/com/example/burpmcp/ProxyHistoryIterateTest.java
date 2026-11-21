package com.example.burpmcp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.proxy.Proxy;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.Before;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.function.BiFunction;

import static org.junit.Assert.*;

/**
 * burp_proxy_history iterate addresses entries by Burp's history number (the #
 * column), like list and detail, and walks newest first unless recent=false.
 * The history here has gaps (#2 and #4-6 were deleted), which is exactly where
 * a list position and Burp's # disagree.
 */
public class ProxyHistoryIterateTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private final List<ProxyHttpRequestResponse> history = new ArrayList<>();
    private ProxyHistoryTool tool;

    @Before
    public void setUp() {
        for (int id : new int[] {1, 3, 7}) history.add(entry(id, "https://example.test/e" + id));
        MontoyaApi api = proxy(MontoyaApi.class, (method, args) -> switch (method) {
            case "proxy" -> proxy(Proxy.class, (name, values) -> history);
            case "logging" -> proxy(Logging.class, (name, values) -> null);
            default -> throw new AssertionError("Unexpected API operation: " + method);
        });
        tool = new ProxyHistoryTool(api);
    }

    @Test
    public void defaultWalksBackwardsFromNewest() throws Exception {
        JsonNode data = iterate();
        assertEquals(List.of(7), ids(data));
        assertEquals(3, data.path("navigation").path("nextStartAt").asInt());
        assertFalse(data.path("navigation").has("previousStartAt"));
        assertEquals(List.of(7, 3, 1), ids(iterate("count", 3)));
    }

    @Test
    public void startAtIsBurpNumberAndEntriesReportIt() throws Exception {
        JsonNode data = iterate("startAt", 3, "count", 2);
        assertEquals(List.of(3, 1), ids(data));
        assertEquals("https://example.test/e3", data.path("entries").get(0).path("url").asText());
        assertEquals(1, data.path("endAt").asInt());
        assertFalse("nothing older than #1", data.path("navigation").has("nextStartAt"));
        assertEquals(7, data.path("navigation").path("previousStartAt").asInt());
    }

    @Test
    public void recentFalseWalksForwardFromStartAt() throws Exception {
        JsonNode data = iterate("startAt", 3, "count", 2, "recent", false);
        assertEquals(List.of(3, 7), ids(data));
        assertFalse("nothing newer than #7", data.path("navigation").has("nextStartAt"));
        assertEquals(1, data.path("navigation").path("previousStartAt").asInt());

        JsonNode oldest = iterate("recent", false);
        assertEquals(List.of(1), ids(oldest));
        assertEquals(3, oldest.path("navigation").path("nextStartAt").asInt());
    }

    @Test
    public void deletedStartAtContinuesInTheWalkDirection() throws Exception {
        assertEquals(List.of(1), ids(iterate("startAt", 2)));
        assertEquals(List.of(3), ids(iterate("startAt", 5)));
        assertEquals(List.of(3), ids(iterate("startAt", 2, "recent", false)));
        assertEquals(List.of(7), ids(iterate("startAt", 4, "recent", false)));
    }

    @Test
    public void startAtBeyondEitherEndReturnsNothing() throws Exception {
        JsonNode pastNewest = iterate("startAt", 8, "recent", false);
        assertEquals(List.of(), ids(pastNewest));
        assertFalse(pastNewest.has("endAt"));
        assertEquals(7, pastNewest.path("navigation").path("previousStartAt").asInt());

        JsonNode beforeOldest = iterate("startAt", 0);
        assertEquals(List.of(), ids(beforeOldest));
        assertEquals(1, beforeOldest.path("navigation").path("previousStartAt").asInt());
    }

    private JsonNode iterate(Object... fields) throws Exception {
        ObjectNode args = JSON.createObjectNode().put("action", "iterate");
        for (int i = 0; i < fields.length; i += 2) args.set((String) fields[i], JSON.valueToTree(fields[i + 1]));
        JsonNode result = JSON.valueToTree(tool.execute(args));
        assertFalse(result.toString(), result.path("isError").asBoolean());
        return result.path("structuredContent");
    }

    private static List<Integer> ids(JsonNode data) {
        List<Integer> ids = new ArrayList<>();
        data.path("entries").forEach(e -> ids.add(e.path("id").asInt()));
        return ids;
    }

    private static ProxyHttpRequestResponse entry(int id, String url) {
        String raw = "GET /e" + id + " HTTP/1.1\r\nHost: example.test\r\n\r\n";
        HttpRequest request = proxy(HttpRequest.class, (method, args) -> switch (method) {
            case "url" -> url;
            case "method" -> "GET";
            case "toString" -> raw;
            default -> null;
        });
        return proxy(ProxyHttpRequestResponse.class, (method, args) -> switch (method) {
            case "id" -> id;
            case "finalRequest", "request" -> request;
            case "hasResponse" -> false;
            default -> null;
        });
    }

    @SuppressWarnings("unchecked")
    private static <T> T proxy(Class<T> type, BiFunction<String, Object[], Object> handler) {
        return (T) java.lang.reflect.Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] {type},
            (proxy, method, args) -> handler.apply(method.getName(), args));
    }
}
