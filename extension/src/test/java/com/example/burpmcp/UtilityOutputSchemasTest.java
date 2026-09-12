package com.example.burpmcp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.*;
import burp.api.montoya.core.*;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.*;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.internal.MontoyaObjectFactory;
import burp.api.montoya.internal.ObjectFactoryLocator;
import burp.api.montoya.organizer.OrganizerItem;
import burp.api.montoya.organizer.OrganizerItemFilter;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.ZonedDateTime;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.*;

/** Executes real compact result paths against a local Montoya double; no live Burp calls. */
public class UtilityOutputSchemasTest {
    @Rule public TemporaryFolder temporary = new TemporaryFolder();
    private static final ObjectMapper JSON = new ObjectMapper();
    private MontoyaObjectFactory originalFactory;
    private MontoyaApi api;
    private final List<McpTool> owned = new ArrayList<>();
    private final Set<String> scope = new HashSet<>();
    private final AtomicInteger uiSends = new AtomicInteger();
    private final AtomicInteger issueAdds = new AtomicInteger();
    private final AtomicInteger httpSends = new AtomicInteger();
    private final AtomicInteger payloadIds = new AtomicInteger();
    private String importedConfig;
    private String annotationNotes = "existing note";
    private HighlightColor annotationColor;
    private HttpRequest sampleRequest;
    private HttpResponse sampleResponse;
    private HttpRequestResponse sampleExchange;
    private ProxyHttpRequestResponse sampleHistory;
    private List<OrganizerItem> organizerItems;
    private List<Cookie> cookies;

    @Before
    public void setUp() {
        originalFactory = ObjectFactoryLocator.FACTORY;
        ObjectFactoryLocator.FACTORY = stub(MontoyaObjectFactory.class, this::factory);
        sampleRequest = request("https://example.test/item", "GET", "");
        sampleResponse = response();
        sampleExchange = exchange(sampleRequest, sampleResponse);
        sampleHistory = stub(ProxyHttpRequestResponse.class, (p, m, a) -> switch (m.getName()) {
            case "finalRequest", "request" -> sampleRequest;
            case "response" -> sampleResponse;
            case "annotations" -> annotations();
            default -> defaultValue(m.getReturnType());
        });
        organizerItems = List.of(organizerItem(7, true), organizerItem(8, false));
        cookies = List.of(cookie("session", "abc", null));
        api = generic(MontoyaApi.class);
    }

    @After
    public void tearDown() throws Exception {
        try {
            for (McpTool tool : owned) tool.close();
        } finally {
            ObjectFactoryLocator.FACTORY = originalFactory;
        }
    }

    @Test
    public void repeaterAndIntruderReturnUiCreationResultsWithoutNetworkRequests() throws Exception {
        RepeaterTool repeater = keep(new RepeaterTool(api));
        JsonNode first = call(repeater, Map.of("action", "SEND_TO_REPEATER", "url", "https://example.test/item", "method", "POST", "body", "a=1"));
        JsonNode second = call(repeater, Map.of("action", "SEND_TO_REPEATER", "url", "https://example.test/item"));
        assertNotEquals(first.path("tabName"), second.path("tabName"));
        assertEquals(3, first.path("bodyLength").asInt());
        call(repeater, Map.of("action", "SEND_FROM_PROXY", "proxyUrl", "https://example.test/item"));
        IntruderTool intruder = keep(new IntruderTool(api));
        call(intruder, Map.of("action", "SEND_TO_INTRUDER", "url", "https://example.test/item", "method", "POST", "body", "a=1"));
        JsonNode positions = call(intruder, Map.of("action", "SEND_WITH_POSITIONS", "url", "https://example.test/item", "method", "POST", "body", "a=§1§"));
        assertEquals(1, positions.path("positionsFound").asInt());
        assertEquals(5, uiSends.get());
        assertEquals(0, httpSends.get());
        assertFalse(JSON.valueToTree(repeater.getToolInfo()).path("annotations").path("idempotentHint").asBoolean());
        assertFalse(JSON.valueToTree(intruder.getToolInfo()).path("annotations").path("idempotentHint").asBoolean());
    }

    @Test
    public void addingAnIssueExposesTheActualNormalizedSuccessFields() throws Exception {
        AddIssueTool tool = keep(new AddIssueTool(api));
        JsonNode result = call(tool, Map.of("issueType", "SQL injection", "url", "https://example.test/item", "detail", "Observed database error", "severity", "HIGH", "confidence", "CERTAIN"));
        assertEquals(1, issueAdds.get());
        assertEquals("SQL injection", result.path("issue_type").asText());
        assertEquals("HIGH", result.path("severity").asText());
        assertTrue(result.path("message").asText().contains("Successfully added issue"));
    }

    @Test
    public void sessionStateCookiesAndNetworkChecksMatchTheirDistinctResultShapes() throws Exception {
        SessionManagementTool tool = keep(new SessionManagementTool(api));
        call(tool, Map.of("action", "SET_TOKEN", "tokenName", "session", "tokenValue", "value"));
        JsonNode listed = call(tool, Map.of("action", "LIST_TOKENS"));
        assertTrue(listed.path("sessionUrls").isArray());
        JsonNode status = call(tool, Map.of("action", "SESSION_STATUS"));
        assertTrue(status.path("sessionUrls").isIntegralNumber());
        JsonNode jar = call(tool, Map.of("action", "COOKIE_JAR_LIST"));
        assertTrue(jar.path("cookies").get(0).path("expires").isNull());
        JsonNode set = call(tool, Map.of("action", "COOKIE_JAR_SET", "tokenName", "session", "tokenValue", "value", "domain", "example.test"));
        assertTrue(set.path("expiration").isNull());
        call(tool, Map.of("action", "COOKIE_JAR_DELETE", "tokenName", "session", "domain", "example.test"));
        call(tool, Map.of("action", "COOKIE_JAR_CLEAR"));
        JsonNode tested = call(tool, Map.of("action", "TEST_SESSION", "url", "https://example.test/item"));
        assertTrue(tested.path("setCookies").get(0).isObject());
        JsonNode analyzed = call(tool, Map.of("action", "ANALYZE_SESSION_VALIDITY", "url", "https://example.test/item"));
        assertTrue(analyzed.path("setCookies").get(0).isTextual());
        assertEquals(2, httpSends.get());
        call(tool, Map.of("action", "EXTRACT_TOKENS"));
        call(tool, Map.of("action", "FIND_LOGOUT"));
        call(tool, Map.of("action", "ENABLE_AUTO_SESSION"));
        JsonNode active = call(tool, Map.of("action", "AUTO_SESSION_STATUS"));
        assertEquals("Never", active.path("lastActivity").asText());
        call(tool, Map.of("action", "DISABLE_AUTO_SESSION"));
        call(tool, Map.of("action", "AUTO_SESSION_STATUS"));
        call(tool, Map.of("action", "CLEAR_TOKENS"));
        assertTrue(JSON.valueToTree(tool.getToolInfo()).path("annotations").path("openWorldHint").asBoolean());
    }

    @Test
    public void collaboratorPayloadsInteractionMapsAndUnsupportedActionAreDocumented() throws Exception {
        String previousHome = System.getProperty("user.home");
        CollaboratorTool tool;
        try {
            System.setProperty("user.home", temporary.newFolder("collaborator-home").getAbsolutePath());
            tool = keep(new CollaboratorTool(api));
        } finally {
            System.setProperty("user.home", previousHome);
        }
        JsonNode payloads = call(tool, Map.of("action", "GENERATE_PAYLOAD", "count", 2));
        assertEquals(2, payloads.path("payloads").size());
        assertTrue(payloads.path("payloads").get(0).path("isLiteral").isTextual());
        call(tool, Map.of("action", "GENERATE_WITH_CUSTOM_DATA", "customData", "contract", "count", 2));
        JsonNode interactions = call(tool, Map.of("action", "CHECK_INTERACTIONS"));
        assertEquals("127.0.0.1", interactions.path("interactions").get(0).path("clientIp").asText());
        call(tool, Map.of("action", "FILTER_INTERACTIONS", "interactionType", "DNS"));
        call(tool, Map.of("action", "STATUS"));
        call(tool, Map.of("action", "LIST_PAYLOAD_TYPES"));
        call(tool, Map.of("action", "SERVER_INFO"));
        call(tool, Map.of("action", "GET_SECRET_KEY"));
        assertFalse(call(tool, Map.of("action", "CLEAR_INTERACTIONS")).path("supported").asBoolean());
    }

    @Test
    public void scopeMutationChecksAndAnalysisReturnTypedUrlResults() throws Exception {
        ScopeTool tool = keep(new ScopeTool(api));
        call(tool, Map.of("action", "add", "url", "https://example.test/item"));
        call(tool, Map.of("action", "view"));
        call(tool, Map.of("action", "check", "url", "https://example.test/item"));
        call(tool, Map.of("action", "analyze"));
        call(tool, Map.of("action", "bulk_add", "urls", List.of("https://example.test/other")));
        JsonNode checked = call(tool, Map.of("action", "bulk_check", "urls", List.of("https://example.test/item", "https://outside.test/")));
        assertEquals(2, checked.path("results").size());
        call(tool, Map.of("action", "remove", "url", "https://example.test/item"));
    }

    @Test
    public void configExportImportAndResetExposeSerializedJsonAndActualKeys() throws Exception {
        ConfigTool tool = keep(new ConfigTool(api));
        JsonNode exported = call(tool, Map.of("action", "GET_PROJECT_OPTIONS", "path", "target.scope"));
        assertEquals(exported.path("json").asText().length(), exported.path("length").asInt());
        call(tool, Map.of("action", "GET_USER_OPTIONS"));
        JsonNode imported = call(tool, Map.of("action", "SET_PROJECT_OPTIONS", "json", "{\"target\":{\"scope\":{}}}"));
        assertEquals("target", imported.path("importedTopLevelKeys").get(0).asText());
        assertNotNull(importedConfig);
        call(tool, Map.of("action", "SET_USER_OPTIONS", "json", "{\"user_options\":{}}"));
        call(tool, Map.of("action", "RESET_PROJECT_OPTIONS", "path", "target.scope"));
    }

    @Test
    public void organizerDetailsIncludeNullableResponseAndListsContainTypedItems() throws Exception {
        OrganizerTool tool = keep(new OrganizerTool(api));
        call(tool, Map.of("action", "SEND_TO_ORGANIZER", "url", "https://example.test/item"));
        JsonNode list = call(tool, Map.of("action", "LIST_ITEMS"));
        assertEquals(2, list.path("items").size());
        call(tool, Map.of("action", "LIST_ITEMS_FILTERED", "urlPattern", "example.test", "methodFilter", "GET"));
        call(tool, Map.of("action", "GET_ITEM_COUNT"));
        call(tool, Map.of("action", "GET_ITEM_STATUS", "itemId", 7));
        call(tool, Map.of("action", "GET_ITEM_BY_ID", "itemId", 7));
        assertTrue(call(tool, Map.of("action", "GET_ITEM_BY_ID", "itemId", 8)).path("response").isNull());
    }

    @Test
    public void annotationsExposeNativeAndDatabaseEntriesAndFileOperationCounts() throws Exception {
        AnnotateTool tool = keep(new AnnotateTool(api));
        call(tool, Map.of("action", "ANNOTATE_PROXY", "entryId", 1, "notes", "new note"));
        call(tool, Map.of("action", "ANNOTATE_TARGET", "url", "https://example.test/item", "notes", "target note"));
        call(tool, Map.of("action", "ANNOTATE_ORGANIZER", "url", "https://example.test/item", "notes", "organizer note"));
        call(tool, Map.of("action", "ANNOTATE_REPEATER", "url", "https://example.test/item", "notes", "saved note"));
        call(tool, Map.of("action", "ANNOTATE_INTRUDER", "url", "https://example.test/item", "notes", "intruder note"));
        call(tool, Map.of("action", "ANNOTATE_SCANNER", "issueId", "7", "notes", "scanner note"));
        call(tool, Map.of("action", "ANNOTATE_COLLABORATOR", "interactionId", "7", "notes", "callback note"));
        call(tool, Map.of("action", "GET_ANNOTATIONS", "source", "ALL"));
        call(tool, Map.of("action", "SEARCH_BY_ANNOTATION", "searchQuery", "note", "source", "ALL"));
        call(tool, Map.of("action", "ANNOTATE_BY_PATTERN", "pattern", "example", "notes", "bulk note"));
        String file = temporary.newFile("annotations.json").getAbsolutePath();
        call(tool, Map.of("action", "EXPORT_ANNOTATIONS", "filePath", file));
        assertTrue(Files.size(java.nio.file.Path.of(file)) > 0);
        call(tool, Map.of("action", "IMPORT_ANNOTATIONS", "filePath", file));
        call(tool, Map.of("action", "ENABLE_AUTO_ANNOTATION", "autoRules", Map.of("urlPatterns", List.of("example"), "notes", "auto note")));
        call(tool, Map.of("action", "DISABLE_AUTO_ANNOTATION"));
        call(tool, Map.of("action", "CLEAR_ANNOTATIONS", "source", "ALL"));
    }

    @Test
    public void logCaptureRecordsActualMessagesAndClearingCounts() throws Exception {
        LogsTool tool = keep(new LogsTool(api));
        tool.close(); // Start this static captured-log store empty.
        call(tool, Map.of("action", "WRITE_LOG", "message", "contract log"));
        JsonNode logs = call(tool, Map.of("action", "GET_LOGS", "category", "ALL"));
        assertEquals("contract log", logs.path("outputLogs").get(0).path("message").asText());
        call(tool, Map.of("action", "RAISE_EVENT", "message", "contract event", "level", "INFO"));
        assertEquals(2, call(tool, Map.of("action", "CLEAR_LOGS", "category", "ALL")).path("clearedCount").asInt());
    }

    @Test
    public void utilitiesExposeRealConversionJsonAndSearchResultsIncludingMissingValues() throws Exception {
        UtilitiesTool tool = keep(new UtilitiesTool(api));
        call(tool, Map.of("action", "base64_encode", "input", "hello"));
        call(tool, Map.of("action", "base64_decode", "input", "AAE="));
        call(tool, Map.of("action", "random", "length", 4));
        JsonNode missing = call(tool, Map.of("action", "json_path", "input", "{}", "jsonPath", "$.missing"));
        assertTrue(missing.path("value").isNull());
        call(tool, Map.of("action", "json_path", "input", "{\"n\":42}", "jsonPath", "$.n"));
        call(tool, Map.of("action", "json_validate", "input", "{\"n\":42}"));
        call(tool, Map.of("action", "number_convert", "input", "42", "fromBase", "decimal", "toBase", "hex"));
        JsonNode noMatch = call(tool, Map.of("action", "byte_search", "input", "abc", "searchPattern", "z"));
        assertEquals(-1, noMatch.path("firstMatchIndex").asInt());
        call(tool, Map.of("action", "byte_search", "input", "ab ab", "searchPattern", "ab", "useRegex", true));
    }

    @Test
    public void schemasRejectIncorrectDomainTypesWhileAllowingFallbackEnvelopes() throws Exception {
        ConfigTool config = keep(new ConfigTool(api));
        ObjectNode data = (ObjectNode) call(config, Map.of("action", "GET_PROJECT_OPTIONS"));
        data.put("length", "wrong");
        assertThrows(AssertionError.class, () -> OutputSchemaAssertions.assertMatches(schema(config), data));
        OrganizerTool organizer = keep(new OrganizerTool(api));
        ObjectNode list = (ObjectNode) call(organizer, Map.of("action", "LIST_ITEMS"));
        ((ObjectNode) list.path("items").get(0)).put("id", "wrong");
        assertThrows(AssertionError.class, () -> OutputSchemaAssertions.assertMatches(schema(organizer), list));
        OutputSchemaAssertions.assertMatches(schema(config), JSON.valueToTree(Map.of("text", "error", "truncated", true, "originalChars", 100000, "limitChars", 95000)));
    }

    private <T extends McpTool> T keep(T tool) { owned.add(tool); return tool; }
    private static JsonNode schema(McpTool tool) { return JSON.valueToTree(tool.getToolInfo()).path("outputSchema"); }
    private JsonNode call(McpTool tool, Map<String, Object> arguments) throws Exception {
        JsonNode response = JSON.valueToTree(tool.execute(JSON.valueToTree(arguments)));
        assertFalse(arguments + " -> " + response, response.path("isError").asBoolean());
        JsonNode data = response.path("structuredContent");
        assertTrue(arguments + " produced no compact structured result: " + response, data.isObject());
        OutputSchemaAssertions.assertDocumented(schema(tool), data);
        return data;
    }

    private Object factory(Object p, Method method, Object[] args) {
        return switch (method.getName()) {
            case "httpRequestFromUrl" -> request((String) args[0], "GET", "");
            case "httpRequest" -> request("https://example.test/item", "POST", args[args.length - 1].toString());
            case "byteArray" -> bytes(args[0] instanceof byte[] value ? value : args[0].toString().getBytes(StandardCharsets.ISO_8859_1));
            case "httpRequestResponse" -> exchange((HttpRequest) args[0], (HttpResponse) args[1]);
            default -> defaultValue(method.getReturnType());
        };
    }

    private <T> T generic(Class<T> type) {
        return stub(type, (p, method, args) -> {
            String name = method.getName();
            if (name.equals("toString")) return "contract-value";
            if (name.equals("history")) return List.of(sampleHistory);
            if (name.equals("requestResponses")) return List.of(sampleExchange);
            if (name.equals("sendToRepeater") || name.equals("sendToIntruder") || name.equals("sendToOrganizer")) { uiSends.incrementAndGet(); return null; }
            if (type.getSimpleName().equals("SiteMap") && name.equals("add")) { issueAdds.incrementAndGet(); return null; }
            if (name.equals("sendRequest")) { httpSends.incrementAndGet(); return sampleExchange; }
            if (name.equals("items")) {
                if (args != null && args.length == 1 && args[0] instanceof OrganizerItemFilter filter) return organizerItems.stream().filter(filter::matches).toList();
                return organizerItems;
            }
            if (name.equals("itemCount")) return organizerItems.size();
            if (name.equals("isInScope")) return scope.contains(args[0]);
            if (name.equals("includeInScope")) { scope.add((String) args[0]); return null; }
            if (name.equals("excludeFromScope")) { scope.remove(args[0]); return null; }
            if (name.startsWith("export") && name.endsWith("OptionsAsJson")) return "{\"target\":{\"scope\":{\"include\":[]}}}";
            if (name.startsWith("import") && name.endsWith("OptionsFromJson")) { importedConfig = (String) args[0]; return null; }
            if (name.equals("cookies")) return cookies;
            if (name.equals("getAllInteractions") || name.equals("getInteractions")) return List.of(interaction());
            if (name.equals("generatePayload")) return payload();
            if (type == CollaboratorServer.class && name.equals("address")) return "collaborator.test";
            if (type.getSimpleName().equals("Base64Utils") && name.equals("encodeToString")) return Base64.getEncoder().encodeToString(((ByteArray) args[0]).getBytes());
            if (type.getSimpleName().equals("Base64Utils") && name.equals("decode")) return bytes(Base64.getDecoder().decode(args[0].toString()));
            if (type.getSimpleName().equals("RandomUtils") && name.equals("randomString")) return "a".repeat((int) args[0]);
            if (type.getSimpleName().equals("JsonUtils")) {
                JsonNode value = JSON.readTree((String) args[0]);
                if (name.equals("isValidJson")) return true;
                if (name.equals("read")) return value.path("n").isMissingNode() ? null : value.path("n").asText();
                if (name.equals("readLong")) return 42L;
                if (name.equals("readDouble")) return 42.0;
                if (name.equals("readBoolean")) return null;
            }
            if (type.getSimpleName().equals("NumberUtils") && name.startsWith("convertDecimalTo")) {
                long number = Long.parseLong((String) args[0]);
                int radix = name.endsWith("Binary") ? 2 : name.endsWith("Octal") ? 8 : 16;
                return Long.toString(number, radix);
            }
            if (type.getSimpleName().equals("ByteUtils")) {
                String input = new String((byte[]) args[0], StandardCharsets.UTF_8);
                if (args[1] instanceof java.util.regex.Pattern regex) {
                    var matcher = regex.matcher(input);
                    if (name.equals("indexOf")) return matcher.find() ? matcher.start() : -1;
                    int count = 0; while (matcher.find()) count++; return count;
                }
                String pattern = new String((byte[]) args[1], StandardCharsets.UTF_8);
                if (name.equals("indexOf")) return input.indexOf(pattern, args.length > 3 ? (int) args[3] : 0);
                return input.contains(pattern) ? 1 : 0;
            }
            return defaultValue(method.getReturnType());
        });
    }

    private Object defaultValue(Class<?> type) {
        if (type == void.class) return null;
        if (type == boolean.class) return false;
        if (type == byte.class) return (byte) 0;
        if (type == short.class) return (short) 0;
        if (type == int.class) return 0;
        if (type == long.class) return 0L;
        if (type == double.class) return 0.0;
        if (type == float.class) return 0.0f;
        if (type == char.class) return '\0';
        if (type == String.class) return "";
        if (type == List.class || type == Collection.class) return List.of();
        if (type == Optional.class) return Optional.empty();
        if (type.isEnum()) return type.getEnumConstants()[0];
        if (type.isInterface()) return generic(type);
        return null;
    }

    private HttpRequest request(String url, String method, String body) {
        return stub(HttpRequest.class, (p, m, a) -> switch (m.getName()) {
            case "url" -> url;
            case "method" -> method;
            case "path", "pathWithoutQuery" -> "/item";
            case "headers" -> List.of(header("Host", "example.test"), header("Cookie", "session=abc"));
            case "body" -> bytes(body.getBytes(StandardCharsets.ISO_8859_1));
            case "withMethod" -> request(url, (String) a[0], body);
            case "withBody" -> request(url, method, a[0].toString());
            case "withAddedHeader", "withUpdatedHeader", "withRemovedHeader" -> p;
            case "httpService" -> generic(HttpService.class);
            case "toString" -> method + " /item HTTP/1.1\r\nHost: example.test\r\nCookie: session=abc\r\n\r\n" + body;
            default -> defaultValue(m.getReturnType());
        });
    }
    private HttpResponse response() {
        return stub(HttpResponse.class, (p, m, a) -> switch (m.getName()) {
            case "statusCode" -> (short) 200;
            case "reasonPhrase" -> "OK";
            case "headers" -> List.of(header("Content-Type", "text/plain"), header("Set-Cookie", "session=refreshed; Path=/"));
            case "body" -> bytes("welcome".getBytes(StandardCharsets.UTF_8));
            case "bodyToString" -> "welcome";
            case "toString" -> "HTTP/1.1 200 OK\r\nSet-Cookie: session=refreshed; Path=/\r\n\r\nwelcome";
            default -> defaultValue(m.getReturnType());
        });
    }
    private HttpRequestResponse exchange(HttpRequest request, HttpResponse response) {
        return stub(HttpRequestResponse.class, (p, m, a) -> switch (m.getName()) {
            case "request" -> request;
            case "response" -> response;
            case "hasResponse" -> response != null;
            case "annotations" -> annotations();
            default -> defaultValue(m.getReturnType());
        });
    }
    private HttpHeader header(String name, String value) {
        return stub(HttpHeader.class, (p, m, a) -> switch (m.getName()) {
            case "name" -> name;
            case "value" -> value;
            case "toString" -> name + ": " + value;
            default -> defaultValue(m.getReturnType());
        });
    }
    private ByteArray bytes(byte[] value) {
        return stub(ByteArray.class, (p, m, a) -> switch (m.getName()) {
            case "length" -> value.length;
            case "getBytes" -> value.clone();
            case "toString" -> new String(value, StandardCharsets.ISO_8859_1);
            default -> defaultValue(m.getReturnType());
        });
    }
    private Cookie cookie(String name, String value, ZonedDateTime expires) {
        return stub(Cookie.class, (p, m, a) -> switch (m.getName()) {
            case "name" -> name;
            case "value" -> value;
            case "domain" -> "example.test";
            case "path" -> "/";
            case "expiration" -> Optional.ofNullable(expires);
            default -> defaultValue(m.getReturnType());
        });
    }
    private Annotations annotations() {
        return stub(Annotations.class, (p, m, a) -> switch (m.getName()) {
            case "notes" -> annotationNotes;
            case "highlightColor" -> annotationColor;
            case "hasNotes" -> annotationNotes != null && !annotationNotes.isEmpty();
            case "hasHighlightColor" -> annotationColor != null;
            case "setNotes" -> { annotationNotes = (String) a[0]; yield null; }
            case "setHighlightColor" -> { annotationColor = (HighlightColor) a[0]; yield null; }
            default -> defaultValue(m.getReturnType());
        });
    }
    private OrganizerItem organizerItem(int id, boolean hasResponse) {
        return stub(OrganizerItem.class, (p, m, a) -> switch (m.getName()) {
            case "id" -> id;
            case "request" -> sampleRequest;
            case "response" -> hasResponse ? sampleResponse : null;
            case "hasResponse" -> hasResponse;
            case "annotations" -> annotations();
            default -> defaultValue(m.getReturnType());
        });
    }
    private CollaboratorPayload payload() {
        int id = payloadIds.incrementAndGet();
        return stub(CollaboratorPayload.class, (p, m, a) -> switch (m.getName()) {
            case "toString" -> "payload" + id + ".collaborator.test";
            case "id" -> generic(m.getReturnType());
            case "server" -> Optional.of(generic(CollaboratorServer.class));
            default -> defaultValue(m.getReturnType());
        });
    }
    private Interaction interaction() {
        return stub(Interaction.class, (p, m, a) -> switch (m.getName()) {
            case "type" -> InteractionType.DNS;
            case "timeStamp" -> ZonedDateTime.parse("2026-01-01T00:00:00Z");
            case "customData" -> Optional.of("contract");
            case "clientIp" -> java.net.InetAddress.getByAddress(new byte[]{127, 0, 0, 1});
            case "clientPort" -> 1234;
            default -> defaultValue(m.getReturnType());
        });
    }
    @SuppressWarnings("unchecked")
    private static <T> T stub(Class<T> type, InvocationHandler handler) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, handler);
    }
}
