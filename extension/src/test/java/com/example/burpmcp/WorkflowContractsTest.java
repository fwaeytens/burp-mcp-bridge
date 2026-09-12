package com.example.burpmcp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.bambda.Bambda;
import burp.api.montoya.bambda.BambdaImportResult;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.responses.analysis.AttributeType;
import burp.api.montoya.http.message.responses.analysis.ResponseKeywordsAnalyzer;
import burp.api.montoya.http.message.responses.analysis.ResponseVariationsAnalyzer;
import burp.api.montoya.internal.MontoyaObjectFactory;
import burp.api.montoya.internal.ObjectFactoryLocator;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.proxy.Proxy;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.scanner.AuditConfiguration;
import burp.api.montoya.scanner.Scanner;
import burp.api.montoya.scanner.audit.Audit;
import burp.api.montoya.utilities.Utilities;
import burp.api.montoya.utilities.rank.RankedHttpRequestResponse;
import burp.api.montoya.utilities.rank.RankingUtils;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.net.URI;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BiFunction;

import static org.junit.Assert.*;

/** Real tool results, backed by isolated Montoya proxies, must match discovery metadata. */
public class WorkflowContractsTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private MontoyaObjectFactory originalFactory;
    private MontoyaApi api;
    private final List<ProxyHttpRequestResponse> history = new ArrayList<>();
    private final Map<String, HttpResponse> responses = new HashMap<>();
    private final List<HttpRequest> sent = new ArrayList<>();
    private final List<HttpRequest> audited = new ArrayList<>();
    private final List<String> importedYaml = new ArrayList<>();
    private int uiItems;
    private int imports;
    private BambdaImportResult.Status importStatus = BambdaImportResult.Status.LOADED_WITHOUT_ERRORS;
    private boolean importThrows;
    private boolean rankingUnavailable;
    private ScannerTool scanner;

    @Before
    public void setUp() {
        originalFactory = ObjectFactoryLocator.FACTORY;
        ObjectFactoryLocator.FACTORY = proxy(MontoyaObjectFactory.class, (method, args) -> switch (method) {
            case "httpRequestFromUrl" -> {
                String url = (String) args[0];
                if (url.contains("broken")) throw new IllegalArgumentException("bad URL");
                URI uri = URI.create(url);
                boolean secure = uri.getScheme().equals("https");
                HttpService service = service(uri.getHost(), uri.getPort() < 0 ? secure ? 443 : 80 : uri.getPort(), secure);
                yield request(url, "GET " + (uri.getRawPath().isEmpty() ? "/" : uri.getRawPath())
                    + " HTTP/1.1\r\nHost: " + uri.getHost() + "\r\n\r\n", service);
            }
            case "httpService" -> service((String) args[0], (int) args[1], (boolean) args[2]);
            case "httpRequest" -> request("https://example.test/", (String) args[1], (HttpService) args[0]);
            case "byteArray" -> bytes((byte[]) args[0]);
            case "httpRequestResponse" -> exchange((HttpRequest) args[0], (HttpResponse) args[1]);
            case "auditConfiguration" -> proxy(AuditConfiguration.class, (name, values) -> null);
            default -> throw new AssertionError("Unexpected factory: " + method);
        });
        ResponseKeywordsAnalyzer keywords = proxy(ResponseKeywordsAnalyzer.class, (method, args) -> switch (method) {
            case "variantKeywords" -> Set.of("token");
            case "invariantKeywords" -> Set.of("error");
            default -> null;
        });
        ResponseVariationsAnalyzer variations = proxy(ResponseVariationsAnalyzer.class, (method, args) -> switch (method) {
            case "variantAttributes" -> Set.of(AttributeType.BODY_CONTENT);
            case "invariantAttributes" -> Set.of(AttributeType.STATUS_CODE);
            default -> null;
        });
        Http http = proxy(Http.class, (method, args) -> switch (method) {
            case "sendRequest" -> {
                HttpRequest request = (HttpRequest) args[0];
                sent.add(request);
                yield exchange(request, responses.get(request.url()));
            }
            case "createResponseKeywordsAnalyzer" -> keywords;
            case "createResponseVariationsAnalyzer" -> variations;
            default -> throw new AssertionError("Unexpected HTTP operation: " + method);
        });
        Bambda bambda = proxy(Bambda.class, (method, args) -> {
            imports++;
            importedYaml.add((String) args[0]);
            if (importThrows) throw new IllegalStateException("import failure");
            if (importStatus == null) return null;
            return proxy(BambdaImportResult.class, (name, values) -> switch (name) {
                case "status" -> importStatus;
                case "importErrors" -> importStatus == BambdaImportResult.Status.LOADED_WITH_ERRORS ? List.of("Compilation error") : List.of();
                default -> null;
            });
        });
        Audit audit = proxy(Audit.class, (method, args) -> switch (method) {
            case "addRequest" -> { audited.add((HttpRequest) args[0]); yield null; }
            case "requestCount" -> audited.size();
            default -> null;
        });
        RankingUtils ranking = proxy(RankingUtils.class, (method, args) -> {
            HttpRequestResponse exchange = (HttpRequestResponse) ((List<?>) args[0]).get(0);
            return List.of(proxy(RankedHttpRequestResponse.class, (name, values) -> switch (name) {
                case "rank" -> 85;
                case "requestResponse" -> exchange;
                default -> null;
            }));
        });
        Utilities utilities = proxy(Utilities.class, (method, args) -> {
            if (method.equals("rankingUtils")) {
                if (rankingUnavailable) throw new NoSuchMethodError("rankingUtils");
                return ranking;
            }
            return null; // byteUtils is obtained but unused by pattern analysis.
        });
        api = proxy(MontoyaApi.class, (method, args) -> switch (method) {
            case "http" -> http;
            case "logging" -> proxy(Logging.class, (name, values) -> null);
            case "proxy" -> proxy(Proxy.class, (name, values) -> history);
            case "bambda" -> bambda;
            case "utilities" -> utilities;
            case "scanner" -> proxy(Scanner.class, (name, values) -> audit);
            case "comparer" -> proxy(burp.api.montoya.comparer.Comparer.class, (name, values) -> { uiItems++; return null; });
            default -> throw new AssertionError("Unexpected API operation: " + method);
        });
    }

    @After
    public void tearDown() {
        if (scanner != null) scanner.close();
        ObjectFactoryLocator.FACTORY = originalFactory;
    }

    @Test
    public void wordAndByteModesReturnDifferentAccurateChangedSpans() throws Exception {
        ComparerTool tool = new ComparerTool(api);
        ObjectNode args = args("COMPARE_TEXT", "text1", "the red fox", "text2", "the blue fox");
        JsonNode words = call(tool, args, false).path("comparison");
        assertEquals("token", words.path("unit").asText());
        assertEquals(1, words.path("removedUnits").asInt());
        assertEquals("red", words.path("removedPreview").asText());
        args.put("comparisonType", "BYTES");
        JsonNode bytes = call(tool, args, false).path("comparison");
        assertEquals(3, bytes.path("removedUnits").asInt());
        assertEquals(4, bytes.path("addedUnits").asInt());
        assertEquals("blue", new String(Base64.getDecoder().decode(bytes.path("addedPreview").asText()), StandardCharsets.UTF_8));
        JsonNode unicode = call(tool, args("COMPARE_TEXT", "text1", "é", "text2", "e", "comparisonType", "BYTES"), false);
        assertEquals(2, unicode.path("comparison").path("removedUnits").asInt());
    }

    @Test
    public void comparisonOptionsAreValidatedAndPreviewsAndInputsAreBounded() throws Exception {
        ComparerTool tool = new ComparerTool(api);
        JsonNode normalized = call(tool, args("COMPARE_TEXT", "text1", "a\n b", "text2", "a b", "ignoreWhitespace", true), false);
        assertTrue(normalized.path("comparison").path("identical").asBoolean());
        for (String type : List.of("UNKNOWN", "HEADERS_ONLY", "BODY_ONLY")) {
            call(tool, args("COMPARE_TEXT", "text1", "a", "text2", "b", "comparisonType", type), true);
        }
        call(tool, args("COMPARE_TEXT", "text1", "a", "text2", "b", "comparisonType", "BYTES", "ignoreWhitespace", true), true);
        call(tool, args("SEND_TO_COMPARER", "text1", "a", "comparisonType", "WORDS"), true);
        call(tool, args("SEND_TO_COMPARER"), true);
        call(tool, args("SEND_TO_COMPARER", "text1", "a", "url1", "https://example.test/a"), true);
        assertEquals(0, uiItems);
        JsonNode bounded = call(tool, args("COMPARE_TEXT", "text1", "a".repeat(2000), "text2", "b".repeat(2000)), false);
        assertEquals(1024, bounded.path("comparison").path("removedPreview").asText().length());
        assertTrue(bounded.path("comparison").path("previewTruncated").asBoolean());
        call(tool, args("COMPARE_TEXT", "text1", "a".repeat(1024 * 1024 + 1), "text2", "b"), true);
    }

    @Test
    public void httpSectionModesHonorHeadersAndBodyWithExplicitNetworkBehavior() throws Exception {
        ComparerTool tool = new ComparerTool(api);
        responses.put("https://example.test/a", response("HTTP/1.1 200 OK\r\nX-Test: one\r\n\r\nalpha"));
        responses.put("https://example.test/b", response("HTTP/1.1 200 OK\r\nX-Test: one\r\n\r\nbeta"));
        ObjectNode args = args("COMPARE_RESPONSES", "url1", "https://example.test/a", "url2", "https://example.test/b", "comparisonType", "HEADERS_ONLY");
        assertTrue(call(tool, args, false).path("comparison").path("identical").asBoolean());
        assertEquals(2, sent.size());
        args.put("comparisonType", "BODY_ONLY");
        assertFalse(call(tool, args, false).path("comparison").path("identical").asBoolean());
        responses.put("https://example.test/b", response("HTTP/1.1 404 Missing\r\nX-Test: two\r\n\r\nalpha"));
        assertTrue(call(tool, args, false).path("comparison").path("identical").asBoolean());
        int before = sent.size();
        args.put("action", "COMPARE_REQUESTS");
        args.put("comparisonType", "BYTES");
        assertFalse(call(tool, args, false).path("comparison").path("identical").asBoolean());
        assertEquals(before, sent.size());
    }

    @Test
    public void proxyAndUiActionsReturnDocumentedResultsAndRealErrors() throws Exception {
        ComparerTool tool = new ComparerTool(api);
        ObjectNode args = args("COMPARE_PROXY_ENTRIES", "url1", "/a", "url2", "/b");
        assertEquals("proxy_entries_not_found", call(tool, args, true).path("error").asText());
        addHistory("https://example.test/a", "alpha");
        addHistory("https://example.test/b", "beta");
        JsonNode compared = call(tool, args, false);
        assertTrue(compared.path("sentToComparer").asBoolean());
        assertTrue(compared.has("comparison"));
        assertEquals(2, uiItems);
        assertEquals(0, sent.size());
        call(tool, args("SEND_TO_COMPARER", "text1", "hello"), false);
        assertEquals(3, uiItems);
        JsonNode partial = call(tool, args("SEND_TO_COMPARER", "url1", "https://example.test/a", "url2", "https://broken.test/"), true);
        assertEquals(1, partial.path("sent").size());
        assertEquals(1, partial.path("errors").size());
    }

    @Test
    public void bambdaUnsupportedActionAndNativeImportFailuresAreMachineReadable() throws Exception {
        BambdaTool tool = new BambdaTool(api);
        for (boolean verbose : new boolean[]{false, true}) {
            JsonNode unsupported = call(tool, args("GET_ACTIVE_FILTER", "verbose", verbose), true);
            assertEquals("api_limitation", unsupported.path("error").asText());
            assertFalse(unsupported.path("supported").asBoolean(true));
        }
        assertEquals(0, imports);
        assertEquals(10, call(tool, args("LIST_PRESETS"), false).path("presets").size());
        assertTrue(call(tool, args("APPLY_FILTER", "preset", "api_endpoints"), false).path("success").asBoolean());
        importStatus = BambdaImportResult.Status.LOADED_WITH_ERRORS;
        JsonNode failed = call(tool, args("CREATE_CUSTOM", "customScript", "broken", "description", "Test"), true);
        assertFalse(failed.path("success").asBoolean());
        assertEquals("LOADED_WITH_ERRORS", failed.path("status").asText());
        assertEquals("Compilation error", failed.path("errors").get(0).asText());
        importStatus = null;
        assertEquals("NO_RESULT", call(tool, args("APPLY_FILTER", "preset", "api_endpoints"), true).path("status").asText());
        importThrows = true;
        call(tool, args("CREATE_CUSTOM", "customScript", "return true;"), true);
        int before = imports;
        call(tool, args("CREATE_CUSTOM"), true);
        call(tool, args("APPLY_FILTER", "preset", "api_endpoints", "customScript", "return true;"), true);
        assertEquals(before, imports);
    }

    @Test
    public void bambdaImportsUseNativeViewIdentifiersAndPreservePublicAliases() throws Exception {
        BambdaTool tool = new BambdaTool(api);
        Map<String, String> locations = Map.of(
            "PROXY_HTTP_HISTORY", "PROXY_HTTP_HISTORY", "PROXY_WS_HISTORY", "PROXY_WEBSOCKET",
            "SITEMAP", "SITEMAP", "LOGGER", "LOGGER");
        for (String action : List.of("APPLY_FILTER", "CREATE_CUSTOM")) {
            for (Map.Entry<String, String> location : locations.entrySet()) {
                JsonNode imported = call(tool, args(action, "customScript", "return true;",
                    "location", location.getKey()), false);
                assertEquals(location.getKey(), imported.path("location").asText());
                String yaml = importedYaml.get(importedYaml.size() - 1);
                assertTrue(yaml.contains("\nfunction: VIEW_FILTER\nlocation: " + location.getValue() + "\n"));
            }
        }
        int before = imports;
        call(tool, args("CREATE_CUSTOM", "customScript", "return true;", "location", "SITE_MAP"), true);
        assertEquals(before, imports);
    }

    @Test
    public void emittedXssPresetMatchesHtmlWithParametersOnly() throws Exception {
        call(new BambdaTool(api), args("APPLY_FILTER", "preset", "xss_candidates"), false);
        String yaml = importedYaml.get(0);
        String script = yaml.substring(yaml.indexOf("\nsource: |\n  ") + "\nsource: |\n  ".length());
        Path directory = Files.createTempDirectory("bambda-preset-test-");
        try {
            Path source = directory.resolve("GeneratedBambda.java");
            Files.writeString(source, "public class GeneratedBambda { public static boolean filter("
                + "burp.api.montoya.http.message.HttpRequestResponse requestResponse) { " + script + " } }");
            String apiClasspath = Path.of(HttpRequestResponse.class.getProtectionDomain()
                .getCodeSource().getLocation().toURI()).toString();
            assertEquals(0, javax.tools.ToolProvider.getSystemJavaCompiler().run(null, null, null,
                "--release", "17", "-classpath", apiClasspath, "-d", directory.toString(), source.toString()));
            try (URLClassLoader loader = new URLClassLoader(new java.net.URL[]{directory.toUri().toURL()},
                    getClass().getClassLoader())) {
                var filter = loader.loadClass("GeneratedBambda").getMethod("filter", HttpRequestResponse.class);
                assertEquals(true, filter.invoke(null, presetExchange(MimeType.HTML, true)));
                assertEquals(false, filter.invoke(null, presetExchange(MimeType.HTML, false)));
                assertEquals(false, filter.invoke(null, presetExchange(MimeType.JSON, true)));
                assertEquals(false, filter.invoke(null, presetExchange(null, true)));
            }
        } finally {
            try (var files = Files.walk(directory)) {
                for (Path file : files.sorted(Comparator.reverseOrder()).toList()) Files.deleteIfExists(file);
            }
        }
    }

    private static HttpRequestResponse presetExchange(MimeType mimeType, boolean parameters) {
        HttpRequest request = proxy(HttpRequest.class, (method, args) -> parameters);
        HttpResponse response = mimeType == null ? null : proxy(HttpResponse.class, (method, args) -> mimeType);
        return proxy(HttpRequestResponse.class, (method, args) -> switch (method) {
            case "hasResponse" -> response != null;
            case "request" -> request;
            case "response" -> response;
            default -> null;
        });
    }

    @Test
    public void analyzerOutputsCoverNestedCollectionsAndNullableOmissions() throws Exception {
        ResponseAnalysisTool tool = new ResponseAnalysisTool(api);
        addHistory("https://example.test/a?q=token", "token token");
        addHistory("https://example.test/a?q=token", "token error");
        assertEquals(2, call(tool, args("keywords"), false).path("responsesAnalyzed").asInt());
        assertTrue(call(tool, args("variations"), false).path("variantAttributes").size() > 0);
        JsonNode pattern = call(tool, args("pattern", "pattern", "token"), false);
        assertEquals(2, pattern.path("matches").size());
        JsonNode reflection = call(tool, args("reflection", "proxyIds", List.of(1, -1)), false);
        assertEquals(-1, reflection.path("invalidProxyIds").get(0).asInt());
        assertTrue(reflection.path("reflectionPoints").get(0).path("reflections").has("q"));
        JsonNode ranked = call(tool, args("rank_anomalies"), false);
        assertEquals(85, ranked.path("topAnomalies").get(0).path("rank").asInt());
        assertFalse(ranked.path("topAnomalies").get(0).has("contentType"));
        assertEquals(1, ranked.path("distribution").path("veryHigh").asInt());
        assertEquals(0, sent.size());
    }

    @Test
    public void analyzerAllContainsPlainSubResultsIncludingFailures() throws Exception {
        ResponseAnalysisTool tool = new ResponseAnalysisTool(api);
        JsonNode combined = call(tool, args("all"), false);
        assertEquals("keywords", combined.path("keywords").path("operation").asText());
        assertTrue(combined.path("variations").has("error"));
        assertFalse(combined.path("variations").has("content"));
        call(tool, args("pattern", "pattern", "["), true);
        rankingUnavailable = true;
        assertTrue(call(tool, args("rank_anomalies"), true).path("message").asText().contains("not supported"));
        responses.put("https://example.test/a", response("HTTP/1.1 200 OK\r\n\r\na"));
        responses.put("https://example.test/b", response("HTTP/1.1 200 OK\r\n\r\nb"));
        assertEquals(2, call(tool, args("variations", "urls", List.of("https://example.test/a", "https://example.test/b")), false)
            .path("responsesAnalyzed").asInt());
        assertEquals(2, sent.size());
    }

    @Test
    public void scannerRequiresRealBooleanAndRejectsMixedBatchesBeforeAddingUrls() throws Exception {
        scanner = new ScannerTool(api);
        String raw = "GET / HTTP/1.1\r\nHost: example.test:80\r\n\r\n";
        ObjectNode start = args("SCAN_SPECIFIC_REQUEST", "request", raw);
        assertTrue(JSON.valueToTree(scanner.execute(start)).path("isError").asBoolean());
        start.put("useHttps", "false");
        assertTrue(JSON.valueToTree(scanner.execute(start)).path("isError").asBoolean());
        assertTrue(audited.isEmpty());
        start.put("useHttps", false);
        JsonNode started = JSON.valueToTree(scanner.execute(start)).path("structuredContent");
        assertEquals("HTTP", started.path("protocol").asText());
        String id = started.path("scanId").asText();
        ObjectNode add = args("ADD_TO_SCAN", "scanId", id, "urls", List.of("https://example.test/a"), "request", raw);
        assertTrue(JSON.valueToTree(scanner.execute(add)).path("isError").asBoolean());
        assertEquals(1, audited.size());
        add.remove("request");
        assertFalse(JSON.valueToTree(scanner.execute(add)).path("isError").asBoolean());
        assertEquals(2, audited.size());
        add.remove("urls");
        assertTrue(JSON.valueToTree(scanner.execute(add)).path("isError").asBoolean());
        start.put("useHttps", true);
        JsonNode tls = JSON.valueToTree(scanner.execute(start)).path("structuredContent");
        assertEquals("HTTPS", tls.path("protocol").asText());
        assertEquals(80, audited.get(2).httpService().port());
        assertTrue(audited.get(2).httpService().secure());
    }

    @Test
    public void metadataAndSchemaRejectIncorrectResultTypesAndAllowBridgeFallbacks() throws Exception {
        for (McpTool tool : List.of(new ComparerTool(api), new ResponseAnalysisTool(api))) {
            JsonNode info = JSON.valueToTree(tool.getToolInfo());
            assertFalse(info.path("annotations").path("readOnlyHint").asBoolean());
            assertFalse(info.path("annotations").path("idempotentHint").asBoolean());
            assertTrue(info.path("annotations").path("openWorldHint").asBoolean());
        }
        JsonNode bambda = JSON.valueToTree(new BambdaTool(api).getToolInfo());
        assertTrue(bambda.path("annotations").path("openWorldHint").asBoolean());
        assertTrue(bambda.path("annotations").path("destructiveHint").asBoolean());
        assertTrue(bambda.path("inputSchema").path("properties").path("customScript").path("description").asText().contains("Bindings depend on the selected view"));
        assertTrue(bambda.path("inputSchema").path("properties").path("preset").path("description").asText().contains("PROXY_HTTP_HISTORY"));
        assertNull(WorkflowOutputSchemas.forTool("unknown"));
        for (String name : List.of("burp_comparer", "burp_bambda", "burp_response_analyzer")) {
            validate(JSON.valueToTree(WorkflowOutputSchemas.forTool(name)), JSON.valueToTree(Map.of(
                "text", "Preview", "truncated", true, "originalChars", 100000, "limitChars", 95000)), "$", true);
        }
        ComparerTool tool = new ComparerTool(api);
        ObjectNode data = (ObjectNode) call(tool, args("COMPARE_TEXT", "text1", "a", "text2", "b"), false);
        ((ObjectNode) data.path("comparison")).put("removedUnits", "one");
        assertThrows(AssertionError.class, () -> validate(JSON.valueToTree(tool.getToolInfo()).path("outputSchema"), data, "$", true));
    }

    @Test
    public void verboseResultsAndErrorsKeepStructuredFallbacks() throws Exception {
        assertTrue(call(new ComparerTool(api), args("COMPARE_TEXT", "text1", "a", "text2", "b", "verbose", true), false).has("text"));
        assertTrue(call(new BambdaTool(api), args("LIST_PRESETS", "verbose", true), false).has("text"));
        assertTrue(call(new BambdaTool(api), args("CREATE_CUSTOM", "customScript", "return true;", "verbose", true), false).has("text"));
        assertTrue(call(new ResponseAnalysisTool(api), args("all", "verbose", true), false).path("text").asText().contains("No responses available"));
        call(new ComparerTool(api), args("SEND_TO_COMPARER", "url1", "https://broken.test/", "verbose", true), true);
    }

    private JsonNode call(McpTool tool, ObjectNode arguments, boolean error) throws Exception {
        JsonNode result = JSON.valueToTree(tool.execute(arguments));
        assertEquals(result.toString(), error, result.path("isError").asBoolean());
        JsonNode data = result.path("structuredContent");
        assertTrue(result.toString(), data.isObject());
        validate(JSON.valueToTree(tool.getToolInfo()).path("outputSchema"), data, "$", true);
        return data;
    }

    private static void validate(JsonNode schema, JsonNode value, String path, boolean documented) {
        String type = schema.path("type").asText();
        boolean matches = switch (type) {
            case "object" -> value.isObject(); case "array" -> value.isArray();
            case "integer" -> value.isIntegralNumber(); case "string" -> value.isTextual();
            case "boolean" -> value.isBoolean(); default -> false;
        };
        assertTrue(path + " expected " + type + ": " + value, matches);
        if (schema.has("minimum")) assertTrue(path, value.asLong() >= schema.path("minimum").asLong());
        if (schema.has("enum")) assertTrue(path, java.util.stream.StreamSupport.stream(schema.path("enum").spliterator(), false).anyMatch(value::equals));
        if (value.isObject()) {
            for (JsonNode required : schema.path("required")) assertTrue(path, value.has(required.asText()));
            value.fields().forEachRemaining(field -> {
                JsonNode definition = schema.path("properties").path(field.getKey());
                if (definition.isMissingNode() && schema.path("additionalProperties").isObject()) definition = schema.path("additionalProperties");
                assertFalse(path + "." + field.getKey() + " lacks a documented type", definition.isMissingNode());
                validate(definition, field.getValue(), path + "." + field.getKey(), documented);
            });
        } else if (value.isArray()) {
            for (JsonNode item : value) validate(schema.path("items"), item, path + "[]", documented);
        }
    }

    private void addHistory(String url, String body) {
        HttpRequest request = request(url, "GET /a HTTP/1.1\r\nHost: example.test\r\n\r\n", service("example.test", 443, true));
        HttpResponse response = response("HTTP/1.1 200 OK\r\n\r\n" + body);
        history.add(proxy(ProxyHttpRequestResponse.class, (method, args) -> switch (method) {
            case "finalRequest", "request" -> request;
            case "response", "originalResponse" -> response;
            case "hasResponse" -> true;
            default -> null;
        }));
    }

    private static ObjectNode args(String action, Object... fields) {
        ObjectNode result = JSON.createObjectNode().put("action", action);
        for (int i = 0; i < fields.length; i += 2) result.set((String) fields[i], JSON.valueToTree(fields[i + 1]));
        return result;
    }

    private static HttpService service(String host, int port, boolean secure) {
        return proxy(HttpService.class, (method, args) -> switch (method) {
            case "host" -> host; case "port" -> port; case "secure" -> secure; default -> null;
        });
    }

    private static HttpRequest request(String url, String raw, HttpService service) {
        return proxy(HttpRequest.class, (method, args) -> switch (method) {
            case "url" -> url; case "method" -> raw.split(" ", 3)[0]; case "path" -> raw.split(" ", 3)[1];
            case "httpService" -> service; case "headers" -> List.of();
            default -> message(raw, method, args);
        });
    }

    private static HttpResponse response(String raw) {
        return proxy(HttpResponse.class, (method, args) -> switch (method) {
            case "statusCode" -> Short.parseShort(raw.split(" ", 3)[1]);
            case "headerValue" -> null;
            default -> message(raw, method, args);
        });
    }

    private static Object message(String raw, String method, Object[] args) {
        int offset = raw.indexOf("\r\n\r\n") + 4;
        return switch (method) {
            case "toString" -> raw; case "toByteArray" -> bytes(raw.getBytes(StandardCharsets.UTF_8));
            case "bodyOffset" -> offset; case "body" -> bytes(raw.substring(offset).getBytes(StandardCharsets.UTF_8));
            case "bodyToString" -> raw.substring(offset); default -> null;
        };
    }

    private static HttpRequestResponse exchange(HttpRequest request, HttpResponse response) {
        return proxy(HttpRequestResponse.class, (method, args) -> switch (method) {
            case "request" -> request; case "response" -> response; default -> null;
        });
    }

    private static ByteArray bytes(byte[] bytes) {
        return proxy(ByteArray.class, (method, args) -> switch (method) {
            case "length" -> bytes.length; case "getBytes" -> bytes;
            case "subArray" -> bytes(Arrays.copyOfRange(bytes, (int) args[0], (int) args[1]));
            default -> null;
        });
    }

    @SuppressWarnings("unchecked")
    private static <T> T proxy(Class<T> type, BiFunction<String, Object[], Object> handler) {
        return (T) java.lang.reflect.Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type},
            (proxy, method, args) -> handler.apply(method.getName(), args));
    }
}
