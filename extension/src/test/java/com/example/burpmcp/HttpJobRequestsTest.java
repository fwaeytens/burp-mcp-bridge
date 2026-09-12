package com.example.burpmcp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.internal.MontoyaObjectFactory;
import burp.api.montoya.internal.ObjectFactoryLocator;
import burp.api.montoya.logging.Logging;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class HttpJobRequestsTest {
    private final ObjectMapper mapper = new ObjectMapper();
    private MontoyaObjectFactory originalFactory;
    private HttpJobRequests preparation;
    private int factoryCalls;

    @Before
    public void setUp() {
        originalFactory = ObjectFactoryLocator.FACTORY;
        ObjectFactoryLocator.FACTORY = stub(MontoyaObjectFactory.class, (proxy, method, args) -> {
            factoryCalls++;
            if (method.getName().equals("httpService") && args.length == 3) {
                return new Service((String) args[0], (int) args[1], (boolean) args[2]);
            }
            if (method.getName().equals("httpRequest") && args.length == 2 && args[1] instanceof String raw) {
                HttpService service = (HttpService) args[0];
                return stub(HttpRequest.class, (requestProxy, requestMethod, requestArgs) -> switch (requestMethod.getName()) {
                    case "httpService" -> service;
                    case "toString" -> raw;
                    default -> throw new AssertionError("Unexpected request operation: " + requestMethod.getName());
                });
            }
            throw new AssertionError("Unexpected Montoya factory operation: " + method);
        });
        Logging logging = stub(Logging.class, (proxy, method, args) -> null);
        MontoyaApi api = stub(MontoyaApi.class, (proxy, method, args) -> {
            if (method.getName().equals("logging")) return logging;
            throw new AssertionError("Preparation accessed browser state or network: " + method.getName());
        });
        preparation = new HttpJobRequests(api);
    }

    @After
    public void tearDown() {
        ObjectFactoryLocator.FACTORY = originalFactory;
    }

    @Test
    public void urlEntriesUseTheirSchemeAndPreserveEscapedPathQueryAndIpv6() throws Exception {
        ObjectNode arguments = requests("http://example.test?x=%2F%20", "https://example.test:8443/a%2Fb",
            "https://[::1]/a", "HTTP://Example.test/path#local-fragment");
        arguments.put("use_https", false);
        List<HttpRequest> prepared = preparation.prepare(arguments);

        assertService(prepared.get(0), "example.test", 80, false);
        assertEquals("GET /?x=%2F%20 HTTP/1.1\r\nHost: example.test:80\r\n\r\n", prepared.get(0).toString());
        assertService(prepared.get(1), "example.test", 8443, true);
        assertTrue(prepared.get(1).toString().startsWith("GET /a%2Fb HTTP/1.1\r\n"));
        assertService(prepared.get(2), "::1", 443, true);
        assertTrue(prepared.get(2).toString().contains("Host: [::1]:443\r\n"));
        assertService(prepared.get(3), "Example.test", 80, false);
        assertFalse(prepared.get(3).toString().contains("#local-fragment"));
    }

    @Test
    public void unicodeTargetsBecomeAsciiUrisWithoutDoubleEncodingEscapes() {
        List<HttpRequest> prepared = preparation.prepare(requests(
            "https://example.test/雪?q=é&escaped=%2F",
            "GET /雪?q=é&escaped=%2F HTTP/1.1\r\nHost: example.test\r\n\r\n",
            "GET https://example.test/雪?q=é&escaped=%2F HTTP/1.1\r\nHost: example.test\r\n\r\n"));

        for (HttpRequest request : prepared) {
            assertTrue(request.toString().startsWith("GET /%E9%9B%AA?q=%C3%A9&escaped=%2F HTTP/1.1\r\n"));
            assertService(request, "example.test", 443, true);
        }
    }

    @Test
    public void omittedTlsChoiceInfersPort80AndPreservesRawRequest() throws Exception {
        String raw = "POST /login HTTP/1.1\nHost: example.test:80\nCookie: session=explicit\nX-Test: value\n\nbody";
        HttpRequest prepared = preparation.prepare(requests(raw)).get(0);
        assertService(prepared, "example.test", 80, false);
        assertEquals(raw.replace("\n", "\r\n"), prepared.toString());

        List<HttpRequest> defaults = preparation.prepare(requests(
            "GET / HTTP/1.1\r\nHost: example.test:443\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: example.test:8080\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"));
        assertService(defaults.get(0), "example.test", 443, true);
        assertService(defaults.get(1), "example.test", 8080, true);
        assertService(defaults.get(2), "example.test", 443, true);
    }

    @Test
    public void explicitTlsChoiceOverridesPortInferenceButKeepsExplicitPorts() {
        for (boolean secure : new boolean[]{false, true}) {
            ObjectNode arguments = requests(
                "GET / HTTP/1.1\r\nHost: example.test:80\r\n\r\n",
                "GET / HTTP/1.1\r\nHost: example.test:443\r\n\r\n",
                "GET / HTTP/1.1\r\nHost: example.test:8080\r\n\r\n",
                "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n");
            arguments.put("use_https", secure);
            List<HttpRequest> prepared = preparation.prepare(arguments);

            assertService(prepared.get(0), "example.test", 80, secure);
            assertService(prepared.get(1), "example.test", 443, secure);
            assertService(prepared.get(2), "example.test", 8080, secure);
            assertService(prepared.get(3), "example.test", secure ? 443 : 80, secure);
        }
    }

    @Test
    public void urlAndAbsoluteTargetSchemesOverrideEitherExplicitTlsChoice() {
        for (boolean secure : new boolean[]{false, true}) {
            ObjectNode arguments = requests("http://example.test:443/", "https://example.test:80/",
                "GET http://example.test:443/ HTTP/1.1\r\nHost: example.test:443\r\n\r\n",
                "GET https://example.test:80/ HTTP/1.1\r\nHost: example.test:80\r\n\r\n");
            arguments.put("use_https", secure);
            List<HttpRequest> prepared = preparation.prepare(arguments);

            assertService(prepared.get(0), "example.test", 443, false);
            assertService(prepared.get(1), "example.test", 80, true);
            assertService(prepared.get(2), "example.test", 443, false);
            assertService(prepared.get(3), "example.test", 80, true);
        }
    }

    @Test
    public void underscoreUrlHostsPreservePortsCaseAndEscapedTargets() {
        ObjectNode arguments = requests("http://service_api:8080/a%2Fb?q=%2F",
            "https://_internal.example_test./雪", "HTTP://API_name/path", "http://service_api:8080?x=%2F");
        arguments.put("use_https", false);
        List<HttpRequest> prepared = preparation.prepare(arguments);

        assertService(prepared.get(0), "service_api", 8080, false);
        assertEquals("GET /a%2Fb?q=%2F HTTP/1.1\r\nHost: service_api:8080\r\n\r\n", prepared.get(0).toString());
        assertService(prepared.get(1), "_internal.example_test.", 443, true);
        assertTrue(prepared.get(1).toString().startsWith("GET /%E9%9B%AA HTTP/1.1\r\n"));
        assertService(prepared.get(2), "API_name", 80, false);
        assertService(prepared.get(3), "service_api", 8080, false);
        assertTrue(prepared.get(3).toString().startsWith("GET /?x=%2F HTTP/1.1\r\n"));
    }

    @Test
    public void underscoreRawHostAndConnectAuthoritiesRemainValid() {
        List<HttpRequest> prepared = preparation.prepare(requests(
            "GET / HTTP/1.1\r\nHost: service_api:80\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: _internal.example_test\r\n\r\n",
            "CONNECT service_api:443 HTTP/1.1\r\nHost: service_api:443\r\n\r\n"));

        assertService(prepared.get(0), "service_api", 80, false);
        assertService(prepared.get(1), "_internal.example_test", 443, true);
        assertService(prepared.get(2), "service_api", 443, true);
        assertTrue(prepared.get(2).toString().startsWith("CONNECT service_api:443 HTTP/1.1\r\n"));
    }

    @Test
    public void underscoreAbsoluteTargetsKeepSchemeAndHostHeaderPrecedence() {
        ObjectNode arguments = requests(
            "GET https://uri_name:8443/path HTTP/1.1\r\nHost: header_name:8080\r\n\r\n",
            "GET http://uri_name:8080/path HTTP/1.1\r\n\r\n",
            "GET http://Uri_Name:8080/path HTTP/1.1\r\nHost: uri_name\r\n\r\n");
        arguments.put("use_https", true);
        List<HttpRequest> prepared = preparation.prepare(arguments);

        assertService(prepared.get(0), "header_name", 8080, true);
        assertService(prepared.get(1), "uri_name", 8080, false);
        assertService(prepared.get(2), "uri_name", 8080, false);
        assertTrue(prepared.get(1).toString().contains("\r\nHost: uri_name:8080\r\n"));
        for (HttpRequest request : prepared) {
            assertTrue(request.toString().startsWith("GET /path HTTP/1.1\r\n"));
        }
    }

    @Test
    public void postBodyAndContentLengthSurviveHeaderNormalizationAndOriginRewrite() {
        String body = "first\nsecond\rthird\r\nHost: body.test:9999\u0000\u00ff";
        for (String ending : new String[]{"\n", "\r\n", "\r"}) {
            String raw = "POST http://expected.test:8080/path HTTP/1.1" + ending
                + "Host: expected.test:8080" + ending
                + "Content-Length: " + body.length() + ending + ending + body;
            HttpRequest prepared = preparation.prepare(requests(raw)).get(0);

            assertService(prepared, "expected.test", 8080, false);
            assertEquals("POST /path HTTP/1.1\r\nHost: expected.test:8080\r\nContent-Length: "
                + body.length() + "\r\n\r\n" + body, prepared.toString());
        }
    }

    @Test
    public void rawAbsoluteTargetsKeepSchemeAndFirstHostDestinationPrecedence() throws Exception {
        ObjectNode arguments = requests("GET https://uri.test:8443/path HTTP/1.1\r\nHost: header.test:8080\r\n\r\n",
            "GET http://uri.test:8080/path HTTP/1.1\r\nHost: uri.test\r\n\r\n");
        arguments.put("use_https", false);
        List<HttpRequest> prepared = preparation.prepare(arguments);

        assertService(prepared.get(0), "header.test", 8080, true);
        assertTrue(prepared.get(0).toString().startsWith("GET /path HTTP/1.1\r\n"));
        assertService(prepared.get(1), "uri.test", 8080, false);
    }

    @Test
    public void absoluteTargetWithoutHostDoesNotUseHostTextFromBody() throws Exception {
        String raw = "POST http://expected.test:8080/path HTTP/1.1\r\nContent-Type: text/plain\r\n\r\nHost: body.test:9999";
        HttpRequest prepared = preparation.prepare(requests(raw)).get(0);

        assertService(prepared, "expected.test", 8080, false);
        assertTrue(prepared.toString().contains("\r\nHost: expected.test:8080\r\n"));
        assertTrue(prepared.toString().endsWith("\r\n\r\nHost: body.test:9999"));
    }

    @Test
    public void validatesTheEntireBatchBeforeAnyMontoyaParsing() {
        ObjectNode arguments = requests("https://valid.test/", "https://bad.test:70000/");
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class, () -> preparation.prepare(arguments));

        assertTrue(error.getMessage().contains("requests[1]"));
        assertEquals(0, factoryCalls);
    }

    @Test
    public void rejectsMalformedUrlsAndHostHeadersBeforeMontoyaParsing() {
        String[] invalid = {"http://", "https:///path", "ftp://example.test/", "https://example.test:0/",
            "https://example.test:/", "http://[::1/path", "https://bad host/", "https://example.test/%ZZ",
            "https://user:pass@example.test/", "GET / HTTP/1.1\r\nHost: example.test/path\r\n\r\n",
            "GET / HTTP/1.1\r\n\r\nHost: body.test", "GET / HTTP/1.1\r\nHost: example.test:70000\r\n\r\n",
            "GET file:///etc/passwd HTTP/1.1\r\nHost: example.test\r\n\r\n"};
        for (String input : invalid) {
            assertThrows(input, IllegalArgumentException.class, () -> preparation.prepare(requests(input)));
        }
        assertEquals(0, factoryCalls);
    }

    @Test
    public void underscoreFallbackRejectsMalformedAuthoritiesBeforeParsingTheBatch() {
        String[] authorities = {"user@bad_name", "user:pass@bad_name", "bad_name:80@other.test",
            "bad_name:abc", "bad_name:", "bad_name:0", "bad_name:65536", "bad_name:2147483648",
            "bad_name:-1", "bad_name:+80", "bad_name::80", "bad_name:%38%30", "valid.test:8_0", "[bad_name]:80",
            "bad_name]", "bad%40_name", "bad%2f_name", "bad%3a_name", "bad%20_name", "bad_ name",
            "bad_name..test", ".bad_name", "bad_name..", "-bad_name", "bad_name-", "bad_name.-label"};
        for (String authority : authorities) {
            String[] forms = {"http://" + authority + "/path",
                "GET / HTTP/1.1\r\nHost: " + authority + "\r\n\r\n",
                "GET http://" + authority + "/path HTTP/1.1\r\n\r\n",
                "CONNECT " + authority + " HTTP/1.1\r\nHost: valid.test:443\r\n\r\n"};
            for (String input : forms) {
                IllegalArgumentException error = assertThrows(input, IllegalArgumentException.class,
                    () -> preparation.prepare(requests("https://valid.test/", input)));
                assertTrue(error.getMessage(), error.getMessage().contains("requests[1]"));
            }
        }
        for (String authority : new String[]{"bad_name/path", "bad_name?query=value", "bad_name#fragment"}) {
            assertThrows(authority, IllegalArgumentException.class,
                () -> preparation.prepare(requests("https://valid.test/",
                    "GET / HTTP/1.1\r\nHost: " + authority + "\r\n\r\n")));
        }
        assertEquals(0, factoryCalls);
    }

    @Test
    public void rejectsMalformedRawTargetsAndUrlWhitespaceBeforeParsingAnyEntry() {
        String[] targets = {"/bad\u0000path", "/bad\u007fpath", "/bad\u0085path", "/bad\tpath",
            "/bad\u00a0path", "/path#fragment", "/bad%ZZ", "/bad%", "/bad%0"};
        for (String target : targets) {
            ObjectNode batch = requests("https://valid.test/", "GET " + target
                + " HTTP/1.1\r\nHost: example.test\r\n\r\n");
            assertThrows(target, IllegalArgumentException.class, () -> preparation.prepare(batch));
        }
        for (String url : new String[]{" https://example.test/", "https://example.test/ ",
                "https://example.test/a b", "https://example.test/a\t"}) {
            assertThrows(url, IllegalArgumentException.class,
                () -> preparation.prepare(requests("https://valid.test/", url)));
        }
        assertEquals(0, factoryCalls);
    }

    @Test
    public void validatesArraySizeTypesAndBooleanStrictly() {
        assertThrows(IllegalArgumentException.class, () -> HttpJobRequests.validate(null));
        assertThrows(IllegalArgumentException.class, () -> HttpJobRequests.validate(mapper.createObjectNode()));
        assertThrows(IllegalArgumentException.class, () -> HttpJobRequests.validate(requests()));
        assertThrows(IllegalArgumentException.class, () -> HttpJobRequests.validate(requests(" ")));
        ObjectNode wrongEntry = requests("https://example.test/");
        ((ArrayNode) wrongEntry.get("requests")).add(42);
        assertThrows(IllegalArgumentException.class, () -> HttpJobRequests.validate(wrongEntry));
        ObjectNode wrongBoolean = requests("https://example.test/");
        wrongBoolean.put("use_https", "false");
        assertThrows(IllegalArgumentException.class, () -> HttpJobRequests.validate(wrongBoolean));
        wrongBoolean.putNull("use_https");
        assertThrows(IllegalArgumentException.class, () -> HttpJobRequests.validate(wrongBoolean));

        ObjectNode max = requests();
        ArrayNode array = (ArrayNode) max.get("requests");
        for (int i = 0; i < HttpJobRequests.MAX_REQUESTS; i++) array.add("https://example.test/");
        HttpJobRequests.validate(max);
        array.add("https://example.test/");
        assertThrows(IllegalArgumentException.class, () -> HttpJobRequests.validate(max));
        assertEquals(0, factoryCalls);
    }

    @Test
    public void enforcesAggregateTenMiBInputLimitBeforeParsing() {
        String prefix = "POST / HTTP/1.1\r\nHost: example.test\r\n\r\n";
        String exact = prefix + "x".repeat(HttpJobRequests.MAX_INPUT_CHARACTERS - prefix.length());
        HttpJobRequests.validate(requests(exact));
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
            () -> preparation.prepare(requests(exact, "https://example.test/")));

        assertTrue(error.getMessage().contains("10 MiB"));
        assertEquals(0, factoryCalls);
    }

    @Test
    public void rejectsUnicodeExpansionAbovePreparedBatchLimitBeforeMontoyaParsing() {
        String url = "https://example.test/" + "é".repeat(HttpJobRequests.MAX_INPUT_CHARACTERS / 12);
        assertTrue((long) url.length() * 2 < HttpJobRequests.MAX_INPUT_CHARACTERS);

        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
            () -> preparation.prepare(requests(url, url)));

        assertTrue(error.getMessage().contains("prepared requests exceed the 10 MiB"));
        assertEquals(0, factoryCalls);
    }

    private ObjectNode requests(String... entries) {
        ObjectNode arguments = mapper.createObjectNode();
        ArrayNode requests = arguments.putArray("requests");
        for (String entry : entries) requests.add(entry);
        return arguments;
    }

    private static void assertService(HttpRequest request, String host, int port, boolean secure) {
        assertEquals(host, request.httpService().host());
        assertEquals(port, request.httpService().port());
        assertEquals(secure, request.httpService().secure());
    }

    @SuppressWarnings("unchecked")
    private static <T> T stub(Class<T> type, InvocationHandler handler) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, handler);
    }

    private record Service(String host, int port, boolean secure) implements HttpService {
        @Override
        public String ipAddress() {
            throw new AssertionError("Preparation attempted DNS resolution");
        }
    }
}
