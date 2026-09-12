package com.example.burpmcp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.fasterxml.jackson.databind.JsonNode;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Validates and prepares finite HTTP jobs before any request can be queued. */
final class HttpJobRequests {
    static final int MAX_REQUESTS = 1000;
    static final int MAX_INPUT_CHARACTERS = 10 * 1024 * 1024;
    private static final Pattern METHOD = Pattern.compile("[!#$%&'*+.^_`|~0-9A-Za-z-]+");
    private static final Pattern VERSION = Pattern.compile("HTTP/[0-9]+(?:\\.[0-9]+)?");
    // Atomic grouping keeps one CRLF from backtracking into two separate newlines.
    private static final Pattern HEADER_END = Pattern.compile("(?>\\r\\n|\\n|\\r){2}");

    private final CustomHttpTool requestBuilder;

    HttpJobRequests(MontoyaApi api) {
        requestBuilder = new CustomHttpTool(api);
    }

    List<HttpRequest> prepare(JsonNode arguments) {
        // Validate the entire batch before invoking a Montoya factory for its first entry.
        List<PreparedInput> inputs = validatedInputs(arguments);
        List<HttpRequest> requests = new ArrayList<>(inputs.size());
        for (int i = 0; i < inputs.size(); i++) {
            PreparedInput input = inputs.get(i);
            try {
                requests.add(requestBuilder.prepareJobRequest(input.request(), input.useHttps()));
            } catch (Exception e) {
                throw new IllegalArgumentException("requests[" + i + "] could not be prepared: " + e.getMessage(), e);
            }
        }
        return requests;
    }

    static void validate(JsonNode arguments) {
        validatedInputs(arguments);
    }

    private static List<PreparedInput> validatedInputs(JsonNode arguments) {
        if (arguments == null || !arguments.isObject()) {
            throw new IllegalArgumentException("HTTP job arguments must be an object");
        }
        JsonNode entries = arguments.get("requests");
        if (entries == null || !entries.isArray() || entries.size() < 1 || entries.size() > MAX_REQUESTS) {
            throw new IllegalArgumentException("requests must be an array containing 1-1000 strings");
        }
        if (arguments.has("use_https") && !arguments.get("use_https").isBoolean()) {
            throw new IllegalArgumentException("use_https must be a boolean");
        }
        Boolean useHttps = arguments.has("use_https") ? arguments.get("use_https").booleanValue() : null;

        long totalCharacters = 0;
        for (int i = 0; i < entries.size(); i++) {
            JsonNode entry = entries.get(i);
            if (!entry.isTextual() || entry.textValue().isBlank()) {
                throw invalid(i, "must be a nonempty raw HTTP request or absolute http(s) URL");
            }
            // A character bounds a Latin-1 encoded input byte; count before normalization,
            // URI conversion, or Montoya parsing can allocate additional representations.
            totalCharacters += entry.textValue().length();
            if (totalCharacters > MAX_INPUT_CHARACTERS) {
                throw new IllegalArgumentException("requests exceed the 10 MiB total input limit");
            }
        }

        List<PreparedInput> inputs = new ArrayList<>(entries.size());
        long preparedCharacters = 0;
        for (int i = 0; i < entries.size(); i++) {
            String entry = entries.get(i).textValue();
            PreparedInput input;
            if (isHttpUrl(entry)) {
                ValidatedUrl url = validatedUrl(entry, i);
                URI uri = URI.create(url.uri().toASCIIString());
                String host = url.host();
                boolean secure = "https".equalsIgnoreCase(uri.getScheme());
                int port = url.port() == -1 ? (secure ? 443 : 80) : url.port();
                String path = uri.getRawPath();
                if (path == null || path.isEmpty()) path = "/";
                if (uri.getRawQuery() != null) path += "?" + uri.getRawQuery();
                String authority = (host.contains(":") ? "[" + host + "]" : host) + ":" + port;
                input = new PreparedInput("GET " + path + " HTTP/1.1\r\nHost: " + authority + "\r\n\r\n", secure);
            } else {
                input = new PreparedInput(validateRawRequest(entry, i), useHttps);
            }
            // URL percent encoding, synthesized Host headers and CRLF normalization
            // can grow an otherwise-valid input batch. Bound that representation too,
            // still before the first Montoya factory call in prepare(). Raw Latin-1
            // body characters retain their one-byte accounting rather than UTF-8 size.
            preparedCharacters += input.request().length();
            if (preparedCharacters > MAX_INPUT_CHARACTERS) {
                throw new IllegalArgumentException("prepared requests exceed the 10 MiB total limit after encoding or header normalization");
            }
            inputs.add(input);
        }
        return inputs;
    }

    private static String validateRawRequest(String request, int index) {
        Matcher separator = HEADER_END.matcher(request);
        boolean hasBodySeparator = separator.find();
        String headers = hasBodySeparator ? request.substring(0, separator.start()) : request;
        String body = hasBodySeparator ? request.substring(separator.end()) : null;
        headers = headers.replace("\r\n", "\n").replace('\r', '\n');
        String[] lines = headers.split("\n", -1);
        String[] firstLine = lines[0].split(" ", -1);
        if (firstLine.length != 3 || !METHOD.matcher(firstLine[0]).matches()
                || firstLine[1].isEmpty() || !VERSION.matcher(firstLine[2]).matches()) {
            throw invalid(index, "has an invalid HTTP request line");
        }
        String target = firstLine[1];
        if (target.chars().anyMatch(c -> Character.isISOControl(c) || Character.isWhitespace(c)
                || Character.isSpaceChar(c))) {
            throw invalid(index, "request target must not contain whitespace or control characters");
        }
        if (target.indexOf('#') >= 0) {
            throw invalid(index, "request target must not contain a fragment");
        }
        URI targetUrl = null;
        if (isHttpUrl(target)) {
            targetUrl = validatedUrl(target, index).uri();
            firstLine[1] = targetUrl.toASCIIString();
        } else if ("CONNECT".equalsIgnoreCase(firstLine[0])) {
            validatedAuthority(target, index);
        } else if (!(target.startsWith("/") || target.equals("*"))) {
            throw invalid(index, "request target must be an origin path, *, or an absolute http(s) URL");
        } else {
            try {
                firstLine[1] = new URI(target).toASCIIString();
            } catch (URISyntaxException e) {
                throw invalid(index, "contains a malformed request target: " + e.getReason());
            }
        }
        lines[0] = String.join(" ", firstLine);

        String host = null;
        for (int i = 1; i < lines.length; i++) {
            if (lines[i].regionMatches(true, 0, "Host:", 0, 5)) {
                host = lines[i].substring(5).trim();
                // Match CustomHttpTool's first-Host destination selection.
                validatedAuthority(host, index);
                break;
            }
        }
        if (host == null && targetUrl == null) {
            throw invalid(index, "requires a Host header or an absolute http(s) request target");
        }
        if (host == null) {
            // Give the shared builder an explicit header so a body line named Host
            // cannot become the destination of an absolute-form request without Host.
            List<String> withHost = new ArrayList<>(Arrays.asList(lines));
            withHost.add(1, "Host: " + targetUrl.getRawAuthority());
            lines = withHost.toArray(String[]::new);
        }
        String normalizedHeaders = String.join("\r\n", lines);
        return body == null ? normalizedHeaders : normalizedHeaders + "\r\n\r\n" + body;
    }

    private static URI validatedAuthority(String authority, int index) {
        URI uri = validatedUrl("http://" + authority, index).uri();
        if (uri.getRawPath() != null && !uri.getRawPath().isEmpty()
                || uri.getRawQuery() != null || uri.getRawFragment() != null) {
            throw invalid(index, "Host must contain only a hostname or IP address and optional port");
        }
        return uri;
    }

    private static ValidatedUrl validatedUrl(String value, int index) {
        final URI uri;
        try {
            uri = new URI(value);
        } catch (URISyntaxException e) {
            throw invalid(index, "contains a malformed URL: " + e.getReason());
        }
        String scheme = uri.getScheme();
        if (scheme == null || !(scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase("https"))) {
            throw invalid(index, "URL scheme must be http or https");
        }
        String authority = uri.getRawAuthority();
        if (authority == null || authority.isEmpty()) {
            throw invalid(index, "URL requires a valid hostname or IP address");
        }
        // URI treats underscore hosts as registry authorities, so getRawUserInfo()
        // alone cannot detect credentials in those authorities.
        if (uri.getRawUserInfo() != null || authority.indexOf('@') >= 0) {
            throw invalid(index, "URL user information is unsupported; supply an Authorization header in a raw request");
        }
        String host = uri.getHost();
        int port = uri.getPort();
        if (host == null && authority.indexOf('_') >= 0) {
            // Permit underscores in hostname labels without accepting arbitrary URI
            // registry authorities. A same-length substitution lets URI enforce its
            // existing hostname, bracket and numeric-port rules for everything else.
            try {
                URI checked = new URI("http://" + authority.replace('_', 'a')).parseServerAuthority();
                if (checked.getHost() != null && !checked.getHost().startsWith("[")) {
                    int colon = authority.indexOf(':');
                    host = colon < 0 ? authority : authority.substring(0, colon);
                    port = checked.getPort();
                }
            } catch (URISyntaxException e) {
                throw invalid(index, "URL requires a valid hostname or IP address and optional numeric port");
            }
        }
        if (host == null || host.isEmpty()) {
            throw invalid(index, "URL requires a valid hostname or IP address");
        }
        if (port == 0 || port > 65535 || authority.endsWith(":")) {
            throw invalid(index, "URL port must be between 1 and 65535");
        }
        return new ValidatedUrl(uri, unbracket(host), port);
    }

    private static boolean isHttpUrl(String value) {
        String lower = value.length() > 8 ? value.substring(0, 8).toLowerCase(Locale.ROOT) : value.toLowerCase(Locale.ROOT);
        return lower.startsWith("http://") || lower.startsWith("https://");
    }

    private static String unbracket(String host) {
        return host.startsWith("[") && host.endsWith("]") ? host.substring(1, host.length() - 1) : host;
    }

    private static IllegalArgumentException invalid(int index, String message) {
        return new IllegalArgumentException("requests[" + index + "] " + message);
    }

    private record ValidatedUrl(URI uri, String host, int port) {}

    private record PreparedInput(String request, Boolean useHttps) {}
}
