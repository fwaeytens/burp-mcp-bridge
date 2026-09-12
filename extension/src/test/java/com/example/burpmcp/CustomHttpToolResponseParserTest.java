package com.example.burpmcp;

import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class CustomHttpToolResponseParserTest {
    private final CustomHttpTool tool = new CustomHttpTool(null);

    @Test
    public void rejectsOversizedContentLengthWithoutReadingBody() throws Exception {
        for (long length : new long[]{50_000_001L, Integer.MAX_VALUE, Long.MAX_VALUE}) {
            String response = "HTTP/1.1 200 OK\r\nContent-Length: " + length + "\r\n\r\n";
            List<?> parsed = parse(new ExactInput(response), 1, true, List.of("GET"));

            assertEquals(1, parsed.size());
            assertEquals("content length out of bounds: " + length, field(parsed.get(0), "parseError"));
            assertArrayEquals(bytes(response), (byte[]) field(parsed.get(0), "rawBytes"));
            assertEquals(0, ((byte[]) field(parsed.get(0), "body")).length);
        }
    }

    @Test
    public void bodylessResponsesIgnoreLengthAndTransferCodingOnKeepalive() throws Exception {
        String[] responses = {
            "HTTP/1.1 200 OK\r\nContent-Length: 2147483647\r\n\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
            "HTTP/1.1 304 Not Modified\r\nContent-Length: 12\r\n\r\n",
            "HTTP/1.1 204 No Content\r\nTransfer-Encoding: chunked\r\n\r\n"
        };
        String[] methods = {"HEAD", "HEAD", "GET", "GET"};
        for (int i = 0; i < responses.length; i++) {
            List<?> parsed = parse(new ExactInput(responses[i]), 1, true, List.of(methods[i]));

            assertEquals(1, parsed.size());
            assertNull(field(parsed.get(0), "parseError"));
            assertEquals(0, ((byte[]) field(parsed.get(0), "body")).length);
            assertArrayEquals(bytes(responses[i]), (byte[]) field(parsed.get(0), "rawBytes"));
        }
    }

    @Test
    public void headAndNotModifiedResponsesPreserveNextPipelinedResponse() throws Exception {
        String next = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
        String[] first = {
            "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n",
            "HTTP/1.1 304 Not Modified\r\nContent-Length: 12\r\n\r\n"
        };
        String[] methods = {"HEAD", "GET"};
        for (int i = 0; i < first.length; i++) {
            List<?> parsed = parse(new ExactInput(first[i] + next), 2, false, List.of(methods[i], "GET"));

            assertEquals(2, parsed.size());
            assertArrayEquals(bytes(first[i]), (byte[]) field(parsed.get(0), "rawBytes"));
            assertArrayEquals(bytes(next), (byte[]) field(parsed.get(1), "rawBytes"));
            assertArrayEquals(bytes("OK"), (byte[]) field(parsed.get(1), "body"));
            assertNull(field(parsed.get(1), "parseError"));
        }
    }

    @Test
    public void informationalResponsesKeepMethodAssociationAndRawBytes() throws Exception {
        String interim = "HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n";
        String head = "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n";
        String get = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
        List<?> parsed = parse(new ExactInput(interim + head + get), 2, false, List.of("HEAD", "GET"));

        assertEquals(2, parsed.size());
        assertEquals(200, field(parsed.get(0), "statusCode"));
        assertEquals(0, ((byte[]) field(parsed.get(0), "body")).length);
        assertArrayEquals(bytes(interim + head), (byte[]) field(parsed.get(0), "rawBytes"));
        assertArrayEquals(bytes(head), (byte[]) field(parsed.get(0), "finalResponseBytes"));
        assertArrayEquals(bytes(get), (byte[]) field(parsed.get(1), "rawBytes"));
        assertArrayEquals(bytes("OK"), (byte[]) field(parsed.get(1), "body"));
    }

    @Test
    public void continueDoesNotReplaceTheFinalPostResponse() throws Exception {
        String interim = "HTTP/1.1 100 Continue\r\n\r\n";
        String response = "HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nOK";
        List<?> parsed = parse(new ExactInput(interim + response), 1, true, List.of("POST"));

        assertEquals(1, parsed.size());
        assertEquals(201, field(parsed.get(0), "statusCode"));
        assertArrayEquals(bytes("OK"), (byte[]) field(parsed.get(0), "body"));
        assertArrayEquals(bytes(interim + response), (byte[]) field(parsed.get(0), "rawBytes"));
    }

    @Test
    public void missingFinalResponseRetainsInformationalBytes() throws Exception {
        String interim = "HTTP/1.1 100 Continue\r\n\r\n";
        List<?> parsed = parse(new ByteArrayInputStream(bytes(interim)), 1, true, List.of("POST"));

        assertEquals(1, parsed.size());
        assertEquals("connection closed before final response", field(parsed.get(0), "parseError"));
        assertArrayEquals(bytes(interim), (byte[]) field(parsed.get(0), "rawBytes"));
    }

    @Test
    public void repeatedInformationalResponsesAreBounded() throws Exception {
        String wire = "HTTP/1.1 100 Continue\r\n\r\n".repeat(101);
        List<?> parsed = parse(new ExactInput(wire), 1, true, List.of("POST"));

        assertEquals(1, parsed.size());
        assertEquals("too many informational responses before final response", field(parsed.get(0), "parseError"));
        assertArrayEquals(bytes(wire), (byte[]) field(parsed.get(0), "rawBytes"));
    }

    @Test
    public void protocolUpgradeLeavesNonHttpBytesUnread() throws Exception {
        String response = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n";
        ExactInput input = new ExactInput(response + "frame");
        List<?> parsed = parse(input, 2, false, List.of("GET", "GET"));

        assertEquals(1, parsed.size());
        assertEquals(101, field(parsed.get(0), "statusCode"));
        assertEquals(5, input.available());
        assertArrayEquals(bytes(response), (byte[]) field(parsed.get(0), "rawBytes"));
    }

    @Test
    public void fragmentedBodiesKeepLengthAndChunkedPipelineBoundaries() throws Exception {
        String first = "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789";
        String second = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
            + "4\r\nWiki\r\n5\r\npedia\r\n0\r\nTrailer: value\r\n\r\n";
        ExactInput input = new ExactInput(first + second);
        List<?> parsed = parse(input, 2, false, List.of("GET", "GET"));

        assertEquals(2, parsed.size());
        assertArrayEquals(bytes("0123456789"), (byte[]) field(parsed.get(0), "body"));
        assertArrayEquals(bytes("Wikipedia"), (byte[]) field(parsed.get(1), "body"));
        assertArrayEquals(bytes(first), (byte[]) field(parsed.get(0), "rawBytes"));
        assertArrayEquals(bytes(second), (byte[]) field(parsed.get(1), "rawBytes"));
        assertTrue(input.bulkReads > 2);
    }

    private List<?> parse(InputStream in, int expected, boolean closeFraming, List<String> methods) throws Exception {
        Method parser = CustomHttpTool.class.getDeclaredMethod("parseResponseStream", InputStream.class,
            int.class, int.class, boolean.class, List.class);
        parser.setAccessible(true);
        return (List<?>) parser.invoke(tool, in, expected, 100, closeFraming, methods);
    }

    private static Object field(Object response, String name) throws Exception {
        Field field = response.getClass().getDeclaredField(name);
        field.setAccessible(true);
        return field.get(response);
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.ISO_8859_1);
    }

    /** A persistent connection: reading past supplied bytes would block for its timeout. */
    private static final class ExactInput extends ByteArrayInputStream {
        int bulkReads;

        ExactInput(String response) {
            super(bytes(response));
        }

        @Override
        public synchronized int read() {
            if (available() == 0) throw new AssertionError("Parser read past the response boundary");
            return super.read();
        }

        @Override
        public synchronized int read(byte[] buffer, int offset, int length) {
            if (available() == 0) throw new AssertionError("Parser read past the response boundary");
            bulkReads++;
            return super.read(buffer, offset, Math.min(length, 3));
        }
    }
}
