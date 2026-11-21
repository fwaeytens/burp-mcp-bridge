package com.example.burpmcp;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.After;
import org.junit.Test;

import java.lang.reflect.Field;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

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
