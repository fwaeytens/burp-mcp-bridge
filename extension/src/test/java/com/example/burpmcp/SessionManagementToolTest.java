package com.example.burpmcp;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.Test;

import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;

public class SessionManagementToolTest {
    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    @SuppressWarnings("unchecked")
    public void singletonStatePersistsAcrossCallsAndIsClearedOnClose() throws Exception {
        SessionManagementTool tool = new SessionManagementTool(null);

        ObjectNode setToken = mapper.createObjectNode();
        setToken.put("action", "SET_TOKEN");
        setToken.put("tokenName", "session");
        setToken.put("tokenValue", "abc123");
        tool.execute(setToken);

        Map<String, Object> beforeClose = structured(tool.execute(action("LIST_TOKENS")));
        assertEquals(1, beforeClose.get("tokenCount"));
        List<Map<String, Object>> tokens = (List<Map<String, Object>>) beforeClose.get("tokens");
        assertEquals("session", tokens.get(0).get("name"));
        assertEquals("abc123", tokens.get(0).get("value"));

        tool.close();

        Map<String, Object> afterClose = structured(tool.execute(action("LIST_TOKENS")));
        assertEquals(0, afterClose.get("tokenCount"));
    }

    private ObjectNode action(String action) {
        ObjectNode node = mapper.createObjectNode();
        node.put("action", action);
        return node;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> structured(Object response) {
        return (Map<String, Object>) ((Map<String, Object>) response).get("structuredContent");
    }
}
