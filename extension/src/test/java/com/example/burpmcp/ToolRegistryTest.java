package com.example.burpmcp;

import org.junit.Test;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class ToolRegistryTest {
    @Test
    public void registryHasStableUniqueOrderAndVersionCount() {
        List<ToolDescriptor> descriptors = ToolRegistry.descriptors();
        List<String> names = descriptors.stream().map(ToolDescriptor::getName).collect(Collectors.toList());
        Set<String> uniqueNames = new HashSet<>(names);

        assertEquals("burp_help", names.get(0));
        assertEquals(Version.TOOL_COUNT, descriptors.size());
        assertEquals(descriptors.size(), uniqueNames.size());
        assertEquals(22, ToolRegistry.documentationDescriptors().size());
        assertFalse(ToolRegistry.get("burp_help").isIncludedInHelpDocs());
    }

    @Test
    public void registryIsAuthoritativeForActionRequirements() {
        ToolDescriptor session = ToolRegistry.get("burp_session_management");
        assertNotNull(session);

        Map<String, List<String>> requirements = session.getActionRequirements();
        assertEquals(List.of("tokenName", "tokenValue", "domain"), requirements.get("COOKIE_JAR_SET"));
        assertEquals(List.of("tokenName", "domain"), requirements.get("COOKIE_JAR_DELETE"));

        ToolDocumentation doc = ToolDocumentationStore.getInstance().getDocumentation("burp_session_management");
        assertNotNull(doc);
        assertEquals(requirements, doc.getActionRequirements());
    }

    @Test
    public void registryCanCreateKnownStandaloneTool() {
        McpTool tool = ToolRegistry.createTool("burp_session_management", null);
        assertTrue(tool instanceof SessionManagementTool);
        assertEquals(null, ToolRegistry.createTool("missing", null));
    }
}
