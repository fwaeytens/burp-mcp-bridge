package com.example.burpmcp;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.Iterator;
import java.util.Map;

import static org.junit.Assert.*;

/** Assertions for the JSON Schema keywords used by the tool result contracts. */
final class OutputSchemaAssertions {
    private OutputSchemaAssertions() {}

    static void assertMatches(JsonNode schema, JsonNode value) {
        assertMatches(schema, value, "$", false);
    }

    static void assertDocumented(JsonNode schema, JsonNode value) {
        assertMatches(schema, value, "$", true);
    }

    private static void assertMatches(JsonNode schema, JsonNode value, String path, boolean documented) {
        if (schema.isBoolean()) { assertTrue(path + " is forbidden", schema.asBoolean()); return; }
        if (schema.has("anyOf") || schema.has("oneOf")) {
            JsonNode choices = schema.has("anyOf") ? schema.get("anyOf") : schema.get("oneOf");
            int matches = 0;
            for (JsonNode choice : choices) {
                try { assertMatches(choice, value, path, documented); matches++; }
                catch (AssertionError ignored) { }
            }
            assertTrue(path + " matches no schema alternative: " + value, matches > 0);
            if (schema.has("oneOf")) assertEquals(path + " matches multiple alternatives", 1, matches);
        }
        if (schema.has("allOf")) for (JsonNode part : schema.get("allOf")) assertMatches(part, value, path, documented);
        if (schema.has("type")) {
            JsonNode types = schema.get("type");
            boolean valid = types.isArray()
                ? java.util.stream.StreamSupport.stream(types.spliterator(), false).anyMatch(t -> isType(t.asText(), value))
                : isType(types.asText(), value);
            assertTrue(path + " expected " + types + ", got " + value, valid);
        }
        if (schema.has("enum")) {
            assertTrue(path + " is not an allowed value: " + value,
                java.util.stream.StreamSupport.stream(schema.get("enum").spliterator(), false).anyMatch(value::equals));
        }
        if (schema.has("const")) assertEquals(path, schema.get("const"), value);
        if (value.isNumber()) {
            if (schema.has("minimum")) assertTrue(path, value.asDouble() >= schema.get("minimum").asDouble());
            if (schema.has("maximum")) assertTrue(path, value.asDouble() <= schema.get("maximum").asDouble());
        }
        if (value.isTextual()) {
            if (schema.has("minLength")) assertTrue(path, value.asText().length() >= schema.get("minLength").asInt());
            if (schema.has("maxLength")) assertTrue(path, value.asText().length() <= schema.get("maxLength").asInt());
            if (schema.has("pattern")) assertTrue(path, java.util.regex.Pattern.compile(schema.get("pattern").asText()).matcher(value.asText()).find());
        }
        if (value.isObject()) {
            for (JsonNode required : schema.path("required")) assertTrue(path + " missing " + required, value.has(required.asText()));
            Iterator<Map.Entry<String, JsonNode>> fields = value.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                JsonNode property = schema.path("properties").path(field.getKey());
                if (!property.isMissingNode()) {
                    assertMatches(property, field.getValue(), path + "." + field.getKey(), documented);
                } else if (schema.path("additionalProperties").isObject()) {
                    assertMatches(schema.get("additionalProperties"), field.getValue(), path + "." + field.getKey(), documented);
                } else if (!schema.has("anyOf") && !schema.has("oneOf") && !schema.has("allOf")) {
                    assertFalse(path + "." + field.getKey() + " lacks output documentation", documented);
                    assertTrue(path + "." + field.getKey() + " is not allowed", schema.path("additionalProperties").asBoolean(true));
                }
            }
        } else if (value.isArray()) {
            if (schema.has("minItems")) assertTrue(path, value.size() >= schema.get("minItems").asInt());
            if (schema.has("maxItems")) assertTrue(path, value.size() <= schema.get("maxItems").asInt());
            if (schema.has("items")) for (int i = 0; i < value.size(); i++) assertMatches(schema.get("items"), value.get(i), path + "[" + i + "]", documented);
        }
    }

    private static boolean isType(String type, JsonNode value) {
        return switch (type) {
            case "object" -> value.isObject();
            case "array" -> value.isArray();
            case "string" -> value.isTextual();
            case "boolean" -> value.isBoolean();
            case "integer" -> value.isIntegralNumber();
            case "number" -> value.isNumber();
            case "null" -> value.isNull();
            default -> throw new AssertionError("Unhandled schema type: " + type);
        };
    }
}
