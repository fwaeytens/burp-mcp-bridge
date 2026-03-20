package com.example.burpmcp;

import java.util.*;

/**
 * Reusable helpers for building JSON Schema structures for MCP tool metadata.
 */
public class SchemaHelper {

    /** Create a string property */
    public static Map<String, Object> stringProp(String description) {
        return Map.of("type", "string", "description", description);
    }

    /** Create a string property with enum */
    public static Map<String, Object> enumProp(String description, List<String> values) {
        return Map.of("type", "string", "description", description, "enum", values);
    }

    /** Create a string property with enum and default */
    public static Map<String, Object> enumProp(String description, List<String> values, String defaultValue) {
        return Map.of("type", "string", "description", description, "enum", values, "default", defaultValue);
    }

    /** Create an integer property */
    public static Map<String, Object> intProp(String description) {
        return Map.of("type", "integer", "description", description);
    }

    /** Create an integer property with default */
    public static Map<String, Object> intProp(String description, int defaultValue) {
        return Map.of("type", "integer", "description", description, "default", defaultValue);
    }

    /** Create a number property with constraints */
    public static Map<String, Object> numberProp(String description, Number defaultValue, Number min, Number max) {
        Map<String, Object> prop = new HashMap<>();
        prop.put("type", "number");
        prop.put("description", description);
        if (defaultValue != null) prop.put("default", defaultValue);
        if (min != null) prop.put("minimum", min);
        if (max != null) prop.put("maximum", max);
        return prop;
    }

    /** Create a boolean property */
    public static Map<String, Object> boolProp(String description) {
        return Map.of("type", "boolean", "description", description);
    }

    /** Create a boolean property with default */
    public static Map<String, Object> boolProp(String description, boolean defaultValue) {
        return Map.of("type", "boolean", "description", description, "default", defaultValue);
    }

    /** Create an array property with string items */
    public static Map<String, Object> stringArrayProp(String description) {
        return Map.of("type", "array", "description", description, "items", Map.of("type", "string"));
    }

    /** Create an array property with integer items */
    public static Map<String, Object> intArrayProp(String description) {
        return Map.of("type", "array", "description", description, "items", Map.of("type", "integer"));
    }

    /** Create an array property with object items */
    public static Map<String, Object> objectArrayProp(String description, Map<String, Object> itemProperties) {
        return Map.of("type", "array", "description", description,
            "items", Map.of("type", "object", "properties", itemProperties));
    }

    /** Create an object property */
    public static Map<String, Object> objectProp(String description) {
        return Map.of("type", "object", "description", description);
    }

    /**
     * Build an action-discriminated schema using if/then.
     *
     * @param actionEnum all valid action values
     * @param actionDescription description for the action parameter
     * @param sharedProperties properties available to all actions
     * @param actionSchemas map of action -> {required: [...], optionalProperties: {...}}
     * @return complete inputSchema object
     */
    public static Map<String, Object> actionSchema(
            List<String> actionEnum,
            String actionDescription,
            Map<String, Object> sharedProperties,
            Map<String, ActionDef> actionSchemas) {

        Map<String, Object> schema = new HashMap<>();
        schema.put("type", "object");

        // Merge action property into shared properties
        Map<String, Object> allProperties = new HashMap<>(sharedProperties);
        allProperties.put("action", enumProp(actionDescription, actionEnum));

        schema.put("properties", allProperties);
        schema.put("required", List.of("action"));

        // Build allOf with if/then blocks for action-specific requirements
        if (actionSchemas != null && !actionSchemas.isEmpty()) {
            List<Map<String, Object>> allOf = new ArrayList<>();
            for (Map.Entry<String, ActionDef> entry : actionSchemas.entrySet()) {
                String action = entry.getKey();
                ActionDef def = entry.getValue();

                Map<String, Object> ifBlock = Map.of(
                    "properties", Map.of("action", Map.of("const", action))
                );

                Map<String, Object> thenBlock = new HashMap<>();
                if (def.required != null && !def.required.isEmpty()) {
                    thenBlock.put("required", def.required);
                }
                if (def.properties != null && !def.properties.isEmpty()) {
                    // Merge action-specific properties into allProperties
                    allProperties.putAll(def.properties);
                }

                if (!thenBlock.isEmpty()) {
                    allOf.add(Map.of("if", ifBlock, "then", thenBlock));
                }
            }
            if (!allOf.isEmpty()) {
                schema.put("allOf", allOf);
            }
        }

        return schema;
    }

    /** Definition for action-specific schema requirements */
    public static class ActionDef {
        public final List<String> required;
        public final Map<String, Object> properties;

        public ActionDef(List<String> required) {
            this.required = required;
            this.properties = Map.of();
        }

        public ActionDef(List<String> required, Map<String, Object> properties) {
            this.required = required;
            this.properties = properties;
        }
    }

    /** Convenience for creating ActionDef */
    public static ActionDef actionDef(String... required) {
        return new ActionDef(List.of(required));
    }

    /** Convenience for creating ActionDef with extra properties */
    public static ActionDef actionDef(List<String> required, Map<String, Object> properties) {
        return new ActionDef(required, properties);
    }

    /**
     * Build a simple output schema.
     */
    public static Map<String, Object> outputSchema(Map<String, Object> properties) {
        return Map.of("type", "object", "properties", properties);
    }
}
