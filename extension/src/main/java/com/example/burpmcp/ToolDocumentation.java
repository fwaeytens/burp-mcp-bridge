package com.example.burpmcp;

import java.util.*;

/**
 * Documentation structure for a single tool
 */
public class ToolDocumentation {
    private final String name;
    private final String category;
    private String description;
    private final List<Map<String, Object>> parameters;
    private final Map<String, Object> returns;
    private final List<Map<String, Object>> examples;
    private final List<Map<String, Object>> errors;
    private final List<String> bestPractices;
    private final List<String> relatedTools;
    private final List<String> keywords;
    private final List<String> capabilities;
    private final List<String> inputTypes;
    private final List<String> outputTypes;
    
    private ToolDocumentation(Builder builder) {
        this.name = builder.name;
        this.category = builder.category;
        this.description = builder.description;
        this.parameters = builder.parameters;
        this.returns = builder.returns;
        this.examples = builder.examples;
        this.errors = builder.errors;
        this.bestPractices = builder.bestPractices;
        this.relatedTools = builder.relatedTools;
        this.keywords = builder.keywords;
        this.capabilities = builder.capabilities;
        this.inputTypes = builder.inputTypes;
        this.outputTypes = builder.outputTypes;
    }
    
    // Getters
    public String getName() { return name; }
    public String getCategory() { return category; }
    public String getDescription() { return description; }
    public List<Map<String, Object>> getParameters() { return new ArrayList<>(parameters); }
    public Map<String, Object> getReturns() { return new HashMap<>(returns); }
    public List<Map<String, Object>> getExamples() { return new ArrayList<>(examples); }
    public List<Map<String, Object>> getErrors() { return new ArrayList<>(errors); }
    public List<String> getBestPractices() { return new ArrayList<>(bestPractices); }
    public List<String> getRelatedTools() { return new ArrayList<>(relatedTools); }
    public List<String> getKeywords() { return new ArrayList<>(keywords); }
    public List<String> getCapabilities() { return new ArrayList<>(capabilities); }
    public List<String> getInputTypes() { return new ArrayList<>(inputTypes); }
    public List<String> getOutputTypes() { return new ArrayList<>(outputTypes); }

    public void setDescription(String description) {
        if (description != null && !description.isBlank()) {
            this.description = description;
        }
    }

    public void replaceParameters(List<Map<String, Object>> newParameters) {
        parameters.clear();
        if (newParameters != null) {
            parameters.addAll(newParameters);
        }
    }

    public void setReturns(Map<String, Object> newReturns) {
        returns.clear();
        if (newReturns != null) {
            returns.putAll(newReturns);
        }
    }
    
    public static class Builder {
        private String name;
        private String category;
        private String description;
        private List<Map<String, Object>> parameters = new ArrayList<>();
        private Map<String, Object> returns = new HashMap<>();
        private List<Map<String, Object>> examples = new ArrayList<>();
        private List<Map<String, Object>> errors = new ArrayList<>();
        private List<String> bestPractices = new ArrayList<>();
        private List<String> relatedTools = new ArrayList<>();
        private List<String> keywords = new ArrayList<>();
        private List<String> capabilities = new ArrayList<>();
        private List<String> inputTypes = new ArrayList<>();
        private List<String> outputTypes = new ArrayList<>();
        
        public Builder(String name) {
            this.name = name;
        }
        
        public Builder category(String category) {
            this.category = category;
            return this;
        }
        
        public Builder description(String description) {
            this.description = description;
            return this;
        }
        
        public Builder addParameter(String name, String type, boolean required, String description) {
            Map<String, Object> param = new HashMap<>();
            param.put("name", name);
            param.put("type", type);
            param.put("required", required);
            param.put("description", description);
            parameters.add(param);
            return this;
        }
        
        public Builder addParameter(String name, String type, boolean required, String description, Object defaultValue) {
            Map<String, Object> param = new HashMap<>();
            param.put("name", name);
            param.put("type", type);
            param.put("required", required);
            param.put("description", description);
            param.put("default", defaultValue);
            parameters.add(param);
            return this;
        }
        
        public Builder addParameterWithEnum(String name, String type, boolean required, String description, List<String> enumValues) {
            Map<String, Object> param = new HashMap<>();
            param.put("name", name);
            param.put("type", type);
            param.put("required", required);
            param.put("description", description);
            param.put("enum", enumValues);
            parameters.add(param);
            return this;
        }
        
        public Builder returns(String type, String description) {
            returns.put("type", type);
            returns.put("description", description);
            return this;
        }
        
        public Builder addExample(String title, Map<String, Object> input, Map<String, Object> output, String explanation) {
            Map<String, Object> example = new HashMap<>();
            example.put("title", title);
            example.put("input", input);
            example.put("output", output);
            example.put("explanation", explanation);
            examples.add(example);
            return this;
        }
        
        public Builder addError(String code, String description, String solution) {
            Map<String, Object> error = new HashMap<>();
            error.put("code", code);
            error.put("description", description);
            error.put("solution", solution);
            errors.add(error);
            return this;
        }
        
        public Builder addBestPractice(String practice) {
            bestPractices.add(practice);
            return this;
        }
        
        public Builder addRelatedTool(String tool) {
            relatedTools.add(tool);
            return this;
        }
        
        public Builder addKeyword(String keyword) {
            keywords.add(keyword);
            return this;
        }
        
        public Builder addKeywords(String... keywords) {
            this.keywords.addAll(Arrays.asList(keywords));
            return this;
        }
        
        public Builder addCapability(String capability) {
            capabilities.add(capability);
            return this;
        }
        
        public Builder addCapabilities(String... capabilities) {
            this.capabilities.addAll(Arrays.asList(capabilities));
            return this;
        }
        
        public Builder addInputType(String type) {
            inputTypes.add(type);
            return this;
        }
        
        public Builder addInputTypes(String... types) {
            inputTypes.addAll(Arrays.asList(types));
            return this;
        }
        
        public Builder addOutputType(String type) {
            outputTypes.add(type);
            return this;
        }
        
        public Builder addOutputTypes(String... types) {
            outputTypes.addAll(Arrays.asList(types));
            return this;
        }
        
        public ToolDocumentation build() {
            return new ToolDocumentation(this);
        }
    }
}
