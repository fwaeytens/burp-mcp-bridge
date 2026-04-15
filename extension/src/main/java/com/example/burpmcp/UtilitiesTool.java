package com.example.burpmcp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.utilities.*;
import burp.api.montoya.utilities.json.JsonUtils;
import burp.api.montoya.utilities.shell.ShellUtils;
import burp.api.montoya.utilities.shell.ExecuteOptions;
import burp.api.montoya.utilities.shell.TimeoutBehavior;
import burp.api.montoya.utilities.shell.StderrBehavior;
import burp.api.montoya.utilities.shell.ExitCodeBehavior;
import burp.api.montoya.core.ByteArray;
import com.fasterxml.jackson.databind.JsonNode;

import java.time.Duration;
import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.nio.charset.StandardCharsets;

public class UtilitiesTool implements McpTool {
    private final MontoyaApi api;
    
    public UtilitiesTool(MontoyaApi api) {
        this.api = api;
    }

    @Override
    public Map<String, Object> getToolInfo() {
        Map<String, Object> tool = new HashMap<>();
        tool.put("name", "burp_utilities");
        tool.put("title", "Utilities");
        tool.put("description", "Access Burp's utility functions for encoding/decoding, hashing, random data generation, JSON manipulation, and shell execution. " +
            "Actions: base64_encode/decode, url_encode/decode, html_encode/decode, hash (MD5/SHA), random (generate data), " +
            "json_beautify/validate/path, hex_to_ascii, number_convert, shell_execute (run commands). " +
            "Essential helper functions for payload crafting and data manipulation.");

        // MCP 2025-06-18 annotations
        Map<String, Object> annotations = new HashMap<>();
        annotations.put("readOnlyHint", false);
        annotations.put("destructiveHint", true);   // shell_execute can modify system state
        annotations.put("idempotentHint", false);   // shell commands may have side effects
        annotations.put("openWorldHint", true);     // shell commands can access network
        annotations.put("title", "Utilities");
        tool.put("annotations", annotations);

        Map<String, Object> meta = new HashMap<>();
        meta.put("anthropic/searchHint", "encode decode hash URL base64 convert");
        tool.put("_meta", meta);

        Map<String, Object> inputSchema = new HashMap<>();
        inputSchema.put("type", "object");

        Map<String, Object> properties = new HashMap<>();
        
        properties.put("action", McpUtils.createEnumProperty("string",
            "Utility action to perform. shell_execute: SAFE arg-list execution (use commandArgs[] not single command string). shell_execute_dangerous: shell-interpreted single string (allows pipes/redirects but enables injection — only use when shell features are required).",
            List.of("base64_encode", "base64_decode", "url_encode", "url_decode",
                    "html_encode", "html_decode", "hash", "random", "compress",
                    "decompress", "json_beautify", "json_path", "json_validate",
                    "hex_to_ascii", "ascii_to_hex", "number_convert", "byte_search",
                    "shell_execute", "shell_execute_dangerous"),
            "base64_encode"));
        
        properties.put("input", McpUtils.createProperty("string", 
            "Input data for the utility function"));
        
        properties.put("algorithm", McpUtils.createEnumProperty("string",
            "Hash algorithm (for hash action)",
            List.of("MD5", "SHA1", "SHA256", "SHA384", "SHA512"),
            "SHA256"));
        
        properties.put("length", McpUtils.createProperty("integer",
            "Length of random data to generate (for random action)", 16));
        
        properties.put("type", McpUtils.createEnumProperty("string",
            "Type of random data",
            List.of("alphanumeric", "alphabetic", "numeric", "hex"),
            "alphanumeric"));
        
        // For JSON path operations
        properties.put("jsonPath", McpUtils.createProperty("string",
            "JSON path for read/add/update/remove operations"));
        
        properties.put("jsonValue", McpUtils.createProperty("string",
            "Value for JSON add/update operations"));
        
        properties.put("jsonOperation", McpUtils.createEnumProperty("string",
            "JSON operation type",
            List.of("read", "add", "update", "remove"),
            "read"));
        
        // For number conversion
        properties.put("fromBase", McpUtils.createEnumProperty("string",
            "Source number base",
            List.of("binary", "octal", "decimal", "hex"),
            "decimal"));
        
        properties.put("toBase", McpUtils.createEnumProperty("string",
            "Target number base",
            List.of("binary", "octal", "decimal", "hex"),
            "hex"));
        
        // For byte search
        properties.put("searchPattern", McpUtils.createProperty("string",
            "Pattern to search for in bytes (string or regex)"));
        
        properties.put("useRegex", McpUtils.createProperty("boolean",
            "Whether searchPattern is a regex", false));

        // Shell execution parameters
        properties.put("command", McpUtils.createProperty("string",
            "Single shell-interpreted string. Use only with shell_execute_dangerous when pipes/redirects are needed. For safe execution prefer commandArgs[] with shell_execute."));

        properties.put("commandArgs", McpUtils.createProperty("array",
            "Command arguments as separate strings (for shell_execute - safer than single string)"));

        properties.put("timeout", McpUtils.createProperty("integer",
            "Command timeout in seconds (default: 10, 0 to disable)", 10));

        properties.put("mergeStderr", McpUtils.createProperty("boolean",
            "Merge stderr with stdout (default: false)", false));

        properties.put("allowNonZeroExit", McpUtils.createProperty("boolean",
            "Allow non-zero exit codes without error (default: false)", false));

        properties.put("allowTimeout", McpUtils.createProperty("boolean",
            "Silently handle timeout instead of error (default: false)", false));

        properties.put("envVars", McpUtils.createProperty("object",
            "Environment variables as key-value pairs"));

        properties.put("verbose", McpUtils.createProperty("boolean",
            "If true, returns formatted markdown with sections and emoji. Default: compact JSON for token efficiency.", false));

        inputSchema.put("properties", properties);
        inputSchema.put("required", List.of("action"));



        tool.put("inputSchema", inputSchema);
        return tool;
    }

    @Override
    public Object execute(JsonNode arguments) throws Exception {
        String action = McpUtils.getStringParam(arguments, "action", "base64_encode");
        String input = McpUtils.getStringParam(arguments, "input", "");
        
        try {
            switch (action) {
                case "base64_encode":
                    return performBase64Encode(input, arguments);
                case "base64_decode":
                    return performBase64Decode(input, arguments);
                case "url_encode":
                    return performUrlEncode(input, arguments);
                case "url_decode":
                    return performUrlDecode(input, arguments);
                case "html_encode":
                    return performHtmlEncode(input, arguments);
                case "html_decode":
                    return performHtmlDecode(input, arguments);
                case "hash":
                    return performHash(input, arguments);
                case "random":
                    return generateRandom(arguments);
                case "compress":
                    return performCompress(input, arguments);
                case "decompress":
                    return performDecompress(input, arguments);
                case "json_beautify":
                    return performJsonBeautify(input, arguments);
                case "json_path":
                    return performJsonPath(input, arguments);
                case "json_validate":
                    return performJsonValidate(input, arguments);
                case "hex_to_ascii":
                    return performHexToAscii(input, arguments);
                case "ascii_to_hex":
                    return performAsciiToHex(input, arguments);
                case "number_convert":
                    return performNumberConvert(input, arguments);
                case "byte_search":
                    return performByteSearch(input, arguments);
                case "shell_execute":
                    return performShellExecute(arguments, false);
                case "shell_execute_dangerous":
                    return performShellExecute(arguments, true);
                default:
                    return McpUtils.createErrorResponse("Unknown action: " + action);
            }
        } catch (Exception e) {
            return McpUtils.createErrorResponse("Utility operation failed: " + e.getMessage());
        }
    }
    
    /**
     * Wraps a simple utility result with both JSON and markdown output support.
     */
    private Object utilityResult(JsonNode arguments, String operation, String input, String output, Map<String, Object> extra) {
        if (!McpUtils.isVerbose(arguments)) {
            Map<String, Object> data = new HashMap<>();
            data.put("operation", operation);
            data.put("input", input);
            data.put("output", output);
            if (extra != null) data.putAll(extra);
            return McpUtils.createJsonResponse(data);
        }
        StringBuilder result = new StringBuilder();
        result.append("## ").append(operation).append("\n\n");
        result.append("**Input:** ").append(McpUtils.truncateText(input, 100)).append("\n");
        result.append("**Output:**\n```\n").append(output).append("\n```\n");
        if (extra != null) {
            for (Map.Entry<String, Object> e : extra.entrySet()) {
                result.append("**").append(e.getKey()).append(":** ").append(e.getValue()).append("\n");
            }
        }
        return McpUtils.createSuccessResponse(result.toString());
    }

    private Object performBase64Encode(String input, JsonNode arguments) {
        if (input.isEmpty()) return McpUtils.createErrorResponse("Input is required for base64 encoding");
        ByteArray encoded = api.utilities().base64Utils().encode(input);
        Map<String, Object> extra = new HashMap<>();
        extra.put("inputLength", input.length());
        extra.put("outputLength", encoded.length());
        return utilityResult(arguments, "base64_encode", input, encoded.toString(), extra);
    }

    private Object performBase64Decode(String input, JsonNode arguments) {
        if (input.isEmpty()) return McpUtils.createErrorResponse("Input is required for base64 decoding");
        try {
            ByteArray decoded = api.utilities().base64Utils().decode(input);
            String decodedString = decoded.toString();
            boolean isBinary = false;
            for (char c : decodedString.toCharArray()) {
                if (Character.isISOControl(c) && c != '\n' && c != '\r' && c != '\t') { isBinary = true; break; }
            }
            Map<String, Object> extra = new HashMap<>();
            extra.put("inputLength", input.length());
            extra.put("outputLength", decodedString.length());
            extra.put("isBinary", isBinary);
            if (isBinary) extra.put("hex", bytesToHex(decoded.getBytes()));
            return utilityResult(arguments, "base64_decode", input, decodedString, extra);
        } catch (Exception e) {
            return McpUtils.createErrorResponse("Failed to decode base64: " + e.getMessage());
        }
    }

    private Object performUrlEncode(String input, JsonNode arguments) {
        if (input.isEmpty()) return McpUtils.createErrorResponse("Input is required for URL encoding");
        String encoded = api.utilities().urlUtils().encode(input);
        return utilityResult(arguments, "url_encode", input, encoded, null);
    }

    private Object performUrlDecode(String input, JsonNode arguments) {
        if (input.isEmpty()) return McpUtils.createErrorResponse("Input is required for URL decoding");
        String decoded = api.utilities().urlUtils().decode(input);
        return utilityResult(arguments, "url_decode", input, decoded, null);
    }

    private Object performHtmlEncode(String input, JsonNode arguments) {
        if (input.isEmpty()) return McpUtils.createErrorResponse("Input is required for HTML encoding");
        String encoded = api.utilities().htmlUtils().encode(input);
        return utilityResult(arguments, "html_encode", input, encoded, null);
    }

    private Object performHtmlDecode(String input, JsonNode arguments) {
        if (input.isEmpty()) return McpUtils.createErrorResponse("Input is required for HTML decoding");
        String decoded = api.utilities().htmlUtils().decode(input);
        return utilityResult(arguments, "html_decode", input, decoded, null);
    }
    
    private Object performHash(String input, JsonNode arguments) {
        if (input.isEmpty()) {
            return McpUtils.createErrorResponse("Input is required for hashing");
        }
        
        String algorithm = McpUtils.getStringParam(arguments, "algorithm", "SHA256");
        CryptoUtils crypto = api.utilities().cryptoUtils();
        
        DigestAlgorithm digestAlgo;
        switch (algorithm.toUpperCase()) {
            case "MD5":
                digestAlgo = DigestAlgorithm.MD5;
                break;
            case "SHA1":
                digestAlgo = DigestAlgorithm.SHA_1;
                break;
            case "SHA256":
                digestAlgo = DigestAlgorithm.SHA_256;
                break;
            case "SHA384":
                digestAlgo = DigestAlgorithm.SHA_384;
                break;
            case "SHA512":
                digestAlgo = DigestAlgorithm.SHA_512;
                break;
            default:
                return McpUtils.createErrorResponse("Unsupported algorithm: " + algorithm);
        }
        
        ByteArray inputBytes = ByteArray.byteArray(input);
        ByteArray hash = crypto.generateDigest(inputBytes, digestAlgo);
        String hashHex = bytesToHex(hash.getBytes());

        Map<String, Object> extra = new HashMap<>();
        extra.put("algorithm", algorithm);
        extra.put("hashLengthBytes", hashHex.length() / 2);
        return utilityResult(arguments, "hash", input, hashHex, extra);
    }
    
    private Object generateRandom(JsonNode arguments) {
        int length = McpUtils.getIntParam(arguments, "length", 16);
        String type = McpUtils.getStringParam(arguments, "type", "alphanumeric");
        
        if (length <= 0 || length > 1000) {
            return McpUtils.createErrorResponse("Length must be between 1 and 1000");
        }
        
        RandomUtils random = api.utilities().randomUtils();
        String generated;
        
        switch (type) {
            case "alphanumeric":
                generated = random.randomString(length, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");
                break;
            case "alphabetic":
                generated = random.randomString(length, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ");
                break;
            case "numeric":
                generated = random.randomString(length, "0123456789");
                break;
            case "hex":
                generated = random.randomString(length, "0123456789abcdef");
                break;
            default:
                return McpUtils.createErrorResponse("Unknown random type: " + type);
        }
        
        Map<String, Object> extra = new HashMap<>();
        extra.put("type", type);
        extra.put("length", length);
        return utilityResult(arguments, "random", "", generated, extra);
    }

    private Object performCompress(String input, JsonNode arguments) {
        if (input.isEmpty()) {
            return McpUtils.createErrorResponse("Input is required for compression");
        }
        
        try {
            CompressionUtils compression = api.utilities().compressionUtils();
            ByteArray compressed = compression.compress(ByteArray.byteArray(input), CompressionType.GZIP);
            String compressedBase64 = Base64.getEncoder().encodeToString(compressed.getBytes());
            double ratio = (1.0 - (double) compressed.length() / input.length()) * 100;
            Map<String, Object> extra = new HashMap<>();
            extra.put("algorithm", "GZIP");
            extra.put("originalSize", input.length());
            extra.put("compressedSize", compressed.length());
            extra.put("compressionRatioPercent", Math.round(ratio * 10.0) / 10.0);
            return utilityResult(arguments, "compress", input, compressedBase64, extra);
        } catch (Exception e) {
            return McpUtils.createErrorResponse("Compression failed: " + e.getMessage());
        }
    }

    private Object performDecompress(String input, JsonNode arguments) {
        if (input.isEmpty()) {
            return McpUtils.createErrorResponse("Input is required for decompression");
        }
        
        try {
            byte[] compressedBytes;
            try {
                compressedBytes = Base64.getDecoder().decode(input);
            } catch (Exception e) {
                return McpUtils.createErrorResponse("Input should be base64-encoded compressed data");
            }
            ByteArray compressed = ByteArray.byteArray(compressedBytes);
            ByteArray decompressed = api.utilities().compressionUtils().decompress(compressed, CompressionType.GZIP);
            String decompressedString = decompressed.toString();
            Map<String, Object> extra = new HashMap<>();
            extra.put("algorithm", "GZIP");
            extra.put("compressedSize", compressed.length());
            extra.put("decompressedSize", decompressed.length());
            return utilityResult(arguments, "decompress", input, decompressedString, extra);
        } catch (Exception e) {
            return McpUtils.createErrorResponse("Decompression failed: " + e.getMessage());
        }
    }

    private Object performJsonBeautify(String input, JsonNode arguments) {
        if (input.isEmpty()) {
            return McpUtils.createErrorResponse("Input is required for JSON beautification");
        }
        
        try {
            com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
            Object json = mapper.readValue(input, Object.class);
            String beautified = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(json);
            Map<String, Object> extra = new HashMap<>();
            extra.put("originalLength", input.length());
            extra.put("beautifiedLength", beautified.length());
            return utilityResult(arguments, "json_beautify", input, beautified, extra);
        } catch (Exception e) {
            return McpUtils.createErrorResponse("JSON parsing failed: " + e.getMessage());
        }
    }

    private Object performHexToAscii(String input, JsonNode arguments) {
        if (input.isEmpty()) return McpUtils.createErrorResponse("Input is required");
        String ascii = api.utilities().stringUtils().convertHexStringToAscii(input);
        return utilityResult(arguments, "hex_to_ascii", input, ascii, null);
    }

    private Object performAsciiToHex(String input, JsonNode arguments) {
        if (input.isEmpty()) return McpUtils.createErrorResponse("Input is required");
        String hex = api.utilities().stringUtils().convertAsciiToHexString(input);
        return utilityResult(arguments, "ascii_to_hex", input, hex, null);
    }
    
    private String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }
    
    private Object performJsonPath(String input, JsonNode arguments) {
        if (input.isEmpty()) {
            return McpUtils.createErrorResponse("Input JSON is required");
        }

        String jsonPath = McpUtils.getStringParam(arguments, "jsonPath", "");
        if (jsonPath.isEmpty()) {
            return McpUtils.createErrorResponse("JSON path is required");
        }

        String operation = McpUtils.getStringParam(arguments, "jsonOperation", "read");
        String jsonValue = McpUtils.getStringParam(arguments, "jsonValue", "");
        JsonUtils jsonUtils = api.utilities().jsonUtils();
        boolean verbose = McpUtils.isVerbose(arguments);

        try {
            Map<String, Object> data = new HashMap<>();
            data.put("operation", operation);
            data.put("path", jsonPath);

            switch (operation) {
                case "read":
                    String value = jsonUtils.read(input, jsonPath);
                    if (value != null) {
                        data.put("value", value);
                        Boolean boolValue = jsonUtils.readBoolean(input, jsonPath);
                        Double doubleValue = jsonUtils.readDouble(input, jsonPath);
                        Long longValue = jsonUtils.readLong(input, jsonPath);
                        if (boolValue != null) data.put("asBoolean", boolValue);
                        if (doubleValue != null) data.put("asDouble", doubleValue);
                        if (longValue != null) data.put("asLong", longValue);
                    } else {
                        data.put("value", null);
                    }
                    break;
                case "add":
                    if (jsonValue.isEmpty()) return McpUtils.createErrorResponse("jsonValue is required for add operation");
                    data.put("result", jsonUtils.add(input, jsonPath, jsonValue));
                    data.put("addedValue", jsonValue);
                    break;
                case "update":
                    if (jsonValue.isEmpty()) return McpUtils.createErrorResponse("jsonValue is required for update operation");
                    data.put("result", jsonUtils.update(input, jsonPath, jsonValue));
                    data.put("updatedValue", jsonValue);
                    break;
                case "remove":
                    data.put("result", jsonUtils.remove(input, jsonPath));
                    break;
                default:
                    return McpUtils.createErrorResponse("Unknown JSON operation: " + operation);
            }

            if (!verbose) {
                return McpUtils.createJsonResponse(data);
            }

            StringBuilder result = new StringBuilder();
            result.append("## JSON Path Operation\n\n");
            result.append("**Operation:** ").append(operation).append("\n");
            result.append("**Path:** `").append(jsonPath).append("`\n\n");
            for (Map.Entry<String, Object> e : data.entrySet()) {
                if (e.getKey().equals("operation") || e.getKey().equals("path")) continue;
                result.append("**").append(e.getKey()).append(":** ").append(e.getValue()).append("\n");
            }
            return McpUtils.createSuccessResponse(result.toString());

        } catch (Exception e) {
            return McpUtils.createErrorResponse("JSON path operation failed: " + e.getMessage());
        }
    }
    
    private Object performJsonValidate(String input, JsonNode arguments) {
        if (input.isEmpty()) {
            return McpUtils.createErrorResponse("Input is required for JSON validation");
        }

        JsonUtils jsonUtils = api.utilities().jsonUtils();
        boolean isValid = jsonUtils.isValidJson(input);

        if (!McpUtils.isVerbose(arguments)) {
            Map<String, Object> data = new HashMap<>();
            data.put("operation", "json_validate");
            data.put("valid", isValid);
            if (isValid) {
                try {
                    com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
                    Object json = mapper.readValue(input, Object.class);
                    data.put("rootType", json.getClass().getSimpleName());
                    if (json instanceof Map) {
                        data.put("keys", new ArrayList<>(((Map<?, ?>) json).keySet()));
                    } else if (json instanceof List) {
                        data.put("arrayLength", ((List<?>) json).size());
                    }
                } catch (Exception e) { }
            }
            return McpUtils.createJsonResponse(data);
        }

        StringBuilder result = new StringBuilder();
        result.append("## JSON Validation Result\n\n");
        result.append("**Valid JSON:** ").append(isValid ? "✅ Yes" : "❌ No").append("\n\n");
        if (isValid) {
            try {
                com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
                Object json = mapper.readValue(input, Object.class);
                result.append("**Root Type:** ").append(json.getClass().getSimpleName()).append("\n");
                if (json instanceof Map) {
                    result.append("**Keys:** ").append(((Map<?, ?>) json).keySet()).append("\n");
                } else if (json instanceof List) {
                    result.append("**Array Length:** ").append(((List<?>) json).size()).append("\n");
                }
            } catch (Exception e) { }
        } else {
            result.append("Common issues:\n");
            result.append("- Missing quotes around strings\n");
            result.append("- Trailing commas\n");
            result.append("- Single quotes instead of double quotes\n");
            result.append("- Unescaped special characters\n");
        }
        
        return McpUtils.createSuccessResponse(result.toString());
    }
    
    private Object performNumberConvert(String input, JsonNode arguments) {
        if (input.isEmpty()) {
            return McpUtils.createErrorResponse("Input number is required");
        }
        
        String fromBase = McpUtils.getStringParam(arguments, "fromBase", "decimal");
        String toBase = McpUtils.getStringParam(arguments, "toBase", "hex");
        
        NumberUtils numberUtils = api.utilities().numberUtils();
        
        try {
            String converted;
            
            // Convert from source base to target base
            if (fromBase.equals("binary")) {
                switch (toBase) {
                    case "binary": converted = input; break;
                    case "octal": converted = numberUtils.convertBinaryToOctal(input); break;
                    case "decimal": converted = numberUtils.convertBinaryToDecimal(input); break;
                    case "hex": converted = numberUtils.convertBinaryToHex(input); break;
                    default: return McpUtils.createErrorResponse("Invalid target base: " + toBase);
                }
            } else if (fromBase.equals("octal")) {
                switch (toBase) {
                    case "binary": converted = numberUtils.convertOctalToBinary(input); break;
                    case "octal": converted = input; break;
                    case "decimal": converted = numberUtils.convertOctalToDecimal(input); break;
                    case "hex": converted = numberUtils.convertOctalToHex(input); break;
                    default: return McpUtils.createErrorResponse("Invalid target base: " + toBase);
                }
            } else if (fromBase.equals("decimal")) {
                switch (toBase) {
                    case "binary": converted = numberUtils.convertDecimalToBinary(input); break;
                    case "octal": converted = numberUtils.convertDecimalToOctal(input); break;
                    case "decimal": converted = input; break;
                    case "hex": converted = numberUtils.convertDecimalToHex(input); break;
                    default: return McpUtils.createErrorResponse("Invalid target base: " + toBase);
                }
            } else if (fromBase.equals("hex")) {
                switch (toBase) {
                    case "binary": converted = numberUtils.convertHexToBinary(input); break;
                    case "octal": converted = numberUtils.convertHexToOctal(input); break;
                    case "decimal": converted = numberUtils.convertHexToDecimal(input); break;
                    case "hex": converted = input; break;
                    default: return McpUtils.createErrorResponse("Invalid target base: " + toBase);
                }
            } else {
                return McpUtils.createErrorResponse("Invalid source base: " + fromBase);
            }
            
            String decimal;
            if (fromBase.equals("decimal")) decimal = input;
            else if (fromBase.equals("binary")) decimal = numberUtils.convertBinaryToDecimal(input);
            else if (fromBase.equals("octal")) decimal = numberUtils.convertOctalToDecimal(input);
            else decimal = numberUtils.convertHexToDecimal(input);

            Map<String, Object> allBases = new HashMap<>();
            allBases.put("binary", numberUtils.convertDecimalToBinary(decimal));
            allBases.put("octal", numberUtils.convertDecimalToOctal(decimal));
            allBases.put("decimal", decimal);
            allBases.put("hex", numberUtils.convertDecimalToHex(decimal));

            if (!McpUtils.isVerbose(arguments)) {
                Map<String, Object> data = new HashMap<>();
                data.put("operation", "number_convert");
                data.put("input", input);
                data.put("fromBase", fromBase);
                data.put("toBase", toBase);
                data.put("output", converted);
                data.put("allBases", allBases);
                return McpUtils.createJsonResponse(data);
            }

            StringBuilder result = new StringBuilder();
            result.append("## Number Base Conversion\n\n");
            result.append("**Input:** ").append(input).append(" (").append(fromBase).append(")\n");
            result.append("**Output:** ").append(converted).append(" (").append(toBase).append(")\n\n");
            result.append("### All Base Representations:\n");
            result.append("- **Binary:** ").append(allBases.get("binary")).append("\n");
            result.append("- **Octal:** ").append(allBases.get("octal")).append("\n");
            result.append("- **Decimal:** ").append(allBases.get("decimal")).append("\n");
            result.append("- **Hexadecimal:** ").append(allBases.get("hex")).append("\n");
            return McpUtils.createSuccessResponse(result.toString());

        } catch (Exception e) {
            return McpUtils.createErrorResponse("Number conversion failed: " + e.getMessage());
        }
    }
    
    private Object performByteSearch(String input, JsonNode arguments) {
        if (input.isEmpty()) return McpUtils.createErrorResponse("Input is required for byte search");
        String searchPattern = McpUtils.getStringParam(arguments, "searchPattern", "");
        if (searchPattern.isEmpty()) return McpUtils.createErrorResponse("Search pattern is required");

        boolean useRegex = McpUtils.getBooleanParam(arguments, "useRegex", false);
        boolean verbose = McpUtils.isVerbose(arguments);
        ByteUtils byteUtils = api.utilities().byteUtils();
        byte[] inputBytes = input.getBytes(StandardCharsets.UTF_8);

        try {
            int count;
            int firstIndex;
            List<Map<String, Object>> matches = new ArrayList<>();
            String contextPreview = null;

            if (useRegex) {
                Pattern pattern = Pattern.compile(searchPattern);
                count = byteUtils.countMatches(inputBytes, pattern);
                firstIndex = byteUtils.indexOf(inputBytes, pattern);
                if (firstIndex >= 0) {
                    String inputStr = new String(inputBytes, StandardCharsets.UTF_8);
                    Matcher matcher = pattern.matcher(inputStr);
                    int matchNum = 0;
                    while (matcher.find() && matchNum < 10) {
                        Map<String, Object> m = new HashMap<>();
                        m.put("index", matcher.start());
                        m.put("match", matcher.group());
                        matches.add(m);
                        matchNum++;
                    }
                }
            } else {
                byte[] searchBytes = searchPattern.getBytes(StandardCharsets.UTF_8);
                count = byteUtils.countMatches(inputBytes, searchBytes);
                firstIndex = byteUtils.indexOf(inputBytes, searchBytes);
                if (firstIndex >= 0) {
                    int index = firstIndex;
                    int matchCount = 0;
                    while (index >= 0 && matchCount < 10) {
                        Map<String, Object> m = new HashMap<>();
                        m.put("index", index);
                        matches.add(m);
                        index = byteUtils.indexOf(inputBytes, searchBytes, false, index + 1, inputBytes.length);
                        matchCount++;
                    }
                    int contextStart = Math.max(0, firstIndex - 20);
                    int contextEnd = Math.min(inputBytes.length, firstIndex + searchBytes.length + 20);
                    contextPreview = new String(inputBytes, contextStart, contextEnd - contextStart, StandardCharsets.UTF_8);
                }
            }

            if (!verbose) {
                Map<String, Object> data = new HashMap<>();
                data.put("operation", "byte_search");
                data.put("inputLength", inputBytes.length);
                data.put("pattern", searchPattern);
                data.put("useRegex", useRegex);
                data.put("matchCount", count);
                data.put("firstMatchIndex", firstIndex);
                data.put("matches", matches);
                if (contextPreview != null) data.put("contextPreview", contextPreview);
                return McpUtils.createJsonResponse(data);
            }

            StringBuilder result = new StringBuilder();
            result.append("## Byte Search Results\n\n");
            result.append("**Input Length:** ").append(inputBytes.length).append(" bytes\n");
            result.append("**Search Pattern:** `").append(searchPattern).append("`\n");
            result.append("**Use Regex:** ").append(useRegex).append("\n");
            result.append("**Matches Found:** ").append(count).append("\n");
            if (firstIndex >= 0) {
                result.append("**First Match Index:** ").append(firstIndex).append("\n\n");
                result.append("### Match Locations:\n");
                for (Map<String, Object> m : matches) {
                    result.append("- Index ").append(m.get("index"));
                    if (m.containsKey("match")) result.append(": `").append(m.get("match")).append("`");
                    result.append("\n");
                }
                if (count > 10) result.append("... and ").append(count - 10).append(" more matches\n");
                if (contextPreview != null) {
                    result.append("\n### Context (first match):\n```\n").append(contextPreview).append("\n```\n");
                }
            } else {
                result.append("No matches found.\n");
            }
            return McpUtils.createSuccessResponse(result.toString());

        } catch (Exception e) {
            return McpUtils.createErrorResponse("Byte search failed: " + e.getMessage());
        }
    }

    /**
     * Execute shell commands using the Montoya ShellUtils API.
     *
     * @param arguments JSON arguments containing command and options
     * @param dangerous If true, use dangerouslyExecute (splits on whitespace - injection risk)
     * @return Execution result or error
     */
    private Object performShellExecute(JsonNode arguments, boolean dangerous) {
        String command = McpUtils.getStringParam(arguments, "command", "");

        // For safe execution, get command arguments as array
        List<String> commandArgs = new ArrayList<>();
        if (arguments.has("commandArgs") && arguments.get("commandArgs").isArray()) {
            arguments.get("commandArgs").forEach(node -> commandArgs.add(node.asText()));
        }

        // Validate input
        if (command.isEmpty() && commandArgs.isEmpty()) {
            return McpUtils.createErrorResponse(
                "Either 'command' (for dangerous execution) or 'commandArgs' array (for safe execution) is required.\n\n" +
                "**Safe execution (recommended):** Use 'commandArgs' as array: [\"ls\", \"-la\", \"/tmp\"]\n" +
                "**Dangerous execution:** Use 'command' as string: \"ls -la /tmp\" (splits on whitespace - injection risk)");
        }

        // Get execution options
        int timeout = McpUtils.getIntParam(arguments, "timeout", 10);
        boolean mergeStderr = McpUtils.getBooleanParam(arguments, "mergeStderr", false);
        boolean allowNonZeroExit = McpUtils.getBooleanParam(arguments, "allowNonZeroExit", false);
        boolean allowTimeout = McpUtils.getBooleanParam(arguments, "allowTimeout", false);

        try {
            ShellUtils shellUtils;
            try {
                shellUtils = api.utilities().shellUtils();
            } catch (NoSuchMethodError e) {
                return McpUtils.createErrorResponse(
                    "Shell execution requires Burp Suite " + Version.MIN_BURP_VERSION + " or later with shellUtils() API support.");
            }

            // Build execution options
            ExecuteOptions options = ExecuteOptions.executeOptions();

            if (timeout == 0) {
                options = options.withTimeout(Duration.ZERO);
            } else {
                options = options.withTimeout(timeout);
            }

            options = options.withTimeoutBehavior(
                allowTimeout ? TimeoutBehavior.ALLOW_TIMEOUT : TimeoutBehavior.FAIL_ON_TIMEOUT);

            options = options.withStderrBehavior(
                mergeStderr ? StderrBehavior.MERGE : StderrBehavior.DISCARD);

            options = options.withExitCodeBehavior(
                allowNonZeroExit ? ExitCodeBehavior.ALLOW_NON_ZERO : ExitCodeBehavior.FAIL_ON_NON_ZERO);

            // Add environment variables if provided
            if (arguments.has("envVars") && arguments.get("envVars").isObject()) {
                Iterator<String> fieldNames = arguments.get("envVars").fieldNames();
                while (fieldNames.hasNext()) {
                    String key = fieldNames.next();
                    String value = arguments.get("envVars").get(key).asText();
                    options = options.withEnvironmentVariable(key, value);
                }
            }

            // Execute command
            String output;
            String executionMode;
            String executedCommand;

            long startTime = System.currentTimeMillis();

            if (dangerous || commandArgs.isEmpty()) {
                // Use dangerouslyExecute - splits on whitespace (injection risk!)
                if (command.isEmpty()) {
                    return McpUtils.createErrorResponse(
                        "For dangerous execution, 'command' string is required.");
                }
                executionMode = "⚠️ DANGEROUS (whitespace-split)";
                executedCommand = command;
                output = shellUtils.dangerouslyExecute(options, command);
            } else {
                // Use safe execute - arguments passed separately
                executionMode = "✅ SAFE (argument array)";
                executedCommand = String.join(" ", commandArgs);
                output = shellUtils.execute(options, commandArgs.toArray(new String[0]));
            }

            long executionTime = System.currentTimeMillis() - startTime;

            if (!McpUtils.isVerbose(arguments)) {
                Map<String, Object> data = new HashMap<>();
                data.put("operation", "shell_execute");
                data.put("mode", (dangerous || commandArgs.isEmpty()) ? "dangerous" : "safe");
                data.put("command", executedCommand);
                data.put("executionTimeMs", executionTime);
                data.put("timeoutSeconds", timeout);
                data.put("mergeStderr", mergeStderr);
                data.put("allowNonZeroExit", allowNonZeroExit);
                data.put("output", output != null ? output : "");
                return McpUtils.createJsonResponse(data);
            }

            StringBuilder result = new StringBuilder();
            result.append("## Shell Execution Result\n\n");
            result.append("**Execution Mode:** ").append(executionMode).append("\n");
            result.append("**Command:** `").append(executedCommand).append("`\n");
            result.append("**Execution Time:** ").append(executionTime).append(" ms\n\n");
            result.append("### Output\n");
            if (output == null || output.isEmpty()) {
                result.append("*(No output)*\n");
            } else {
                result.append("```\n").append(output).append("\n```\n");
            }
            return McpUtils.createSuccessResponse(result.toString());

        } catch (Exception e) {
            StringBuilder error = new StringBuilder();
            error.append("Shell execution failed: ").append(e.getMessage()).append("\n\n");
            error.append("**Common issues:**\n");
            error.append("- Command not found in PATH\n");
            error.append("- Insufficient permissions\n");
            error.append("- Command timed out (default: 10 seconds)\n");
            error.append("- Non-zero exit code (use allowNonZeroExit: true to ignore)\n");

            return McpUtils.createErrorResponse(error.toString());
        }
    }
}