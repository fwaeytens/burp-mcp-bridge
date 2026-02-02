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
        tool.put("annotations", annotations);
        
        Map<String, Object> inputSchema = new HashMap<>();
        inputSchema.put("type", "object");
        
        Map<String, Object> properties = new HashMap<>();
        
        properties.put("action", McpUtils.createEnumProperty("string",
            "Utility action to perform",
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

        // Shell execution parameters (NEW in Montoya 2025.12)
        properties.put("command", McpUtils.createProperty("string",
            "Shell command to execute (for shell_execute/shell_execute_dangerous)"));

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
                    return performBase64Encode(input);
                case "base64_decode":
                    return performBase64Decode(input);
                case "url_encode":
                    return performUrlEncode(input);
                case "url_decode":
                    return performUrlDecode(input);
                case "html_encode":
                    return performHtmlEncode(input);
                case "html_decode":
                    return performHtmlDecode(input);
                case "hash":
                    return performHash(input, arguments);
                case "random":
                    return generateRandom(arguments);
                case "compress":
                    return performCompress(input);
                case "decompress":
                    return performDecompress(input);
                case "json_beautify":
                    return performJsonBeautify(input);
                case "json_path":
                    return performJsonPath(input, arguments);
                case "json_validate":
                    return performJsonValidate(input);
                case "hex_to_ascii":
                    return performHexToAscii(input);
                case "ascii_to_hex":
                    return performAsciiToHex(input);
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
    
    private Object performBase64Encode(String input) {
        if (input.isEmpty()) {
            return McpUtils.createErrorResponse("Input is required for base64 encoding");
        }
        
        Base64Utils base64 = api.utilities().base64Utils();
        ByteArray encoded = base64.encode(input);
        
        StringBuilder result = new StringBuilder();
        result.append("## Base64 Encode Result\n\n");
        result.append("**Input:** ").append(McpUtils.truncateText(input, 100)).append("\n");
        result.append("**Input Length:** ").append(input.length()).append(" characters\n\n");
        result.append("**Encoded:**\n```\n").append(encoded.toString()).append("\n```\n");
        result.append("**Encoded Length:** ").append(encoded.length()).append(" characters\n");
        
        return McpUtils.createSuccessResponse(result.toString());
    }
    
    private Object performBase64Decode(String input) {
        if (input.isEmpty()) {
            return McpUtils.createErrorResponse("Input is required for base64 decoding");
        }
        
        try {
            Base64Utils base64 = api.utilities().base64Utils();
            ByteArray decoded = base64.decode(input);
            String decodedString = decoded.toString();
            
            StringBuilder result = new StringBuilder();
            result.append("## Base64 Decode Result\n\n");
            result.append("**Input:** ").append(McpUtils.truncateText(input, 100)).append("\n");
            result.append("**Input Length:** ").append(input.length()).append(" characters\n\n");
            result.append("**Decoded:**\n```\n").append(decodedString).append("\n```\n");
            result.append("**Decoded Length:** ").append(decodedString.length()).append(" characters\n");
            
            // Check if decoded content looks like binary
            boolean isBinary = false;
            for (char c : decodedString.toCharArray()) {
                if (Character.isISOControl(c) && c != '\n' && c != '\r' && c != '\t') {
                    isBinary = true;
                    break;
                }
            }
            
            if (isBinary) {
                result.append("\n⚠️ **Note:** Decoded content appears to be binary data. ");
                result.append("Hex representation:\n```\n");
                result.append(bytesToHex(decoded.getBytes())).append("\n```");
            }
            
            return McpUtils.createSuccessResponse(result.toString());
        } catch (Exception e) {
            return McpUtils.createErrorResponse("Failed to decode base64: " + e.getMessage() + 
                " (input might not be valid base64)");
        }
    }
    
    private Object performUrlEncode(String input) {
        if (input.isEmpty()) {
            return McpUtils.createErrorResponse("Input is required for URL encoding");
        }
        
        URLUtils urlUtils = api.utilities().urlUtils();
        String encoded = urlUtils.encode(input);
        
        StringBuilder result = new StringBuilder();
        result.append("## URL Encode Result\n\n");
        result.append("**Input:** ").append(input).append("\n");
        result.append("**Encoded:** ").append(encoded).append("\n\n");
        
        // Show character-by-character encoding for special chars
        if (!input.equals(encoded)) {
            result.append("**Encoding Details:**\n");
            for (int i = 0; i < input.length(); i++) {
                char c = input.charAt(i);
                String charEncoded = urlUtils.encode(String.valueOf(c));
                if (!String.valueOf(c).equals(charEncoded)) {
                    result.append("- '").append(c).append("' → ").append(charEncoded).append("\n");
                }
            }
        }
        
        return McpUtils.createSuccessResponse(result.toString());
    }
    
    private Object performUrlDecode(String input) {
        if (input.isEmpty()) {
            return McpUtils.createErrorResponse("Input is required for URL decoding");
        }
        
        URLUtils urlUtils = api.utilities().urlUtils();
        String decoded = urlUtils.decode(input);
        
        StringBuilder result = new StringBuilder();
        result.append("## URL Decode Result\n\n");
        result.append("**Input:** ").append(input).append("\n");
        result.append("**Decoded:** ").append(decoded).append("\n");
        
        return McpUtils.createSuccessResponse(result.toString());
    }
    
    private Object performHtmlEncode(String input) {
        if (input.isEmpty()) {
            return McpUtils.createErrorResponse("Input is required for HTML encoding");
        }
        
        HtmlUtils htmlUtils = api.utilities().htmlUtils();
        String encoded = htmlUtils.encode(input);
        
        StringBuilder result = new StringBuilder();
        result.append("## HTML Encode Result\n\n");
        result.append("**Input:** ").append(input).append("\n");
        result.append("**Encoded:** ").append(encoded).append("\n\n");
        
        // Show encoding of special characters
        String[] testChars = {"<", ">", "&", "\"", "'", "/"};
        result.append("**Common HTML Entity Encodings:**\n");
        for (String ch : testChars) {
            if (input.contains(ch)) {
                result.append("- '").append(ch).append("' → ")
                    .append(htmlUtils.encode(ch)).append("\n");
            }
        }
        
        return McpUtils.createSuccessResponse(result.toString());
    }
    
    private Object performHtmlDecode(String input) {
        if (input.isEmpty()) {
            return McpUtils.createErrorResponse("Input is required for HTML decoding");
        }
        
        HtmlUtils htmlUtils = api.utilities().htmlUtils();
        String decoded = htmlUtils.decode(input);
        
        StringBuilder result = new StringBuilder();
        result.append("## HTML Decode Result\n\n");
        result.append("**Input:** ").append(input).append("\n");
        result.append("**Decoded:** ").append(decoded).append("\n");
        
        return McpUtils.createSuccessResponse(result.toString());
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
        
        StringBuilder result = new StringBuilder();
        result.append("## Hash Result\n\n");
        result.append("**Algorithm:** ").append(algorithm).append("\n");
        result.append("**Input:** ").append(McpUtils.truncateText(input, 100)).append("\n");
        result.append("**Hash (hex):** `").append(hashHex).append("`\n");
        result.append("**Hash Length:** ").append(hashHex.length() / 2).append(" bytes\n");
        
        return McpUtils.createSuccessResponse(result.toString());
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
        
        StringBuilder result = new StringBuilder();
        result.append("## Random Data Generation\n\n");
        result.append("**Type:** ").append(type).append("\n");
        result.append("**Length:** ").append(length).append("\n");
        result.append("**Generated:**\n```\n").append(generated).append("\n```\n");
        
        return McpUtils.createSuccessResponse(result.toString());
    }
    
    private Object performCompress(String input) {
        if (input.isEmpty()) {
            return McpUtils.createErrorResponse("Input is required for compression");
        }
        
        try {
            CompressionUtils compression = api.utilities().compressionUtils();
            ByteArray inputBytes = ByteArray.byteArray(input);
            ByteArray compressed = compression.compress(inputBytes, CompressionType.GZIP);
            
            String compressedBase64 = Base64.getEncoder().encodeToString(compressed.getBytes());
            double ratio = (1.0 - (double) compressed.length() / input.length()) * 100;
            
            StringBuilder result = new StringBuilder();
            result.append("## Compression Result (GZIP)\n\n");
            result.append("**Original Size:** ").append(input.length()).append(" bytes\n");
            result.append("**Compressed Size:** ").append(compressed.length()).append(" bytes\n");
            result.append("**Compression Ratio:** ").append(String.format("%.1f%%", ratio)).append("\n\n");
            result.append("**Compressed (Base64):**\n```\n").append(compressedBase64).append("\n```\n");
            
            return McpUtils.createSuccessResponse(result.toString());
        } catch (Exception e) {
            return McpUtils.createErrorResponse("Compression failed: " + e.getMessage());
        }
    }
    
    private Object performDecompress(String input) {
        if (input.isEmpty()) {
            return McpUtils.createErrorResponse("Input is required for decompression");
        }
        
        try {
            CompressionUtils compression = api.utilities().compressionUtils();
            
            // Try to decode from base64 first
            byte[] compressedBytes;
            try {
                compressedBytes = Base64.getDecoder().decode(input);
            } catch (Exception e) {
                return McpUtils.createErrorResponse("Input should be base64-encoded compressed data");
            }
            
            ByteArray compressed = ByteArray.byteArray(compressedBytes);
            ByteArray decompressed = compression.decompress(compressed, CompressionType.GZIP);
            String decompressedString = decompressed.toString();
            
            StringBuilder result = new StringBuilder();
            result.append("## Decompression Result (GZIP)\n\n");
            result.append("**Compressed Size:** ").append(compressed.length()).append(" bytes\n");
            result.append("**Decompressed Size:** ").append(decompressed.length()).append(" bytes\n\n");
            result.append("**Decompressed Content:**\n```\n").append(decompressedString).append("\n```\n");
            
            return McpUtils.createSuccessResponse(result.toString());
        } catch (Exception e) {
            return McpUtils.createErrorResponse("Decompression failed: " + e.getMessage() + 
                " (input might not be valid GZIP data)");
        }
    }
    
    private Object performJsonBeautify(String input) {
        if (input.isEmpty()) {
            return McpUtils.createErrorResponse("Input is required for JSON beautification");
        }
        
        try {
            // Use Jackson for JSON beautification
            com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
            Object json = mapper.readValue(input, Object.class);
            String beautified = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(json);
            
            StringBuilder result = new StringBuilder();
            result.append("## JSON Beautify Result\n\n");
            result.append("**Original Length:** ").append(input.length()).append(" characters\n");
            result.append("**Beautified Length:** ").append(beautified.length()).append(" characters\n\n");
            result.append("**Beautified JSON:**\n```json\n").append(beautified).append("\n```\n");
            
            return McpUtils.createSuccessResponse(result.toString());
        } catch (Exception e) {
            return McpUtils.createErrorResponse("JSON parsing failed: " + e.getMessage() + 
                " (input might not be valid JSON)");
        }
    }
    
    private Object performHexToAscii(String input) {
        if (input.isEmpty()) {
            return McpUtils.createErrorResponse("Input is required for hex to ASCII conversion");
        }
        
        StringUtils stringUtils = api.utilities().stringUtils();
        String ascii = stringUtils.convertHexStringToAscii(input);
        
        StringBuilder result = new StringBuilder();
        result.append("## Hex to ASCII Result\n\n");
        result.append("**Hex Input:** ").append(McpUtils.truncateText(input, 100)).append("\n");
        result.append("**ASCII Output:** ").append(ascii).append("\n");
        
        return McpUtils.createSuccessResponse(result.toString());
    }
    
    private Object performAsciiToHex(String input) {
        if (input.isEmpty()) {
            return McpUtils.createErrorResponse("Input is required for ASCII to hex conversion");
        }
        
        StringUtils stringUtils = api.utilities().stringUtils();
        String hex = stringUtils.convertAsciiToHexString(input);
        
        StringBuilder result = new StringBuilder();
        result.append("## ASCII to Hex Result\n\n");
        result.append("**ASCII Input:** ").append(McpUtils.truncateText(input, 100)).append("\n");
        result.append("**Hex Output:** ").append(hex).append("\n");
        
        return McpUtils.createSuccessResponse(result.toString());
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
        
        StringBuilder result = new StringBuilder();
        result.append("## JSON Path Operation\n\n");
        result.append("**Operation:** ").append(operation).append("\n");
        result.append("**Path:** `").append(jsonPath).append("`\n\n");
        
        try {
            String output;
            switch (operation) {
                case "read":
                    String value = jsonUtils.read(input, jsonPath);
                    if (value != null) {
                        result.append("**Value at path:**\n```json\n").append(value).append("\n```\n");
                        
                        // Try to read as different types
                        Boolean boolValue = jsonUtils.readBoolean(input, jsonPath);
                        Double doubleValue = jsonUtils.readDouble(input, jsonPath);
                        Long longValue = jsonUtils.readLong(input, jsonPath);
                        
                        result.append("\n**Type Information:**\n");
                        if (boolValue != null) result.append("- Boolean: ").append(boolValue).append("\n");
                        if (doubleValue != null) result.append("- Double: ").append(doubleValue).append("\n");
                        if (longValue != null) result.append("- Long: ").append(longValue).append("\n");
                    } else {
                        result.append("No value found at the specified path.\n");
                    }
                    break;
                    
                case "add":
                    if (jsonValue.isEmpty()) {
                        return McpUtils.createErrorResponse("jsonValue is required for add operation");
                    }
                    output = jsonUtils.add(input, jsonPath, jsonValue);
                    result.append("**Added value:** ").append(jsonValue).append("\n\n");
                    result.append("**Result:**\n```json\n").append(output).append("\n```\n");
                    break;
                    
                case "update":
                    if (jsonValue.isEmpty()) {
                        return McpUtils.createErrorResponse("jsonValue is required for update operation");
                    }
                    output = jsonUtils.update(input, jsonPath, jsonValue);
                    result.append("**Updated value:** ").append(jsonValue).append("\n\n");
                    result.append("**Result:**\n```json\n").append(output).append("\n```\n");
                    break;
                    
                case "remove":
                    output = jsonUtils.remove(input, jsonPath);
                    result.append("**Path removed**\n\n");
                    result.append("**Result:**\n```json\n").append(output).append("\n```\n");
                    break;
                    
                default:
                    return McpUtils.createErrorResponse("Unknown JSON operation: " + operation);
            }
            
        } catch (Exception e) {
            return McpUtils.createErrorResponse("JSON path operation failed: " + e.getMessage());
        }
        
        return McpUtils.createSuccessResponse(result.toString());
    }
    
    private Object performJsonValidate(String input) {
        if (input.isEmpty()) {
            return McpUtils.createErrorResponse("Input is required for JSON validation");
        }
        
        JsonUtils jsonUtils = api.utilities().jsonUtils();
        boolean isValid = jsonUtils.isValidJson(input);
        
        StringBuilder result = new StringBuilder();
        result.append("## JSON Validation Result\n\n");
        result.append("**Valid JSON:** ").append(isValid ? "✅ Yes" : "❌ No").append("\n\n");
        
        if (isValid) {
            result.append("The input is valid JSON.\n");
            
            // Try to parse and show structure
            try {
                com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
                Object json = mapper.readValue(input, Object.class);
                String type = json.getClass().getSimpleName();
                result.append("**Root Type:** ").append(type).append("\n");
                
                if (json instanceof Map) {
                    Map<?, ?> map = (Map<?, ?>) json;
                    result.append("**Keys:** ").append(map.keySet()).append("\n");
                } else if (json instanceof List) {
                    List<?> list = (List<?>) json;
                    result.append("**Array Length:** ").append(list.size()).append("\n");
                }
            } catch (Exception e) {
                // Ignore parsing errors
            }
        } else {
            result.append("The input is not valid JSON. Common issues:\n");
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
            
            StringBuilder result = new StringBuilder();
            result.append("## Number Base Conversion\n\n");
            result.append("**Input:** ").append(input).append(" (").append(fromBase).append(")\n");
            result.append("**Output:** ").append(converted).append(" (").append(toBase).append(")\n\n");
            
            // Show all conversions
            result.append("### All Base Representations:\n");
            String decimal;
            if (fromBase.equals("decimal")) {
                decimal = input;
            } else if (fromBase.equals("binary")) {
                decimal = numberUtils.convertBinaryToDecimal(input);
            } else if (fromBase.equals("octal")) {
                decimal = numberUtils.convertOctalToDecimal(input);
            } else {
                decimal = numberUtils.convertHexToDecimal(input);
            }
            
            result.append("- **Binary:** ").append(numberUtils.convertDecimalToBinary(decimal)).append("\n");
            result.append("- **Octal:** ").append(numberUtils.convertDecimalToOctal(decimal)).append("\n");
            result.append("- **Decimal:** ").append(decimal).append("\n");
            result.append("- **Hexadecimal:** ").append(numberUtils.convertDecimalToHex(decimal)).append("\n");
            
            return McpUtils.createSuccessResponse(result.toString());
            
        } catch (Exception e) {
            return McpUtils.createErrorResponse("Number conversion failed: " + e.getMessage() + 
                " (check that input is valid for the source base)");
        }
    }
    
    private Object performByteSearch(String input, JsonNode arguments) {
        if (input.isEmpty()) {
            return McpUtils.createErrorResponse("Input is required for byte search");
        }
        
        String searchPattern = McpUtils.getStringParam(arguments, "searchPattern", "");
        if (searchPattern.isEmpty()) {
            return McpUtils.createErrorResponse("Search pattern is required");
        }
        
        boolean useRegex = McpUtils.getBooleanParam(arguments, "useRegex", false);
        
        ByteUtils byteUtils = api.utilities().byteUtils();
        byte[] inputBytes = input.getBytes(StandardCharsets.UTF_8);
        
        StringBuilder result = new StringBuilder();
        result.append("## Byte Search Results\n\n");
        result.append("**Input Length:** ").append(inputBytes.length).append(" bytes\n");
        result.append("**Search Pattern:** `").append(searchPattern).append("`\n");
        result.append("**Use Regex:** ").append(useRegex).append("\n\n");
        
        try {
            if (useRegex) {
                Pattern pattern = Pattern.compile(searchPattern);
                int count = byteUtils.countMatches(inputBytes, pattern);
                int firstIndex = byteUtils.indexOf(inputBytes, pattern);
                
                result.append("**Matches Found:** ").append(count).append("\n");
                if (firstIndex >= 0) {
                    result.append("**First Match Index:** ").append(firstIndex).append("\n\n");
                    
                    // Find all matches
                    result.append("### Match Locations:\n");
                    String inputStr = new String(inputBytes, StandardCharsets.UTF_8);
                    Matcher matcher = pattern.matcher(inputStr);
                    int matchNum = 0;
                    while (matcher.find() && matchNum < 10) {
                        result.append("- **Index ").append(matcher.start()).append(":** `")
                            .append(matcher.group()).append("`\n");
                        matchNum++;
                    }
                    if (count > 10) {
                        result.append("... and ").append(count - 10).append(" more matches\n");
                    }
                } else {
                    result.append("No matches found.\n");
                }
            } else {
                byte[] searchBytes = searchPattern.getBytes(StandardCharsets.UTF_8);
                int count = byteUtils.countMatches(inputBytes, searchBytes);
                int firstIndex = byteUtils.indexOf(inputBytes, searchBytes);
                
                result.append("**Matches Found:** ").append(count).append("\n");
                if (firstIndex >= 0) {
                    result.append("**First Match Index:** ").append(firstIndex).append("\n\n");
                    
                    // Find all match positions
                    result.append("### Match Positions:\n");
                    int index = firstIndex;
                    int matchCount = 0;
                    while (index >= 0 && matchCount < 10) {
                        result.append("- Index ").append(index).append("\n");
                        index = byteUtils.indexOf(inputBytes, searchBytes, false, index + 1, inputBytes.length);
                        matchCount++;
                    }
                    if (count > 10) {
                        result.append("... and ").append(count - 10).append(" more matches\n");
                    }
                    
                    // Show context around first match
                    result.append("\n### Context (first match):\n```\n");
                    int contextStart = Math.max(0, firstIndex - 20);
                    int contextEnd = Math.min(inputBytes.length, firstIndex + searchBytes.length + 20);
                    String context = new String(inputBytes, contextStart, contextEnd - contextStart, StandardCharsets.UTF_8);
                    result.append(context).append("\n```\n");
                } else {
                    result.append("No matches found.\n");
                }
            }
            
            result.append("\n💡 **Use Cases:**\n");
            result.append("- Finding binary patterns in responses\n");
            result.append("- Locating specific byte sequences\n");
            result.append("- Pattern matching in encoded data\n");
            result.append("- Searching for signatures or magic bytes\n");
            
        } catch (Exception e) {
            return McpUtils.createErrorResponse("Byte search failed: " + e.getMessage());
        }
        
        return McpUtils.createSuccessResponse(result.toString());
    }

    /**
     * Execute shell commands using Montoya 2025.12 ShellUtils API.
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
                    "Shell execution requires Burp Suite 2025.12 or later with shellUtils() API support.");
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

            // Build result
            StringBuilder result = new StringBuilder();
            result.append("## Shell Execution Result\n\n");
            result.append("**Execution Mode:** ").append(executionMode).append("\n");
            result.append("**Command:** `").append(executedCommand).append("`\n");
            result.append("**Timeout:** ").append(timeout == 0 ? "Disabled" : timeout + " seconds").append("\n");
            result.append("**Execution Time:** ").append(executionTime).append(" ms\n");
            result.append("**Merge Stderr:** ").append(mergeStderr).append("\n");
            result.append("**Allow Non-Zero Exit:** ").append(allowNonZeroExit).append("\n\n");

            result.append("### Output\n");
            if (output == null || output.isEmpty()) {
                result.append("*(No output)*\n");
            } else {
                result.append("```\n").append(output).append("\n```\n");
            }

            result.append("\n### ⚠️ Security Notes\n\n");
            if (dangerous || commandArgs.isEmpty()) {
                result.append("**WARNING:** `dangerouslyExecute` was used. This method splits the command string on whitespace, ");
                result.append("which can lead to command injection vulnerabilities if user input is included.\n\n");
                result.append("**Recommended:** Use `shell_execute` with `commandArgs` array for safer execution:\n");
                result.append("```json\n");
                result.append("{\n");
                result.append("  \"action\": \"shell_execute\",\n");
                result.append("  \"commandArgs\": [\"ls\", \"-la\", \"/path/with spaces\"]\n");
                result.append("}\n");
                result.append("```\n");
            } else {
                result.append("**Good:** Safe execution mode was used with argument array. ");
                result.append("Arguments are passed directly to the process without shell interpretation.\n");
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