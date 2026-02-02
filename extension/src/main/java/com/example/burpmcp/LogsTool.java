package com.example.burpmcp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import com.fasterxml.jackson.databind.JsonNode;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;

public class LogsTool implements McpTool {
    private final MontoyaApi api;
    private static final int MAX_LOG_ENTRIES = 1000;
    private static final ConcurrentLinkedQueue<LogEntry> outputLogs = new ConcurrentLinkedQueue<>();
    private static final ConcurrentLinkedQueue<LogEntry> errorLogs = new ConcurrentLinkedQueue<>();
    private static final ConcurrentLinkedQueue<LogEntry> eventLogs = new ConcurrentLinkedQueue<>();
    private static boolean interceptorsInstalled = false;
    
    // Static method for other tools to log directly
    public static void logOutput(String message) {
        addStaticLogEntry(outputLogs, "OUTPUT", message);
    }
    
    public static void logError(String message) {
        addStaticLogEntry(errorLogs, "ERROR", message);
    }
    
    private static void addStaticLogEntry(ConcurrentLinkedQueue<LogEntry> queue, String level, String message) {
        if (message == null || message.trim().isEmpty()) {
            return;
        }
        
        LogEntry entry = new LogEntry(level, message, LocalDateTime.now());
        queue.offer(entry);
        
        // Maintain max size
        while (queue.size() > MAX_LOG_ENTRIES) {
            queue.poll();
        }
    }
    
    public LogsTool(MontoyaApi api) {
        this.api = api;
        installLogInterceptors();
    }
    
    private synchronized void installLogInterceptors() {
        if (interceptorsInstalled) {
            return;
        }
        
        try {
            Logging logging = api.logging();
            
            // Intercept output stream
            PrintStream originalOut = logging.output();
            PrintStream interceptedOut = new PrintStream(originalOut) {
                @Override
                public void println(String x) {
                    super.println(x);
                    addLogEntry(outputLogs, "OUTPUT", x);
                }
                
                @Override
                public void print(String s) {
                    super.print(s);
                    addLogEntry(outputLogs, "OUTPUT", s);
                }
            };
            
            // Intercept error stream
            PrintStream originalErr = logging.error();
            PrintStream interceptedErr = new PrintStream(originalErr) {
                @Override
                public void println(String x) {
                    super.println(x);
                    addLogEntry(errorLogs, "ERROR", x);
                }
                
                @Override
                public void print(String s) {
                    super.print(s);
                    addLogEntry(errorLogs, "ERROR", s);
                }
            };
            
            interceptorsInstalled = true;
            api.logging().logToOutput("LogsTool: Log interceptors installed successfully");
            
        } catch (Exception e) {
            // Using the enhanced logToError(String, Throwable) method
            api.logging().logToError("LogsTool: Failed to install log interceptors", e);
        }
    }
    
    private void addLogEntry(ConcurrentLinkedQueue<LogEntry> queue, String level, String message) {
        if (message == null || message.trim().isEmpty()) {
            return;
        }
        
        LogEntry entry = new LogEntry(level, message, LocalDateTime.now());
        queue.offer(entry);
        
        // Maintain max size
        while (queue.size() > MAX_LOG_ENTRIES) {
            queue.poll();
        }
    }
    
    @Override
    public Map<String, Object> getToolInfo() {
        Map<String, Object> tool = new HashMap<>();
        tool.put("name", "burp_logs");
        tool.put("title", "Extension Logs");
        tool.put("description", "Access and manage Burp Suite extension logs. " +
            "Use this to retrieve output logs, error logs, write custom log entries, and raise debug events. " +
            "Actions: GET_LOGS (retrieve logs), WRITE_LOG (add entry), RAISE_EVENT (debug/info/error/critical), CLEAR_LOGS. " +
            "Useful for debugging and monitoring extension behavior.");

        // MCP 2025-06-18 annotations
        Map<String, Object> annotations = new HashMap<>();
        annotations.put("readOnlyHint", false);
        annotations.put("destructiveHint", true);   // CLEAR_LOGS removes data
        annotations.put("idempotentHint", false);
        annotations.put("openWorldHint", false);
        tool.put("annotations", annotations);
        
        Map<String, Object> inputSchema = new HashMap<>();
        Map<String, Object> properties = new HashMap<>();
        
        Map<String, Object> actionProp = new HashMap<>();
        actionProp.put("type", "string");
        List<String> enumValues = Arrays.asList("GET_LOGS", "WRITE_LOG", "RAISE_EVENT", "CLEAR_LOGS");
        actionProp.put("enum", enumValues);
        actionProp.put("description", "The logging action to perform. GET_LOGS retrieves captured logs, WRITE_LOG writes new log entries, RAISE_EVENT creates Burp events, CLEAR_LOGS removes captured logs");
        properties.put("action", actionProp);
        
        Map<String, Object> categoryProp = new HashMap<>();
        categoryProp.put("type", "string");
        List<String> categoryEnum = Arrays.asList("OUTPUT", "ERROR", "ALL");
        categoryProp.put("enum", categoryEnum);
        categoryProp.put("description", "Log category to filter when using GET_LOGS or CLEAR_LOGS. OUTPUT shows standard output logs, ERROR shows error logs, ALL shows both (default: ALL)");
        properties.put("category", categoryProp);
        
        Map<String, Object> messageProp = new HashMap<>();
        messageProp.put("type", "string");
        messageProp.put("description", "Text message to log with WRITE_LOG or event message for RAISE_EVENT. Can be used alone or with exception details");
        properties.put("message", messageProp);
        
        Map<String, Object> objectProp = new HashMap<>();
        objectProp.put("type", "object");
        objectProp.put("description", "Complex object (JSON, array, etc.) to log with WRITE_LOG action. Automatically converted to string. Uses Montoya API's logToOutput(Object) method");
        properties.put("object", objectProp);
        
        Map<String, Object> exceptionMessageProp = new HashMap<>();
        exceptionMessageProp.put("type", "string");
        exceptionMessageProp.put("description", "Exception message for ERROR level logging. Creates a throwable object for detailed error tracking. Uses logToError(Throwable) when stackTrace is not provided");
        properties.put("exceptionMessage", exceptionMessageProp);
        
        Map<String, Object> stackTraceProp = new HashMap<>();
        stackTraceProp.put("type", "string");
        stackTraceProp.put("description", "Stack trace details for exception logging. When provided with message, uses logToError(String, Throwable) for full error context with both message and exception");
        properties.put("stackTrace", stackTraceProp);
        
        Map<String, Object> levelProp = new HashMap<>();
        levelProp.put("type", "string");
        List<String> levelEnum = Arrays.asList("OUTPUT", "ERROR", "DEBUG", "INFO", "WARNING", "CRITICAL");
        levelProp.put("enum", levelEnum);
        levelProp.put("description", "Log level for WRITE_LOG (OUTPUT/ERROR) or event severity for RAISE_EVENT (DEBUG/INFO/WARNING/CRITICAL). Determines where the log appears in Burp");
        properties.put("level", levelProp);
        
        Map<String, Object> limitProp = new HashMap<>();
        limitProp.put("type", "number");
        limitProp.put("description", "Maximum number of log entries to return with GET_LOGS action. Helps manage large log outputs (default: 100, max: 1000)");
        properties.put("limit", limitProp);
        
        inputSchema.put("properties", properties);
        List<String> required = Arrays.asList("action");
        inputSchema.put("required", required);
        inputSchema.put("type", "object");
        
        tool.put("inputSchema", inputSchema);
        return tool;
    }
    
    @Override
    public Object execute(JsonNode arguments) {
        try {
            String action = McpUtils.getStringParam(arguments, "action", "");
            
            switch (action.toUpperCase()) {
                case "GET_LOGS":
                    return getLogs(arguments);
                case "WRITE_LOG":
                    return writeLog(arguments);
                case "RAISE_EVENT":
                    return raiseEvent(arguments);
                case "CLEAR_LOGS":
                    return clearLogs(arguments);
                default:
                    return McpUtils.createErrorResponse("Invalid action: " + action);
            }
        } catch (Exception e) {
            // Using the enhanced logToError(String, Throwable) method
            api.logging().logToError("LogsTool error", e);
            return McpUtils.createErrorResponse("Error: " + e.getMessage());
        }
    }
    
    private Object getLogs(JsonNode arguments) {
        String category = McpUtils.getStringParam(arguments, "category", "ALL").toUpperCase();
        int limit = McpUtils.getIntParam(arguments, "limit", 100);
        limit = Math.min(limit, MAX_LOG_ENTRIES);
        
        StringBuilder result = new StringBuilder();
        result.append("# Burp Suite Logs\n\n");
        
        if (category.equals("ALL") || category.equals("OUTPUT")) {
            result.append("## Output Logs\n\n");
            appendLogs(result, outputLogs, limit);
        }
        
        if (category.equals("ALL") || category.equals("ERROR")) {
            result.append("## Error Logs\n\n");
            appendLogs(result, errorLogs, limit);
        }
        
        if (eventLogs.size() > 0 && category.equals("ALL")) {
            result.append("## Event Logs\n\n");
            appendLogs(result, eventLogs, limit);
        }
        
        // Also capture current extension output
        result.append("\n## Current Session Info\n\n");
        result.append("- Log capture started: ").append(interceptorsInstalled ? "Yes" : "No").append("\n");
        result.append("- Output logs captured: ").append(outputLogs.size()).append("\n");
        result.append("- Error logs captured: ").append(errorLogs.size()).append("\n");
        result.append("- Event logs captured: ").append(eventLogs.size()).append("\n");
        
        return McpUtils.createSuccessResponse(result.toString());
    }
    
    private void appendLogs(StringBuilder result, ConcurrentLinkedQueue<LogEntry> logs, int limit) {
        List<LogEntry> entries = new ArrayList<>(logs);
        int start = Math.max(0, entries.size() - limit);
        
        if (entries.isEmpty()) {
            result.append("*No logs captured*\n\n");
            return;
        }
        
        result.append("```\n");
        for (int i = start; i < entries.size(); i++) {
            LogEntry entry = entries.get(i);
            result.append("[").append(entry.timestamp).append("] ");
            result.append(entry.message).append("\n");
        }
        result.append("```\n\n");
    }
    
    private Object writeLog(JsonNode arguments) {
        String message = McpUtils.getStringParam(arguments, "message", "");
        String level = McpUtils.getStringParam(arguments, "level", "OUTPUT").toUpperCase();
        
        // Check for object logging
        JsonNode objectParam = arguments.get("object");
        boolean hasObject = objectParam != null && !objectParam.isNull();
        
        // Check for exception logging
        String exceptionMessage = McpUtils.getStringParam(arguments, "exceptionMessage", "");
        String stackTrace = McpUtils.getStringParam(arguments, "stackTrace", "");
        boolean hasException = !exceptionMessage.isEmpty() || !stackTrace.isEmpty();
        
        if (message.isEmpty() && !hasObject && !hasException) {
            return McpUtils.createErrorResponse("Message, object, or exception details required for WRITE_LOG action");
        }
        
        Logging logging = api.logging();
        
        switch (level) {
            case "OUTPUT":
                if (hasObject) {
                    // Use logToOutput(Object) for object logging
                    logging.logToOutput(objectParam.toString());
                    addLogEntry(outputLogs, "OUTPUT", "Object: " + objectParam.toString());
                } else {
                    logging.logToOutput(message);
                    addLogEntry(outputLogs, "OUTPUT", message);
                }
                break;
            case "ERROR":
                if (hasException) {
                    // Create a throwable for exception logging
                    Exception simulatedException = new Exception(exceptionMessage != null ? exceptionMessage : "Error logged via MCP");
                    if (!stackTrace.isEmpty()) {
                        // Log with both message and exception
                        logging.logToError(message.isEmpty() ? "Error with exception" : message, simulatedException);
                        addLogEntry(errorLogs, "ERROR", message + " - Exception: " + exceptionMessage + "\n" + stackTrace);
                    } else if (!exceptionMessage.isEmpty()) {
                        // Log just the exception
                        logging.logToError(simulatedException);
                        addLogEntry(errorLogs, "ERROR", "Exception: " + exceptionMessage);
                    }
                } else {
                    logging.logToError(message);
                    addLogEntry(errorLogs, "ERROR", message);
                }
                break;
            default:
                if (hasObject) {
                    logging.logToOutput("[" + level + "] Object: " + objectParam.toString());
                    addLogEntry(outputLogs, level, "Object: " + objectParam.toString());
                } else {
                    logging.logToOutput("[" + level + "] " + message);
                    addLogEntry(outputLogs, level, message);
                }
        }
        
        String successMsg = "Log written successfully: " + level;
        if (hasObject) successMsg += " (object)";
        if (hasException) successMsg += " (with exception)";
        if (!message.isEmpty()) successMsg += " - " + message;
        
        return McpUtils.createSuccessResponse(successMsg);
    }
    
    private Object raiseEvent(JsonNode arguments) {
        String message = McpUtils.getStringParam(arguments, "message", "");
        String level = McpUtils.getStringParam(arguments, "level", "INFO").toUpperCase();
        
        if (message.isEmpty()) {
            return McpUtils.createErrorResponse("Message is required for RAISE_EVENT action");
        }
        
        Logging logging = api.logging();
        
        switch (level) {
            case "DEBUG":
                logging.raiseDebugEvent(message);
                addLogEntry(eventLogs, "DEBUG", message);
                break;
            case "INFO":
                logging.raiseInfoEvent(message);
                addLogEntry(eventLogs, "INFO", message);
                break;
            case "WARNING":
            case "ERROR":
                logging.raiseErrorEvent(message);
                addLogEntry(eventLogs, "ERROR", message);
                break;
            case "CRITICAL":
                logging.raiseCriticalEvent(message);
                addLogEntry(eventLogs, "CRITICAL", message);
                break;
            default:
                logging.raiseInfoEvent(message);
                addLogEntry(eventLogs, "INFO", message);
        }
        
        return McpUtils.createSuccessResponse("Event raised: " + level + " - " + message);
    }
    
    private Object clearLogs(JsonNode arguments) {
        String category = McpUtils.getStringParam(arguments, "category", "ALL").toUpperCase();
        
        int clearedCount = 0;
        
        if (category.equals("ALL") || category.equals("OUTPUT")) {
            clearedCount += outputLogs.size();
            outputLogs.clear();
        }
        
        if (category.equals("ALL") || category.equals("ERROR")) {
            clearedCount += errorLogs.size();
            errorLogs.clear();
        }
        
        if (category.equals("ALL")) {
            clearedCount += eventLogs.size();
            eventLogs.clear();
        }
        
        return McpUtils.createSuccessResponse("Cleared " + clearedCount + " log entries from " + category + " category");
    }
    
    private static class LogEntry {
        final String level;
        final String message;
        final String timestamp;
        
        LogEntry(String level, String message, LocalDateTime time) {
            this.level = level;
            this.message = message;
            this.timestamp = time.format(DateTimeFormatter.ISO_LOCAL_TIME);
        }
    }
}