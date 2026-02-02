package com.example.burpmcp;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * Centralized configuration management for Burp MCP Bridge.
 * Provides configurable settings for performance, security, and behavior.
 */
public class BurpMcpConfig {
    
    // Server Configuration
    private static final int DEFAULT_PORT = 8081;
    private static final long DEFAULT_MAX_REQUEST_BYTES = 5 * 1024 * 1024; // 5MB guardrail
    private static final int DEFAULT_REQUEST_TIMEOUT = 30000; // 30 seconds
    private static final int DEFAULT_MAX_RESPONSE_SIZE = 100000; // tokens

    // Performance Configuration
    private static final int DEFAULT_THREAD_POOL_SIZE = 10;
    private static final boolean DEFAULT_ENABLE_CACHING = false;
    private static final long DEFAULT_CACHE_TTL = TimeUnit.MINUTES.toMillis(5);

    // Security Configuration
    private static final boolean DEFAULT_ENABLE_RATE_LIMITING = false;
    private static final int DEFAULT_RATE_LIMIT_REQUESTS = 100; // per minute
    private static final boolean DEFAULT_ENABLE_AUDIT_LOGGING = true;
    
    // Instance fields
    private int serverPort;
    private String serverHost;
    private long maxRequestBytes;
    private int requestTimeoutMs;
    private int maxResponseSizeTokens;
    private int threadPoolSize;
    private boolean enableCaching;
    private long cacheTtlMs;
    private boolean enableRateLimiting;
    private int rateLimitRequestsPerMinute;
    private boolean enableAuditLogging;
    private Set<String> allowedHosts;
    private LogLevel logLevel;
    private boolean enableMetrics;
    private int maxProxyHistoryItems;
    private int scanStatusPageSize;
    
    // Singleton instance
    private static BurpMcpConfig instance;
    
    public enum LogLevel {
        ERROR, WARN, INFO, DEBUG, TRACE
    }
    
    private BurpMcpConfig() {
        // Initialize with default values
        this.serverPort = DEFAULT_PORT;
        this.serverHost = "127.0.0.1";
        this.maxRequestBytes = DEFAULT_MAX_REQUEST_BYTES;
        this.requestTimeoutMs = DEFAULT_REQUEST_TIMEOUT;
        this.maxResponseSizeTokens = DEFAULT_MAX_RESPONSE_SIZE;
        this.threadPoolSize = DEFAULT_THREAD_POOL_SIZE;
        this.enableCaching = DEFAULT_ENABLE_CACHING;
        this.cacheTtlMs = DEFAULT_CACHE_TTL;
        this.enableRateLimiting = DEFAULT_ENABLE_RATE_LIMITING;
        this.rateLimitRequestsPerMinute = DEFAULT_RATE_LIMIT_REQUESTS;
        this.enableAuditLogging = DEFAULT_ENABLE_AUDIT_LOGGING;
        this.allowedHosts = new HashSet<>();
        this.logLevel = LogLevel.INFO;
        this.enableMetrics = true;
        this.maxProxyHistoryItems = Integer.MAX_VALUE;
        this.scanStatusPageSize = Integer.MAX_VALUE;
        
        // Add localhost by default
        this.allowedHosts.add("localhost");
        this.allowedHosts.add("127.0.0.1");
    }
    
    /**
     * Get the singleton configuration instance.
     */
    public static synchronized BurpMcpConfig getInstance() {
        if (instance == null) {
            instance = new BurpMcpConfig();
        }
        return instance;
    }
    
    /**
     * Load configuration from system properties or environment variables.
     * System properties take precedence over environment variables.
     */
    public void loadFromSystemProperties() {
        // Server configuration
        this.serverPort = getIntProperty("burp.mcp.server.port", "BURP_MCP_SERVER_PORT", this.serverPort);
        this.serverHost = getStringProperty("burp.mcp.server.host", "BURP_MCP_SERVER_HOST", this.serverHost);
        this.maxRequestBytes = getLongProperty("burp.mcp.request.maxbytes", "BURP_MCP_REQUEST_MAXBYTES", this.maxRequestBytes);
        this.requestTimeoutMs = getIntProperty("burp.mcp.request.timeout", "BURP_MCP_REQUEST_TIMEOUT", this.requestTimeoutMs);
        this.maxResponseSizeTokens = getIntProperty("burp.mcp.response.maxsize", "BURP_MCP_RESPONSE_MAXSIZE", this.maxResponseSizeTokens);
        
        // Performance configuration
        this.threadPoolSize = getIntProperty("burp.mcp.threadpool.size", "BURP_MCP_THREADPOOL_SIZE", this.threadPoolSize);
        this.enableCaching = getBooleanProperty("burp.mcp.cache.enabled", "BURP_MCP_CACHE_ENABLED", this.enableCaching);
        this.cacheTtlMs = getLongProperty("burp.mcp.cache.ttl", "BURP_MCP_CACHE_TTL", this.cacheTtlMs);
        
        // Security configuration
        this.enableRateLimiting = getBooleanProperty("burp.mcp.ratelimit.enabled", "BURP_MCP_RATELIMIT_ENABLED", this.enableRateLimiting);
        this.rateLimitRequestsPerMinute = getIntProperty("burp.mcp.ratelimit.requests", "BURP_MCP_RATELIMIT_REQUESTS", this.rateLimitRequestsPerMinute);
        this.enableAuditLogging = getBooleanProperty("burp.mcp.audit.enabled", "BURP_MCP_AUDIT_ENABLED", this.enableAuditLogging);
        
        // Tool-specific configuration
        this.maxProxyHistoryItems = getIntProperty("burp.mcp.proxy.maxitems", "BURP_MCP_PROXY_MAXITEMS", this.maxProxyHistoryItems);
        this.scanStatusPageSize = getIntProperty("burp.mcp.scan.pagesize", "BURP_MCP_SCAN_PAGESIZE", this.scanStatusPageSize);
        
        // Log level
        String logLevelStr = getStringProperty("burp.mcp.log.level", "BURP_MCP_LOG_LEVEL", this.logLevel.name());
        try {
            this.logLevel = LogLevel.valueOf(logLevelStr.toUpperCase());
        } catch (IllegalArgumentException e) {
            // Keep default if invalid
        }
        
        // Allowed hosts (comma-separated)
        String allowedHostsStr = getStringProperty("burp.mcp.allowed.hosts", "BURP_MCP_ALLOWED_HOSTS", "");
        if (!allowedHostsStr.isEmpty()) {
            String[] hosts = allowedHostsStr.split(",");
            for (String host : hosts) {
                this.allowedHosts.add(host.trim());
            }
        }
    }
    
    // Utility methods for property resolution
    private int getIntProperty(String systemProp, String envVar, int defaultValue) {
        String value = System.getProperty(systemProp);
        if (value == null) {
            value = System.getenv(envVar);
        }
        if (value != null) {
            try {
                return Integer.parseInt(value);
            } catch (NumberFormatException e) {
                // Return default if invalid
            }
        }
        return defaultValue;
    }
    
    private long getLongProperty(String systemProp, String envVar, long defaultValue) {
        String value = System.getProperty(systemProp);
        if (value == null) {
            value = System.getenv(envVar);
        }
        if (value != null) {
            try {
                return Long.parseLong(value);
            } catch (NumberFormatException e) {
                // Return default if invalid
            }
        }
        return defaultValue;
    }
    
    private boolean getBooleanProperty(String systemProp, String envVar, boolean defaultValue) {
        String value = System.getProperty(systemProp);
        if (value == null) {
            value = System.getenv(envVar);
        }
        if (value != null) {
            return Boolean.parseBoolean(value);
        }
        return defaultValue;
    }
    
    private String getStringProperty(String systemProp, String envVar, String defaultValue) {
        String value = System.getProperty(systemProp);
        if (value == null) {
            value = System.getenv(envVar);
        }
        return value != null ? value : defaultValue;
    }
    
    /**
     * Check if a host is allowed to make requests.
     */
    public boolean isHostAllowed(String host) {
        if (allowedHosts.isEmpty()) {
            return true; // Allow all if no restrictions
        }
        return allowedHosts.contains(host) || allowedHosts.contains("*");
    }
    
    /**
     * Get configuration summary for debugging.
     */
    public String getConfigSummary() {
        StringBuilder sb = new StringBuilder();
        sb.append("Burp MCP Configuration:\n");
        sb.append("  Server Port: ").append(serverPort).append("\n");
        sb.append("  Server Host: ").append(serverHost).append("\n");
        sb.append("  Max Request Size: ").append(maxRequestBytes).append(" bytes\n");
        sb.append("  Request Timeout: ").append(requestTimeoutMs).append("ms\n");
        sb.append("  Max Response Size: ").append(maxResponseSizeTokens).append(" tokens\n");
        sb.append("  Thread Pool Size: ").append(threadPoolSize).append("\n");
        sb.append("  Caching Enabled: ").append(enableCaching).append("\n");
        sb.append("  Cache TTL: ").append(cacheTtlMs).append("ms\n");
        sb.append("  Rate Limiting: ").append(enableRateLimiting).append("\n");
        sb.append("  Rate Limit: ").append(rateLimitRequestsPerMinute).append("/min\n");
        sb.append("  Audit Logging: ").append(enableAuditLogging).append("\n");
        sb.append("  Log Level: ").append(logLevel).append("\n");
        sb.append("  Allowed Hosts: ").append(allowedHosts).append("\n");
        sb.append("  Max Proxy Items: ").append(maxProxyHistoryItems).append("\n");
        sb.append("  Scan Page Size: ").append(scanStatusPageSize).append("\n");
        return sb.toString();
    }
    
    // Getters and setters
    public int getServerPort() { return serverPort; }
    public void setServerPort(int serverPort) { this.serverPort = serverPort; }

    public String getServerHost() { return serverHost; }
    public void setServerHost(String serverHost) { this.serverHost = serverHost; }

    public long getMaxRequestBytes() { return maxRequestBytes; }
    public void setMaxRequestBytes(long maxRequestBytes) { this.maxRequestBytes = maxRequestBytes; }
    
    public int getRequestTimeoutMs() { return requestTimeoutMs; }
    public void setRequestTimeoutMs(int requestTimeoutMs) { this.requestTimeoutMs = requestTimeoutMs; }
    
    public int getMaxResponseSizeTokens() { return maxResponseSizeTokens; }
    public void setMaxResponseSizeTokens(int maxResponseSizeTokens) { this.maxResponseSizeTokens = maxResponseSizeTokens; }
    
    public int getThreadPoolSize() { return threadPoolSize; }
    public void setThreadPoolSize(int threadPoolSize) { this.threadPoolSize = threadPoolSize; }
    
    public boolean isEnableCaching() { return enableCaching; }
    public void setEnableCaching(boolean enableCaching) { this.enableCaching = enableCaching; }
    
    public long getCacheTtlMs() { return cacheTtlMs; }
    public void setCacheTtlMs(long cacheTtlMs) { this.cacheTtlMs = cacheTtlMs; }
    
    public boolean isEnableRateLimiting() { return enableRateLimiting; }
    public void setEnableRateLimiting(boolean enableRateLimiting) { this.enableRateLimiting = enableRateLimiting; }
    
    public int getRateLimitRequestsPerMinute() { return rateLimitRequestsPerMinute; }
    public void setRateLimitRequestsPerMinute(int rateLimitRequestsPerMinute) { this.rateLimitRequestsPerMinute = rateLimitRequestsPerMinute; }
    
    public boolean isEnableAuditLogging() { return enableAuditLogging; }
    public void setEnableAuditLogging(boolean enableAuditLogging) { this.enableAuditLogging = enableAuditLogging; }
    
    public Set<String> getAllowedHosts() { return new HashSet<>(allowedHosts); }
    public void setAllowedHosts(Set<String> allowedHosts) { this.allowedHosts = new HashSet<>(allowedHosts); }
    public void addAllowedHost(String host) { this.allowedHosts.add(host); }
    public void removeAllowedHost(String host) { this.allowedHosts.remove(host); }
    
    public LogLevel getLogLevel() { return logLevel; }
    public void setLogLevel(LogLevel logLevel) { this.logLevel = logLevel; }
    
    public boolean isEnableMetrics() { return enableMetrics; }
    public void setEnableMetrics(boolean enableMetrics) { this.enableMetrics = enableMetrics; }
    
    public int getMaxProxyHistoryItems() { return maxProxyHistoryItems; }
    public void setMaxProxyHistoryItems(int maxProxyHistoryItems) { this.maxProxyHistoryItems = maxProxyHistoryItems; }
    
    public int getScanStatusPageSize() { return scanStatusPageSize; }
    public void setScanStatusPageSize(int scanStatusPageSize) { this.scanStatusPageSize = scanStatusPageSize; }
}
