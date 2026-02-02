package com.example.burpmcp;

import burp.api.montoya.MontoyaApi;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Asynchronous request handler for improved performance and non-blocking operations.
 * Manages thread pools, request queuing, and timeout handling.
 */
public class AsyncRequestHandler {
    
    private final MontoyaApi api;
    private final BurpMcpConfig config;
    private final ExecutorService executorService;
    private final ScheduledExecutorService scheduledExecutor;
    private final ObjectMapper objectMapper;
    
    // Request tracking
    private final AtomicLong requestIdCounter = new AtomicLong(0);
    private final Map<Long, CompletableFuture<Object>> pendingRequests = new ConcurrentHashMap<>();
    
    // Rate limiting
    private final Map<String, RateLimiter> rateLimiters = new ConcurrentHashMap<>();
    
    public AsyncRequestHandler(MontoyaApi api) {
        this.api = api;
        this.config = BurpMcpConfig.getInstance();
        this.objectMapper = new ObjectMapper();
        
        // Create thread pool with configured size
        this.executorService = Executors.newFixedThreadPool(
            config.getThreadPoolSize(),
            r -> {
                Thread t = new Thread(r, "burp-mcp-worker");
                t.setDaemon(true);
                return t;
            }
        );
        
        // Scheduled executor for timeouts and cleanup
        this.scheduledExecutor = Executors.newScheduledThreadPool(2, r -> {
            Thread t = new Thread(r, "burp-mcp-scheduler");
            t.setDaemon(true);
            return t;
        });
        
        // Start cleanup task
        startCleanupTask();
    }
    
    /**
     * Execute a tool request asynchronously with timeout and rate limiting.
     */
    public CompletableFuture<Object> executeAsync(String toolName, JsonNode arguments, String clientHost) {
        long requestId = requestIdCounter.incrementAndGet();
        
        // Check rate limiting
        if (config.isEnableRateLimiting() && !checkRateLimit(clientHost)) {
            return CompletableFuture.completedFuture(
                McpUtils.createErrorResponse("Rate limit exceeded for host: " + clientHost)
            );
        }
        
        // Check host access
        if (!config.isHostAllowed(clientHost)) {
            return CompletableFuture.completedFuture(
                McpUtils.createErrorResponse("Host not allowed: " + clientHost)
            );
        }
        
        CompletableFuture<Object> future = CompletableFuture.supplyAsync(() -> {
            try {
                if (config.isEnableAuditLogging()) {
                    api.logging().logToOutput(String.format(
                        "Async request [%d]: %s from %s", requestId, toolName, clientHost
                    ));
                }
                
                // Get the tool and execute
                McpTool tool = McpServer.getToolInstance(toolName, api);
                if (tool == null) {
                    return McpUtils.createErrorResponse("Unknown tool: " + toolName);
                }
                
                return tool.execute(arguments);
                
            } catch (Exception e) {
                String errorMsg = "Error executing tool " + toolName + ": " + e.getMessage();
                api.logging().logToError(McpUtils.sanitizeForLogging(errorMsg));
                return McpUtils.createErrorResponse(errorMsg);
            }
        }, executorService);
        
        // Add timeout
        CompletableFuture<Object> timeoutFuture = addTimeout(future, requestId);
        
        // Track the request
        pendingRequests.put(requestId, timeoutFuture);
        
        // Remove from tracking when completed
        timeoutFuture.whenComplete((result, throwable) -> {
            pendingRequests.remove(requestId);
            
            if (config.isEnableAuditLogging()) {
                if (throwable != null) {
                    api.logging().logToOutput(String.format(
                        "Async request [%d] failed: %s", requestId, throwable.getMessage()
                    ));
                } else {
                    api.logging().logToOutput(String.format(
                        "Async request [%d] completed successfully", requestId
                    ));
                }
            }
        });
        
        return timeoutFuture;
    }
    
    /**
     * Add timeout handling to a future.
     */
    private CompletableFuture<Object> addTimeout(CompletableFuture<Object> future, long requestId) {
        CompletableFuture<Object> timeoutFuture = new CompletableFuture<>();
        
        // Schedule timeout
        ScheduledFuture<?> timeoutTask = scheduledExecutor.schedule(() -> {
            if (!future.isDone()) {
                future.cancel(true);
                timeoutFuture.completeExceptionally(new TimeoutException(
                    "Request " + requestId + " timed out after " + config.getRequestTimeoutMs() + "ms"
                ));
            }
        }, config.getRequestTimeoutMs(), TimeUnit.MILLISECONDS);
        
        // Complete when original future completes
        future.whenComplete((result, throwable) -> {
            timeoutTask.cancel(false); // Cancel timeout
            
            if (throwable != null) {
                if (throwable instanceof CancellationException) {
                    timeoutFuture.completeExceptionally(new TimeoutException(
                        "Request " + requestId + " was cancelled"
                    ));
                } else {
                    timeoutFuture.completeExceptionally(throwable);
                }
            } else {
                timeoutFuture.complete(result);
            }
        });
        
        return timeoutFuture;
    }
    
    /**
     * Check rate limiting for a client host.
     */
    private boolean checkRateLimit(String clientHost) {
        if (!config.isEnableRateLimiting()) {
            return true;
        }
        
        RateLimiter limiter = rateLimiters.computeIfAbsent(clientHost, 
            host -> new RateLimiter(config.getRateLimitRequestsPerMinute())
        );
        
        return limiter.tryAcquire();
    }
    
    /**
     * Start background cleanup task for rate limiters and metrics.
     */
    private void startCleanupTask() {
        scheduledExecutor.scheduleAtFixedRate(() -> {
            try {
                // Clean up expired rate limiters
                long now = System.currentTimeMillis();
                rateLimiters.entrySet().removeIf(entry -> 
                    entry.getValue().isExpired(now)
                );
                
                // Log current status if debug logging is enabled
                if (config.getLogLevel().ordinal() >= BurpMcpConfig.LogLevel.DEBUG.ordinal()) {
                    api.logging().logToOutput(String.format(
                        "AsyncRequestHandler: %d pending requests, %d rate limiters", 
                        pendingRequests.size(), rateLimiters.size()
                    ));
                }
                
            } catch (Exception e) {
                api.logging().logToError("Error in cleanup task: " + McpUtils.sanitizeForLogging(e.getMessage()));
            }
        }, 60, 60, TimeUnit.SECONDS); // Run every minute
    }
    
    /**
     * Get current statistics about the async handler.
     */
    public AsyncStats getStats() {
        return new AsyncStats(
            pendingRequests.size(),
            rateLimiters.size(),
            requestIdCounter.get(),
            executorService instanceof ThreadPoolExecutor ? 
                ((ThreadPoolExecutor) executorService).getActiveCount() : -1
        );
    }
    
    /**
     * Shutdown the async handler gracefully.
     */
    public void shutdown() {
        api.logging().logToOutput("Shutting down AsyncRequestHandler...");
        
        // Cancel all pending requests
        pendingRequests.values().forEach(future -> future.cancel(true));
        pendingRequests.clear();
        
        // Shutdown thread pools
        executorService.shutdown();
        scheduledExecutor.shutdown();
        
        try {
            if (!executorService.awaitTermination(5, TimeUnit.SECONDS)) {
                executorService.shutdownNow();
            }
            if (!scheduledExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                scheduledExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            executorService.shutdownNow();
            scheduledExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }
        
        api.logging().logToOutput("AsyncRequestHandler shutdown complete");
    }
    
    /**
     * Simple rate limiter implementation.
     */
    private static class RateLimiter {
        private final int maxRequests;
        private final long windowMs = TimeUnit.MINUTES.toMillis(1); // 1 minute window
        private final AtomicLong requestCount = new AtomicLong(0);
        private volatile long windowStart = System.currentTimeMillis();
        
        public RateLimiter(int maxRequestsPerMinute) {
            this.maxRequests = maxRequestsPerMinute;
        }
        
        public synchronized boolean tryAcquire() {
            long now = System.currentTimeMillis();
            
            // Reset window if expired
            if (now - windowStart >= windowMs) {
                windowStart = now;
                requestCount.set(0);
            }
            
            // Check if under limit
            if (requestCount.get() < maxRequests) {
                requestCount.incrementAndGet();
                return true;
            }
            
            return false;
        }
        
        public boolean isExpired(long now) {
            // Consider expired if no requests in the last 5 minutes
            return now - windowStart > (5 * windowMs);
        }
    }
    
    /**
     * Statistics about the async handler.
     */
    public static class AsyncStats {
        public final int pendingRequests;
        public final int rateLimiters;
        public final long totalRequests;
        public final int activeThreads;
        
        public AsyncStats(int pendingRequests, int rateLimiters, long totalRequests, int activeThreads) {
            this.pendingRequests = pendingRequests;
            this.rateLimiters = rateLimiters;
            this.totalRequests = totalRequests;
            this.activeThreads = activeThreads;
        }
        
        @Override
        public String toString() {
            return String.format(
                "AsyncStats{pending=%d, rateLimiters=%d, total=%d, activeThreads=%d}",
                pendingRequests, rateLimiters, totalRequests, activeThreads
            );
        }
    }
}