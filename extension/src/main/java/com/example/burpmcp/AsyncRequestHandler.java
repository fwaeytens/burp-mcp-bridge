package com.example.burpmcp;

import burp.api.montoya.MontoyaApi;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Asynchronous request handler for improved performance and non-blocking operations.
 * Manages thread pools, request queuing, and timeout handling.
 */
public class AsyncRequestHandler implements AsyncToolExecutor {
    
    private final MontoyaApi api;
    private final BurpMcpConfig config;
    private final ExecutorService executorService;
    private final ScheduledExecutorService scheduledExecutor;

    // Registered singleton tool instances (same ordered map McpServer builds from ToolRegistry).
    // Async execution MUST run against these so per-tool in-memory state (e.g.
    // SessionManagementTool's token map, AnnotateTool's handler registry) survives across
    // tools/call requests. Newing up a fresh instance per call silently dropped that state.
    private final Map<String, McpTool> tools;
    
    // Request tracking
    private final AtomicLong requestIdCounter = new AtomicLong(0);
    private final Map<Long, CompletableFuture<Object>> pendingRequests = new ConcurrentHashMap<>();
    
    // Rate limiting
    private final Map<String, RateLimiter> rateLimiters = new ConcurrentHashMap<>();
    // Guarded by this together with request admission and executor shutdown.
    private boolean shutdownStarted;
    
    public AsyncRequestHandler(MontoyaApi api, Map<String, McpTool> tools) {
        this.api = api;
        this.tools = tools;
        this.config = BurpMcpConfig.getInstance();
        
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
    public synchronized CompletableFuture<Object> executeAsync(String toolName, JsonNode arguments, String clientHost) {
        if (shutdownStarted) {
            return CompletableFuture.failedFuture(new RejectedExecutionException("Async request handler is shutting down"));
        }
        long requestId = requestIdCounter.incrementAndGet();
        
        // Check host access
        if (!config.isHostAllowed(clientHost)) {
            return CompletableFuture.completedFuture(
                McpUtils.createErrorResponse("Host not allowed: " + clientHost)
            );
        }

        if (!checkRateLimit(clientHost)) {
            return CompletableFuture.completedFuture(
                McpUtils.createErrorResponse("Rate limit exceeded for host: " + clientHost)
            );
        }
        
        CompletableFuture<Object> resultFuture = new CompletableFuture<>();
        // FutureTask cancellation interrupts the actual worker. Cancelling a
        // CompletableFuture from supplyAsync only changes the reported result.
        FutureTask<Object> task = new FutureTask<>(() -> {
            try {
                if (config.isEnableAuditLogging()) {
                    api.logging().logToOutput(String.format(
                        "Async request [%d]: %s from %s", requestId, toolName, clientHost
                    ));
                }
                
                // Resolve the registered singleton instance (NOT a fresh one) so per-tool
                // in-memory state persists across calls.
                McpTool tool = tools != null ? tools.get(toolName) : null;
                if (tool == null) {
                    return McpUtils.createErrorResponse("Unknown tool: " + toolName);
                }
                
                return tool.execute(arguments);
                
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw e;
            } catch (Exception e) {
                String errorMsg = "Error executing tool " + toolName + ": " + e.getMessage();
                api.logging().logToError(McpUtils.sanitizeForLogging(errorMsg));
                return McpUtils.createErrorResponse(errorMsg);
            }
        }) {
            @Override
            protected void done() {
                try {
                    resultFuture.complete(get());
                } catch (CancellationException e) {
                    resultFuture.cancel(false);
                } catch (ExecutionException e) {
                    resultFuture.completeExceptionally(e.getCause());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    resultFuture.completeExceptionally(e);
                }
            }
        };

        pendingRequests.put(requestId, resultFuture);
        resultFuture.whenComplete((result, throwable) -> {
            if (!task.isDone()) {
                task.cancel(true);
                if (executorService instanceof ThreadPoolExecutor pool) {
                    pool.remove(task);
                }
            }
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

        try {
            int timeoutMs = config.getRequestTimeoutMs();
            ScheduledFuture<?> timeoutTask = scheduledExecutor.schedule(() ->
                resultFuture.completeExceptionally(new TimeoutException(
                    "Request " + requestId + " timed out after " + timeoutMs + "ms"
                )), timeoutMs, TimeUnit.MILLISECONDS);
            resultFuture.whenComplete((result, throwable) -> timeoutTask.cancel(false));
            executorService.execute(task);
        } catch (RejectedExecutionException e) {
            // A request racing with shutdown must complete and leave no tracking entry.
            resultFuture.completeExceptionally(e);
        }

        return resultFuture;
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
        synchronized (this) {
            if (shutdownStarted) {
                return;
            }
            // Close admission before sweeping pending work so a concurrent request
            // cannot be queued after the sweep and lose both its worker and deadline.
            shutdownStarted = true;
            api.logging().logToOutput("Shutting down AsyncRequestHandler...");

            pendingRequests.values().forEach(future -> future.cancel(true));
            pendingRequests.clear();
            executorService.shutdown();
            scheduledExecutor.shutdown();
        }
        
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
