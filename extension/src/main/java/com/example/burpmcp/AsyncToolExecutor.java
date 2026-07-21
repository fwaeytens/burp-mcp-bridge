package com.example.burpmcp;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.concurrent.CompletableFuture;

/**
 * Small dispatch seam used by the JSON-RPC layer and its contract tests.
 */
interface AsyncToolExecutor {
    CompletableFuture<Object> executeAsync(String toolName, JsonNode arguments, String clientHost);

    Object getStats();
}
