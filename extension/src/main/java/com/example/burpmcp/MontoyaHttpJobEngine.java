package com.example.burpmcp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.execution.ExecutionStats;
import burp.api.montoya.http.execution.RequestEngineOptions;
import burp.api.montoya.http.execution.RequestExecution;
import burp.api.montoya.http.execution.RequestExecutionEngine;
import burp.api.montoya.http.execution.RequestResult;
import burp.api.montoya.http.execution.ResourcePool;
import burp.api.montoya.http.execution.Retention;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicIntegerArray;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

/** The only adapter that links against Montoya's optional native request engine. */
final class MontoyaHttpJobEngine implements HttpJobEngine {
    private final MontoyaApi api;

    MontoyaHttpJobEngine(MontoyaApi api) {
        this.api = Objects.requireNonNull(api, "api");
    }

    @Override
    public Execution start(List<HttpRequest> requests, Options options,
                           Consumer<Result> onResult, Consumer<Completion> onComplete) {
        List<HttpRequest> batch = List.copyOf(requests);
        Objects.requireNonNull(options, "options");
        Objects.requireNonNull(onResult, "onResult");
        Objects.requireNonNull(onComplete, "onComplete");
        if (options.timeoutMs() <= 0) throw new IllegalArgumentException("Request timeout must be positive.");

        RequestExecutionEngine engine = createEngine(options);
        for (int index = 0; index < batch.size(); index++) {
            engine.queue(batch.get(index), Integer.toString(index));
        }

        int requestCount = batch.size();
        AtomicIntegerArray delivered = new AtomicIntegerArray(requestCount);
        AtomicInteger deliveredCount = new AtomicInteger();
        AtomicBoolean deliveryFailed = new AtomicBoolean();
        AtomicBoolean cancellationRequested = new AtomicBoolean();
        AtomicReference<Stats> terminalStats = new AtomicReference<>();
        AtomicReference<Consumer<Result>> resultCallback = new AtomicReference<>(onResult);
        AtomicReference<Consumer<Completion>> completionCallback = new AtomicReference<>(onComplete);
        Runnable detach = () -> {
            resultCallback.set(null);
            completionCallback.set(null);
        };
        Consumer<RequestResult> deliver = result -> {
            Consumer<Result> callback = resultCallback.get();
            if (callback == null) return;
            int index = Integer.parseInt(result.label());
            if (index < 0 || index >= requestCount) {
                throw new IllegalStateException("Native request engine returned an invalid request index: " + index);
            }
            if (delivered.compareAndSet(index, 0, 1)) {
                deliveredCount.incrementAndGet();
                callback.accept(new Result(index, result.status().name(), result.requestResponse()));
            }
        };

        final RequestExecution execution;
        try {
            execution = engine.sendAll((result, running) -> {
                try {
                    deliver.accept(result);
                    // The tool owns bounded retention; never retain a second copy in Burp.
                    return Retention.DROP;
                } catch (RuntimeException | Error failure) {
                    deliveryFailed.set(true);
                    resultCallback.set(null);
                    // Completion must still notify the owner once in-flight work drains.
                    cancelAfterFailure(running, failure, cancellationRequested);
                    throw failure;
                }
            }, Duration.ofMillis(options.timeoutMs()));
        } catch (RuntimeException | Error failure) {
            detach.run();
            throw new SubmissionException(null, failure);
        }

        Execution handle = new Execution() {
            @Override public void pause() { execution.lifetime().pause(); }
            @Override public void resume() { execution.lifetime().resume(); }
            @Override public void cancel() {
                cancellationRequested.set(true);
                execution.lifetime().cancel();
            }
            @Override public Stats stats() {
                // Burp admits queued inputs lazily. On cancellation its final requested
                // count can exclude inputs that were never admitted to the native run.
                Stats cached = terminalStats.get();
                if (cached != null) return cached;
                ExecutionStats current = execution.stats();
                // Registration can fail, so a cancelled execution may have no callback.
                // Never await completion here: the caller may hold the job's callback lock.
                boolean cancelledAndDrained = cancellationRequested.get()
                    && nativeDrained(current, requestCount) && execution.lifetime().finished();
                return MontoyaHttpJobEngine.stats(current, requestCount, cancelledAndDrained);
            }
            @Override public void detach() { detach.run(); }
        };

        try {
            AtomicBoolean completed = new AtomicBoolean();
            execution.lifetime().onComplete(result -> {
                if (!completed.compareAndSet(false, true)) return;
                try {
                    // Publish terminal counters before invoking any owning-tool callback.
                    // Cache counters only; retaining the native result could retain requests.
                    terminalStats.set(stats(result.stats(), requestCount, result.cancelled()));
                    // Requests abandoned on cancellation do not reach the response handler.
                    // Deduplication also protects against an already-reported retained result.
                    try {
                        for (RequestResult remaining : result.results()) deliver.accept(remaining);
                        ExecutionStats nativeStats = result.stats();
                        boolean admittedResultsAccounted = !deliveryFailed.get()
                            && deliveredCount.get() == nativeStats.requested()
                            && nativeDrained(nativeStats, requestCount);
                        if (result.cancelled() && admittedResultsAccounted) {
                            // The remaining indexes were never admitted, so none were sent.
                            // A missing admitted result cannot safely be classified this way.
                            Consumer<Result> callback = resultCallback.get();
                            if (callback != null) {
                                for (int index = 0; index < requestCount; index++) {
                                    if (delivered.compareAndSet(index, 0, 1)) {
                                        callback.accept(new Result(index, "DROPPED", null));
                                    }
                                }
                            }
                        }
                    } finally {
                        Consumer<Completion> callback = completionCallback.getAndSet(null);
                        resultCallback.set(null);
                        if (callback != null) {
                            callback.accept(new Completion(result.cancelled(), terminalStats.get()));
                        }
                    }
                } catch (RuntimeException | Error failure) {
                    cancelAfterFailure(execution, failure, cancellationRequested);
                    throw failure;
                } finally {
                    detach.run();
                }
            });
            return handle;
        } catch (RuntimeException | Error failure) {
            detach.run();
            cancelAfterFailure(execution, failure, cancellationRequested);
            throw new SubmissionException(handle, failure);
        }
    }

    private RequestExecutionEngine createEngine(Options options) {
        try {
            ResourcePool pool = ResourcePool.resourcePool()
                .withConcurrentRequestLimit(options.concurrency())
                .withThrottle(Duration.ofMillis(options.throttleMs()))
                .withMaxRetries(options.maxRetries());
            RequestEngineOptions engineOptions = RequestEngineOptions.requestEngineOptions()
                .withName(options.name()).withResourcePool(pool);
            return api.http().createRequestEngine(engineOptions);
        } catch (LinkageError e) {
            // This happens before any submission; a partially available API is unsupported.
            throw new UnsupportedOperationException(
                "Background HTTP jobs require a Burp version supporting Montoya API 2026.7 request execution.", e);
        }
    }

    private static Stats stats(ExecutionStats stats, int requestCount, boolean cancelled) {
        int unadmitted = Math.max(0, requestCount - stats.requested());
        return new Stats(requestCount, stats.completed(), stats.failed() + (cancelled ? unadmitted : 0),
            stats.inFlight(), cancelled ? 0 : stats.pending() + unadmitted, stats.elapsed().toMillis());
    }

    private static boolean nativeDrained(ExecutionStats stats, int requestCount) {
        return stats.requested() >= 0 && stats.requested() <= requestCount
            && stats.inFlight() == 0 && stats.pending() == 0
            && stats.completed() >= 0 && stats.failed() >= 0
            && stats.completed() + stats.failed() == stats.requested();
    }

    private static void cancelAfterFailure(RequestExecution execution, Throwable failure, AtomicBoolean cancellationRequested) {
        cancellationRequested.set(true);
        try {
            execution.lifetime().cancel();
        } catch (RuntimeException | Error cleanupFailure) {
            if (cleanupFailure != failure) failure.addSuppressed(cleanupFailure);
        }
    }
}
