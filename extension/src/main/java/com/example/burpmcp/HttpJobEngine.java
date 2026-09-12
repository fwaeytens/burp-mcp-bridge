package com.example.burpmcp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.lang.reflect.InvocationTargetException;
import java.util.List;
import java.util.function.Consumer;

/** Keeps the optional 2026.7 API types out of the tool's class-loading path. */
interface HttpJobEngine {
    record Options(String name, int concurrency, long throttleMs, int maxRetries, long timeoutMs) {}
    record Result(int index, String status, HttpRequestResponse exchange) {}
    record Stats(int requested, int completed, int failed, int inFlight, int pending, long elapsedMs) {}
    record Completion(boolean cancelled, Stats stats) {}

    interface Execution {
        void pause();
        void resume();
        void cancel();
        Stats stats();
        /** Release job callbacks when the owning tool is unloaded. */
        default void detach() {}
    }

    /** A submission was attempted; an absent handle means its outcome cannot be polled. */
    final class SubmissionException extends RuntimeException {
        private static final long serialVersionUID = 1L;
        private final Execution execution;

        SubmissionException(Execution execution, Throwable cause) {
            super("Native HTTP job submission may have started: " + cause.getMessage(), cause);
            this.execution = execution;
        }

        Execution execution() {
            return execution;
        }
    }

    /** Callbacks may run before this method returns; register job state before starting. */
    Execution start(List<HttpRequest> requests, Options options,
                    Consumer<Result> onResult, Consumer<Completion> onComplete);

    static HttpJobEngine create(MontoyaApi api) {
        if (api == null) {
            throw new UnsupportedOperationException("Background HTTP jobs require an available Burp Montoya API.");
        }
        try {
            if (!"PROFESSIONAL".equals(api.burpSuite().version().edition().name())) {
                throw new UnsupportedOperationException("Background HTTP jobs require Burp Suite Professional.");
            }
            ClassLoader loader = HttpJobEngine.class.getClassLoader();
            Class<?> options = Class.forName("burp.api.montoya.http.execution.RequestEngineOptions", false, loader);
            Http.class.getMethod("createRequestEngine", options);
            // Referencing the adapter by name allows the other tools to load on older Burp versions.
            return (HttpJobEngine) Class.forName("com.example.burpmcp.MontoyaHttpJobEngine", true, loader)
                .getDeclaredConstructor(MontoyaApi.class).newInstance(api);
        } catch (InvocationTargetException e) {
            throw new UnsupportedOperationException(
                "Background HTTP jobs require a Burp version supporting Montoya API 2026.7 request execution.", e.getCause());
        } catch (ReflectiveOperationException | LinkageError e) {
            throw new UnsupportedOperationException(
                "Background HTTP jobs require a Burp version supporting Montoya API 2026.7 request execution.", e);
        }
    }
}
