package com.example.burpmcp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.Base64;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.function.LongSupplier;

/** Finite, managed HTTP batches whose lifetime is independent of an MCP call. */
public final class HttpJobsTool implements McpTool {
    private static final List<String> ACTIONS = List.of("START", "LIST", "STATUS", "RESULTS", "PAUSE", "RESUME", "CANCEL");
    private static final Set<String> START_FIELDS = Set.of("action", "requests", "use_https", "name",
        "max_concurrency", "delay_ms", "max_retries", "response_timeout");
    private static final ObjectMapper JSON = new ObjectMapper();
    // The bridge caps complete MCP responses at 95,000 characters. JSON is included
    // both as text and structuredContent, so budget the fully wrapped page as well.
    private static final int PAGE_CHARS = 80_000;
    private static final Limits DEFAULT_LIMITS = new Limits(4, 20, 50, 10 * 1024 * 1024L, 16 * 1024, 3_600_000L);

    record Limits(int activeJobs, int storedJobs, int concurrency, long retainedBytes, int previewBytes, long ttlMs) { }

    private final Object lock = new Object();
    private final MontoyaApi api;
    private final Function<JsonNode, List<HttpRequest>> prepare;
    private final LongSupplier clock;
    private final Limits limits;
    private final Map<String, Job> jobs = new LinkedHashMap<>();
    private HttpJobEngine engine;
    private boolean engineResolved;
    private String unavailableReason;
    private ScheduledExecutorService cleanup;
    private boolean closed;

    public HttpJobsTool(MontoyaApi api) {
        this.api = api;
        this.prepare = new HttpJobRequests(api)::prepare;
        this.clock = System::currentTimeMillis;
        this.limits = DEFAULT_LIMITS;
    }

    HttpJobsTool(HttpJobEngine engine, Function<JsonNode, List<HttpRequest>> prepare, LongSupplier clock, Limits limits) {
        this.api = null;
        this.engine = engine;
        this.engineResolved = true;
        this.prepare = prepare;
        this.clock = clock;
        this.limits = limits;
    }

    @Override
    public Map<String, Object> getToolInfo() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("action", Map.of("type", "string", "enum", ACTIONS, "description", "START a finite batch; LIST jobs; STATUS, RESULTS, PAUSE, RESUME or CANCEL using job_id."));
        properties.put("requests", Map.of("type", "array", "minItems", 1, "maxItems", 1000,
            "items", Map.of("type", "string"), "description", "START: raw HTTP requests with valid framing/body lengths, or full http(s) URLs (sent as GET). Internal ceiling 10 MiB; configured transport limits may be smaller (default extension 5 MiB, HTTP bridge 1 MiB). Put authentication headers in the requests; no automatic cookie-jar or proxy-history injection."));
        properties.put("job_id", Map.of("type", "string", "description", "Job ID returned by START; required except for START and LIST."));
        properties.put("name", Map.of("type", "string", "minLength", 1, "maxLength", 120, "description", "START: name shown in the Burp Dashboard."));
        properties.put("use_https", Map.of("type", "boolean", "description", "START: optional TLS override for raw origin-form requests. When omitted, Host port 80 uses HTTP; port 443, other ports, and a missing port default to HTTPS. Full URL and raw absolute-form URL schemes take precedence."));
        properties.put("max_concurrency", number("START: maximum in-flight requests; all active jobs together are limited to 50.", 10, 1, 50));
        properties.put("delay_ms", number("START: minimum dispatch gap in milliseconds for this job.", 0, 0, 60_000));
        properties.put("max_retries", number("START: retries for transport failures; default 0. Retrying can repeat a state-changing request.", 0, 0, 3));
        properties.put("response_timeout", number("START: finite timeout per request attempt, in milliseconds.", 30_000, 1, 300_000));
        properties.put("offset", number("RESULTS: zero-based input index. Pagination stays stable while requests complete; revisit pending entries later.", 0, 0, 1000));
        properties.put("limit", number("RESULTS: maximum entries in the page. Large pages are shortened to fit the MCP response limit; follow next_offset.", 20, 1, 100));
        properties.put("include_response", Map.of("type", "boolean", "default", false,
            "description", "RESULTS: include base64-encoded raw response previews, capped at 16 KiB each and 10 MiB per job. Check response_truncated and preview_bytes."));
        Map<String, Object> tool = new LinkedHashMap<>();
        tool.put("name", "burp_http_jobs");
        tool.put("title", "Background HTTP Jobs");
        tool.put("description", "Run finite HTTP batches in Burp's managed background engine (Professional with Montoya execution API 2026.7). "
            + "START returns a job_id immediately; use STATUS and paginated RESULTS, or PAUSE/RESUME/CANCEL. "
            + "CANCEL stops scheduling and reports cancelling until in-flight requests finish. State tracks MCP controls and native completion; Dashboard pause/resume cannot be queried, so consult progress after Dashboard changes. "
            + "Direct managed HTTP only: use burp_custom_http for proxy routing, explicit protocol, SNI, connection reuse or byte-sensitive requests. "
            + "No automatic retries by default. Up to 4 active jobs, 50 aggregate concurrency and 20 stored jobs; completed jobs expire after one hour or are evicted oldest-first to admit a new job. "
            + "Results remain in input order with PENDING placeholders; previews are bounded and truncation is explicit. Jobs and stored results are cleared on extension unload. LIST reports engine availability. "
            + "If submission fails after sending may have begun, the job keeps its capacity reservation until confirmed drained; submission_uncertain without a handle requires extension unload to release it.");
        tool.put("inputSchema", Map.of("type", "object", "properties", properties, "required", List.of("action"), "additionalProperties", false));
        tool.put("outputSchema", resultSchema());
        tool.put("annotations", Map.of("readOnlyHint", false, "destructiveHint", true, "idempotentHint", false, "openWorldHint", true));
        tool.put("_meta", Map.of("anthropic/searchHint", "background HTTP batch jobs progress pagination pause resume cancel managed engine"));
        return tool;
    }

    private static Map<String, Object> resultSchema() {
        Map<String, Object> progress = new LinkedHashMap<>();
        progress.put("requested", count("Total inputs in this finite batch, including requests not yet admitted by the native engine."));
        progress.put("completed", count("Requests that received a response, including HTTP error responses."));
        progress.put("failed", count("Requests that failed or were dropped; includes confirmed unscheduled requests after cancellation."));
        progress.put("in_flight", count("Requests currently executing in the native engine."));
        progress.put("pending", count("Inputs still pending, including requests not yet admitted by the native engine."));
        progress.put("elapsed_ms", count("Elapsed execution time in milliseconds."));

        Map<String, Object> job = new LinkedHashMap<>();
        job.put("job_id", SchemaHelper.stringProp("Job ID used for STATUS, RESULTS, PAUSE, RESUME, and CANCEL."));
        job.put("name", SchemaHelper.stringProp("Job label shown in Burp Dashboard."));
        job.put("state", SchemaHelper.enumProp("Job lifecycle. completed may include failed requests; inspect progress and individual results. submission_uncertain retains capacity until extension unload when no native handle exists.",
            List.of("starting", "running", "paused", "cancelling", "completed", "cancelled", "failed", "submission_uncertain")));
        job.put("state_source", SchemaHelper.enumProp("Pause/resume reflects MCP controls. Dashboard pause/resume affects progress but cannot be queried directly; native completion and cancellation update state.",
            List.of("mcp_controls_and_native_completion")));
        job.put("total_requests", count("Number of submitted input requests; result indices range from 0 through total_requests - 1."));
        job.put("max_concurrency", count("Concurrency reserved by this job while it remains active."));
        job.put("created_at", count("Creation time as Unix epoch milliseconds."));
        job.put("finished_at", count("Terminal-state time as Unix epoch milliseconds; absent while active."));
        job.put("expires_at", count("Retention expiry as Unix epoch milliseconds; absent while active."));
        job.put("retained_response_bytes", count("Total raw response-preview bytes retained for this job."));
        job.put("truncated_results", count("Number of results whose response previews were truncated or could not be fully captured."));
        job.put("progress", outputObject(progress, List.of("requested", "completed", "failed", "in_flight", "pending", "elapsed_ms")));
        job.put("stats_error", SchemaHelper.stringProp("Diagnostic when native progress could not be read; progress may be unavailable."));
        job.put("message", SchemaHelper.stringProp("Submission or execution diagnostic. Inspect job_id before retrying a submission failure."));

        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("index", count("Zero-based position in the original requests array; stable regardless of completion order."));
        entry.put("url", SchemaHelper.stringProp("Request URL, capped at 2048 characters."));
        entry.put("url_truncated", SchemaHelper.boolProp("True when the URL was shortened."));
        entry.put("status", SchemaHelper.enumProp("PENDING awaits an outcome; RESPONDED includes HTTP error statuses; TIMED_OUT and CONNECTION_FAILED are transport failures; DROPPED means confirmed not sent; UNKNOWN means the final outcome cannot be established.",
            List.of("PENDING", "RESPONDED", "TIMED_OUT", "CONNECTION_FAILED", "DROPPED", "UNKNOWN")));
        entry.put("status_code", SchemaHelper.intProp("HTTP response status when a response is available."));
        entry.put("response_length", count("Full raw response size in bytes before preview truncation."));
        entry.put("body_length", count("Response body size in bytes before preview truncation."));
        entry.put("preview_bytes", count("Number of raw response bytes retained; can be zero when the retention budget is exhausted."));
        entry.put("response_truncated", SchemaHelper.boolProp("True when the full response was not retained. Check this even when include_response is false."));
        entry.put("response_base64", Map.of("type", "string", "contentEncoding", "base64",
            "description", "Base64-encoded raw HTTP response preview, present only when include_response is true and bytes were retained. It may be incomplete; inspect response_truncated and preview_bytes."));
        entry.put("error", SchemaHelper.stringProp("Diagnostic when response capture failed."));

        Map<String, Object> limitsSchema = new LinkedHashMap<>();
        limitsSchema.put("active_jobs", count("Maximum active jobs, including paused or cancelling jobs."));
        limitsSchema.put("stored_jobs", count("Maximum retained jobs."));
        limitsSchema.put("aggregate_concurrency", count("Maximum total concurrency reserved across active jobs."));
        limitsSchema.put("requests_per_job", count("Maximum submitted requests in one job."));
        limitsSchema.put("retained_response_bytes_per_job", count("Maximum raw response-preview bytes retained per job."));
        limitsSchema.put("response_preview_bytes", count("Maximum raw bytes retained per response preview."));
        limitsSchema.put("completed_ttl_ms", count("Completed-job retention period in milliseconds."));

        Map<String, Object> properties = new LinkedHashMap<>(job);
        properties.put("available", SchemaHelper.boolProp("LIST: whether this Burp runtime provides the required Professional managed HTTP engine."));
        properties.put("unavailable_reason", SchemaHelper.stringProp("LIST: explanation when available is false."));
        properties.put("limits", outputObject(limitsSchema, new ArrayList<>(limitsSchema.keySet())));
        properties.put("jobs", Map.of("type", "array", "description", "LIST: retained job summaries; full diagnostics are available through STATUS.",
            "items", outputObject(job, List.of("job_id", "name", "state", "state_source", "total_requests", "max_concurrency", "created_at", "retained_response_bytes", "truncated_results"))));
        properties.put("results", Map.of("type", "array", "description", "RESULTS: rows in original input order, including PENDING placeholders. Revisit pending indices after completion.",
            "items", outputObject(entry, List.of("index", "url", "status"))));
        properties.put("offset", count("RESULTS: first original input index requested."));
        properties.put("limit", count("RESULTS: maximum rows requested; the serialized response budget may shorten the page."));
        properties.put("returned", count("RESULTS: number of rows actually returned."));
        properties.put("next_offset", Map.of("type", List.of("integer", "null"), "minimum", 0,
            "description", "RESULTS: next original input index, or null at the end. Reaching the end of pagination does not mean the job has completed."));
        properties.put("has_more", SchemaHelper.boolProp("RESULTS: more input indices remain after this page, independently of job completion."));
        properties.put("error", SchemaHelper.stringProp("Machine-readable error code such as invalid_arguments, unavailable, unknown_job, capacity, submission_failed, or submission_uncertain. MCP isError is also true."));
        // Every action and error shares this permissive envelope. No success-only
        // fields are required, so structured tool errors and bridge fallbacks validate.
        return outputObject(properties, List.of());
    }

    private static Map<String, Object> outputObject(Map<String, Object> properties, List<String> required) {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        schema.put("properties", properties);
        schema.put("additionalProperties", true);
        if (!required.isEmpty()) schema.put("required", required);
        return schema;
    }

    private static Map<String, Object> count(String description) {
        return Map.of("type", "integer", "minimum", 0, "description", description);
    }

    private static Map<String, Object> number(String description, int value, int minimum, int maximum) {
        return Map.of("type", "integer", "description", description, "default", value, "minimum", minimum, "maximum", maximum);
    }

    @Override
    public Object execute(JsonNode arguments) {
        try {
            if (arguments == null || !arguments.isObject()) throw new IllegalArgumentException("Arguments must be an object.");
            String action = text(arguments, "action", null, 30).toUpperCase(java.util.Locale.ROOT);
            if (!ACTIONS.contains(action)) throw new IllegalArgumentException("Unknown action. Expected: " + ACTIONS);
            validateFields(arguments, action);
            synchronized (lock) {
                if (closed) return error("closed", "HTTP jobs tool is closed.");
                purgeExpired();
            }
            if ("START".equals(action)) return start(arguments);
            synchronized (lock) {
                if (closed) return error("closed", "HTTP jobs tool is closed.");
                if ("LIST".equals(action)) return list();
                String id = text(arguments, "job_id", null, 100);
                Job job = jobs.get(id);
                if (job == null) return error("unknown_job", "Unknown or expired job_id: " + id);
                return switch (action) {
                    case "STATUS" -> McpUtils.createJsonResponse(snapshot(job));
                    case "RESULTS" -> results(job, arguments);
                    default -> control(job, action);
                };
            }
        } catch (IllegalArgumentException e) {
            return error("invalid_arguments", e.getMessage());
        } catch (UnsupportedOperationException e) {
            return error("unavailable", e.getMessage());
        } catch (RuntimeException | LinkageError e) {
            return error("execution_error", safeMessage(e));
        }
    }

    private Object start(JsonNode arguments) {
        String name = text(arguments, "name", "MCP HTTP batch", 120);
        int concurrency = integer(arguments, "max_concurrency", 10, 1, 50);
        int delay = integer(arguments, "delay_ms", 0, 0, 60_000);
        int retries = integer(arguments, "max_retries", 0, 0, 3);
        int timeout = integer(arguments, "response_timeout", 30_000, 1, 300_000);
        synchronized (lock) {
            resolveEngine();
            if (engine == null) throw new UnsupportedOperationException(unavailableReason);
        }
        // Parse and validate the entire finite batch before creating a native execution.
        List<HttpRequest> requests = prepare.apply(arguments);
        synchronized (lock) {
            if (closed) return error("closed", "HTTP jobs tool is closed.");
            purgeExpired();
            long active = jobs.values().stream().filter(j -> !j.terminal()).count();
            int reserved = jobs.values().stream().filter(j -> !j.terminal()).mapToInt(j -> j.concurrency).sum();
            if (active >= limits.activeJobs || reserved + concurrency > limits.concurrency) {
                return error("capacity", "Active job or aggregate concurrency limit reached; finish/cancel jobs or lower max_concurrency.");
            }
            if (jobs.size() >= limits.storedJobs) {
                Job oldest = jobs.values().stream().filter(Job::terminal)
                    .min(java.util.Comparator.comparingLong(j -> j.finishedAt)).orElse(null);
                if (oldest == null) return error("capacity", "Stored job limit reached.");
                jobs.remove(oldest.id);
            }
            Job job = new Job(name, requests, concurrency, clock.getAsLong());
            jobs.put(job.id, job);
            ensureCleanup();
            try {
                HttpJobEngine.Execution execution = engine.start(requests,
                    new HttpJobEngine.Options(name, concurrency, delay, retries, timeout),
                    result -> recordResult(job, result), completion -> finish(job, completion));
                // Native callbacks can finish even before start returns.
                if (!job.terminal()) {
                    job.execution = execution;
                    job.state = "running";
                }
                return McpUtils.createJsonResponse(snapshot(job));
            } catch (HttpJobEngine.SubmissionException e) {
                boolean alreadyFinished = job.terminal();
                job.submissionFailed = true;
                job.error = safeMessage(e);
                job.execution = alreadyFinished ? null : e.execution();
                job.state = alreadyFinished ? "failed" : e.execution() == null ? "submission_uncertain" : "cancelling";
                refreshFailedSubmission(job);
                Map<String, Object> data = snapshot(job);
                data.put("error", "submission_failed");
                data.put("message", "Some requests may have been sent. Capacity remains reserved until native execution is confirmed drained; inspect this job before retrying. " + job.error);
                return error(data);
            } catch (RuntimeException | LinkageError e) {
                job.state = "failed";
                job.finishedAt = clock.getAsLong();
                job.error = safeMessage(e);
                for (Entry entry : job.entries) if ("PENDING".equals(entry.status)) entry.status = "UNKNOWN";
                Map<String, Object> data = snapshot(job);
                data.put("error", "start_failed");
                data.put("message", "Job could not be started: " + job.error);
                return error(data);
            }
        }
    }

    private void resolveEngine() {
        if (engineResolved) return;
        try {
            engine = HttpJobEngine.create(api);
            // Cache only a successful lookup. Burp may not yet be ready when a
            // client first asks for availability; a later LIST or START can retry.
            engineResolved = true;
            unavailableReason = null;
        } catch (RuntimeException | LinkageError e) {
            unavailableReason = safeMessage(e);
        }
    }

    private Object list() {
        resolveEngine();
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("available", engine != null);
        if (engine == null) data.put("unavailable_reason", unavailableReason);
        data.put("jobs", jobs.values().stream().map(j -> {
            Map<String, Object> summary = snapshot(j);
            // Full diagnostics remain available through STATUS. Keep LIST bounded
            // even when every completed job has a lengthy failure message.
            summary.remove("message");
            summary.remove("stats_error");
            return summary;
        }).toList());
        data.put("limits", Map.of("active_jobs", limits.activeJobs, "stored_jobs", limits.storedJobs,
            "aggregate_concurrency", limits.concurrency, "requests_per_job", 1000,
            "retained_response_bytes_per_job", limits.retainedBytes, "response_preview_bytes", limits.previewBytes,
            "completed_ttl_ms", limits.ttlMs));
        return McpUtils.createJsonResponse(data);
    }

    private Object control(Job job, String action) {
        if (job.terminal()) return McpUtils.createJsonResponse(snapshot(job));
        if (job.execution == null) return error("submission_uncertain", "The native sender did not return a handle. Submission cannot be confirmed or controlled; extension unload clears the reservation.");
        String previous = job.state;
        try {
            switch (action) {
                case "CANCEL" -> {
                    job.state = "cancelling";
                    job.execution.cancel();
                }
                case "PAUSE" -> {
                    if ("cancelling".equals(job.state)) return error("cancelling", "A cancelling job cannot be paused or resumed.");
                    job.state = "paused";
                    job.execution.pause();
                }
                case "RESUME" -> {
                    if ("cancelling".equals(job.state)) return error("cancelling", "A cancelling job cannot be paused or resumed.");
                    job.state = "running";
                    job.execution.resume();
                }
                default -> throw new IllegalArgumentException("Unknown control action: " + action);
            }
        } catch (RuntimeException | LinkageError e) {
            if (!job.terminal()) job.state = previous;
            throw e;
        }
        return McpUtils.createJsonResponse(snapshot(job));
    }

    private void recordResult(Job job, HttpJobEngine.Result result) {
        synchronized (lock) {
            if (closed || job.terminal() || jobs.get(job.id) != job) return;
            if (result.index() < 0 || result.index() >= job.entries.size()) return;
            Entry entry = job.entries.get(result.index());
            if (!"PENDING".equals(entry.status)) return;
            entry.status = result.status();
            try {
                HttpResponse response = result.exchange() == null ? null : result.exchange().response();
                if (response == null) return;
                entry.statusCode = (int) response.statusCode();
                ByteArray bytes = response.toByteArray();
                entry.responseLength = bytes.length();
                entry.bodyLength = Math.max(0, bytes.length() - response.bodyOffset());
                int count = (int) Math.min(Math.min(bytes.length(), limits.previewBytes), Math.max(0, limits.retainedBytes - job.retainedBytes));
                if (count > 0) {
                    entry.preview = bytes.subArray(0, count).getBytes();
                    job.retainedBytes += entry.preview.length;
                }
                entry.truncated = count < bytes.length();
                if (entry.truncated) job.truncatedResults++;
            } catch (RuntimeException | LinkageError e) {
                // A failed preview must not stop scheduling or discard other results.
                entry.error = safeMessage(e);
                entry.truncated = true;
                job.truncatedResults++;
            }
        }
    }

    private void finish(Job job, HttpJobEngine.Completion completion) {
        synchronized (lock) {
            if (closed || job.terminal() || jobs.get(job.id) != job) return;
            job.stats = completion.stats();
            job.state = job.submissionFailed ? "failed" : completion.cancelled() ? "cancelled" : "completed";
            job.finishedAt = clock.getAsLong();
            job.execution = null;
            // DROPPED is delivered by the adapter on completion. Any still-missing
            // records are unknown, not presumed successful or never sent.
            for (Entry entry : job.entries) if ("PENDING".equals(entry.status)) entry.status = "UNKNOWN";
        }
    }

    private Map<String, Object> snapshot(Job job) {
        refreshFailedSubmission(job);
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("job_id", job.id);
        data.put("name", job.name);
        data.put("state", job.state);
        data.put("state_source", "mcp_controls_and_native_completion");
        data.put("total_requests", job.entries.size());
        data.put("max_concurrency", job.concurrency);
        data.put("created_at", job.createdAt);
        if (job.terminal()) {
            data.put("finished_at", job.finishedAt);
            data.put("expires_at", job.finishedAt + limits.ttlMs);
        }
        data.put("retained_response_bytes", job.retainedBytes);
        data.put("truncated_results", job.truncatedResults);
        if (job.error != null) data.put("message", job.error);
        HttpJobEngine.Stats stats = job.stats;
        if (job.execution != null) {
            try {
                stats = job.execution.stats();
            } catch (RuntimeException | LinkageError e) {
                data.put("stats_error", safeMessage(e));
            }
        }
        if (stats != null) data.put("progress", Map.of("requested", stats.requested(), "completed", stats.completed(),
            "failed", stats.failed(), "in_flight", stats.inFlight(), "pending", stats.pending(), "elapsed_ms", stats.elapsedMs()));
        return data;
    }

    private Object results(Job job, JsonNode arguments) {
        int offset = integer(arguments, "offset", 0, 0, job.entries.size());
        int limit = integer(arguments, "limit", 20, 1, 100);
        boolean includeResponse = bool(arguments, "include_response", false);
        Map<String, Object> data = snapshot(job);
        data.put("offset", offset);
        data.put("limit", limit);
        List<Map<String, Object>> page = new ArrayList<>();
        data.put("results", page);
        int next = offset;
        int end = Math.min(job.entries.size(), offset + limit);
        while (next < end) {
            page.add(job.entries.get(next).asMap(next, includeResponse));
            data.put("next_offset", next + 1 < job.entries.size() ? next + 1 : null);
            if (serializedSize(McpUtils.createJsonResponse(data)) > PAGE_CHARS && page.size() > 1) {
                page.remove(page.size() - 1);
                break;
            }
            next++;
        }
        data.put("next_offset", next < job.entries.size() ? next : null);
        data.put("returned", page.size());
        data.put("has_more", next < job.entries.size());
        return McpUtils.createJsonResponse(data);
    }

    private static int serializedSize(Object value) {
        try {
            return JSON.writeValueAsString(value).length();
        } catch (java.io.IOException e) {
            throw new IllegalStateException("Unable to serialize job results", e);
        }
    }

    private void ensureCleanup() {
        if (cleanup != null) return;
        cleanup = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread thread = new Thread(r, "burp-mcp-http-jobs-cleanup");
            thread.setDaemon(true);
            return thread;
        });
        cleanup.scheduleAtFixedRate(() -> {
            synchronized (lock) {
                if (!closed) purgeExpired();
            }
        }, 1, 1, TimeUnit.MINUTES);
    }

    private void purgeExpired() {
        long now = clock.getAsLong();
        jobs.values().forEach(this::refreshFailedSubmission);
        jobs.values().removeIf(j -> j.terminal() && now - j.finishedAt >= limits.ttlMs);
    }

    private void refreshFailedSubmission(Job job) {
        if (!job.submissionFailed || job.terminal() || job.execution == null) return;
        try {
            HttpJobEngine.Stats stats = job.execution.stats();
            if (stats.inFlight() != 0 || stats.pending() != 0 || stats.requested() != job.entries.size()
                    || stats.completed() + stats.failed() != stats.requested()) return;
            job.execution.detach();
            job.execution = null;
            job.stats = stats;
            job.state = "failed";
            job.finishedAt = clock.getAsLong();
            for (Entry entry : job.entries) if ("PENDING".equals(entry.status)) entry.status = "UNKNOWN";
        } catch (RuntimeException | LinkageError ignored) {
            // Without confirmation of completion, retain the capacity reservation.
        }
    }

    @Override
    public void close() {
        List<HttpJobEngine.Execution> executions;
        synchronized (lock) {
            if (closed) return;
            closed = true;
            if (cleanup != null) cleanup.shutdownNow();
            executions = jobs.values().stream().map(j -> j.execution).filter(java.util.Objects::nonNull).toList();
            jobs.clear();
        }
        for (HttpJobEngine.Execution execution : executions) {
            try {
                execution.detach();
            } catch (RuntimeException | LinkageError ignored) {
                // Attempt cancellation even if listener detachment fails.
            }
            try {
                execution.cancel();
            } catch (RuntimeException | LinkageError ignored) {
                // Best effort during unload; late callbacks are ignored.
            }
        }
    }

    private static void validateFields(JsonNode arguments, String action) {
        Set<String> allowed = switch (action) {
            case "START" -> START_FIELDS;
            case "LIST" -> Set.of("action");
            case "RESULTS" -> Set.of("action", "job_id", "offset", "limit", "include_response");
            default -> Set.of("action", "job_id");
        };
        Iterator<String> fields = arguments.fieldNames();
        while (fields.hasNext()) {
            String field = fields.next();
            if (!allowed.contains(field)) throw new IllegalArgumentException("Unsupported parameter for " + action + ": " + field
                + ". Use burp_custom_http for proxy routing or custom transport options.");
        }
    }

    private static String text(JsonNode args, String field, String fallback, int maxLength) {
        JsonNode value = args.get(field);
        if (value == null && fallback != null) return fallback;
        if (value == null || !value.isTextual() || value.asText().isBlank() || value.asText().length() > maxLength) {
            throw new IllegalArgumentException(field + " must be a non-empty string of at most " + maxLength + " characters.");
        }
        return value.asText().trim();
    }

    private static int integer(JsonNode args, String field, int fallback, int min, int max) {
        JsonNode value = args.get(field);
        if (value == null) return fallback;
        if (!value.isIntegralNumber() || !value.canConvertToInt() || value.intValue() < min || value.intValue() > max) {
            throw new IllegalArgumentException(field + " must be an integer from " + min + " to " + max + ".");
        }
        return value.intValue();
    }

    private static boolean bool(JsonNode args, String field, boolean fallback) {
        JsonNode value = args.get(field);
        if (value == null) return fallback;
        if (!value.isBoolean()) throw new IllegalArgumentException(field + " must be a boolean.");
        return value.booleanValue();
    }

    private static String safeMessage(Throwable error) {
        String message = error.getMessage() == null ? error.getClass().getSimpleName() : error.getMessage();
        return message.substring(0, Math.min(1000, message.length()));
    }

    private static Object error(String code, String message) {
        return error(Map.of("error", code, "message", message));
    }

    @SuppressWarnings("unchecked")
    private static Object error(Map<String, Object> data) {
        Map<String, Object> response = (Map<String, Object>) McpUtils.createJsonResponse(data);
        response.put("isError", true);
        return response;
    }

    private static final class Job {
        final String id = UUID.randomUUID().toString();
        final String name;
        final List<Entry> entries;
        final int concurrency;
        final long createdAt;
        String state = "starting";
        String error;
        long finishedAt;
        long retainedBytes;
        int truncatedResults;
        boolean submissionFailed;
        HttpJobEngine.Execution execution;
        HttpJobEngine.Stats stats;

        Job(String name, List<HttpRequest> requests, int concurrency, long createdAt) {
            this.name = name;
            this.concurrency = concurrency;
            this.createdAt = createdAt;
            this.entries = requests.stream().map(r -> new Entry(r.url())).toList();
        }

        boolean terminal() {
            return "completed".equals(state) || "cancelled".equals(state) || "failed".equals(state);
        }
    }

    private static final class Entry {
        final String url;
        final boolean urlTruncated;
        String status = "PENDING";
        Integer statusCode;
        int responseLength;
        int bodyLength;
        byte[] preview;
        boolean truncated;
        String error;

        Entry(String url) {
            this.url = url.substring(0, Math.min(url.length(), 2048));
            this.urlTruncated = url.length() > this.url.length();
        }

        Map<String, Object> asMap(int index, boolean includeResponse) {
            Map<String, Object> data = new LinkedHashMap<>();
            data.put("index", index);
            data.put("url", url);
            if (urlTruncated) data.put("url_truncated", true);
            data.put("status", status);
            if (statusCode != null) {
                data.put("status_code", statusCode);
                data.put("response_length", responseLength);
                data.put("body_length", bodyLength);
                data.put("preview_bytes", preview == null ? 0 : preview.length);
                data.put("response_truncated", truncated);
                if (includeResponse && preview != null) data.put("response_base64", Base64.getEncoder().encodeToString(preview));
            }
            if (error != null) data.put("error", error);
            return data;
        }
    }
}
