package cloud.foxlin.aegir.security;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public final class AegirSecurityClient
{
    private final String baseUrl;
    private final String configKey;
    private final String developerKey;
    private final HttpClient httpClient;
    private final AegirDiagnosticsHooks diagnosticsHooks;

    public AegirSecurityClient(String baseUrl, String configKey, String developerKey)
    {
        this(baseUrl, configKey, developerKey, HttpClient.newHttpClient(), null);
    }

    public AegirSecurityClient(String baseUrl, String configKey, String developerKey, HttpClient httpClient)
    {
        this(baseUrl, configKey, developerKey, httpClient, null);
    }

    public AegirSecurityClient(String baseUrl, String configKey, String developerKey, HttpClient httpClient, AegirDiagnosticsHooks diagnosticsHooks)
    {
        if (baseUrl == null || baseUrl.trim().isEmpty())
        {
            throw new IllegalArgumentException("A baseUrl is required.");
        }

        this.baseUrl = baseUrl.replaceAll("/+$", "");
        this.configKey = configKey;
        this.developerKey = developerKey;
        this.httpClient = httpClient;
        this.diagnosticsHooks = diagnosticsHooks;
    }

    public SecurityModels.ScanIdentityResult scanIdentity(String subjectId) throws IOException, InterruptedException
    {
        Map<String, Object> payload = asMap(request("scanIdentity", "/security/scan/" + encode(subjectId), "GET", null));
        return toScanIdentityResult(payload);
    }

    public SecurityModels.IdentityGraphSnapshot getIdentityGraph(String subjectId) throws IOException, InterruptedException
    {
        return new SecurityModels.IdentityGraphSnapshot(asMap(request("getIdentityGraph", "/security/graphs/" + encode(subjectId), "GET", null)));
    }

    public String getIdentityGraphJson(String subjectId) throws IOException, InterruptedException
    {
        return JsonSupport.stringify(getIdentityGraph(subjectId).getPayload());
    }

    public SecurityModels.ExposureSummary getExposureSummary(String subjectId) throws IOException, InterruptedException
    {
        return new SecurityModels.ExposureSummary(asMap(request("getExposureSummary", "/security/exposure/" + encode(subjectId), "GET", null)));
    }

    public SecurityModels.IdentityActionRecord performAction(PerformIdentityActionRequest request) throws IOException, InterruptedException
    {
        return new SecurityModels.IdentityActionRecord(asMap(request("performAction", "/security/actions", "POST", request.toMap())));
    }

    public SecurityModels.IdentityActionRecord reverseAction(String actionId, String reason) throws IOException, InterruptedException
    {
        String suffix = reason == null ? "" : "?reason=" + encode(reason);
        return new SecurityModels.IdentityActionRecord(asMap(request("reverseAction", "/security/actions/" + encode(actionId) + "/reverse" + suffix, "POST", null)));
    }

    public List<SecurityModels.IdentityActionRecord> getActionHistory(String subjectId) throws IOException, InterruptedException
    {
        List<Object> items = asList(request("getActionHistory", "/security/actions/history/" + encode(subjectId), "GET", null));
        List<SecurityModels.IdentityActionRecord> history = new ArrayList<>();
        for (Object item : items)
        {
            history.add(new SecurityModels.IdentityActionRecord(asMap(item)));
        }

        return history;
    }

    private Object request(String operation, String path, String method, Object body) throws IOException, InterruptedException
    {
        emitTrace(new AegirDiagnosticsHooks.TraceEvent("request.start", operation, "request.start", OffsetDateTime.now().toString(), null, Map.of("path", path, "method", method)));
        emitLog(new AegirDiagnosticsHooks.LogEntry("information", "request.start", "Starting " + operation + ".", operation, null, OffsetDateTime.now().toString(), Map.of("path", path, "method", method)));

        HttpRequest.Builder builder = HttpRequest.newBuilder()
            .uri(URI.create(baseUrl + "/v1" + path))
            .header("Accept", "application/json");

        if (configKey != null && !configKey.isBlank())
        {
            builder.header("X-Aegir-Config-Key", configKey);
        }

        if (developerKey != null && !developerKey.isBlank())
        {
            builder.header("X-Aegir-Developer-Key", developerKey);
        }

        if (body != null)
        {
            builder.header("Content-Type", "application/json");
            builder.method(method, HttpRequest.BodyPublishers.ofString(JsonSupport.stringify(body)));
        }
        else
        {
            builder.method(method, HttpRequest.BodyPublishers.noBody());
        }

        HttpResponse<String> response = httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString());
        Object payload = response.body() == null || response.body().isBlank() ? null : JsonSupport.parse(response.body());
        String correlationId = response.headers().firstValue("X-Correlation-Id").orElse(null);
        String code = resolveErrorCode(response.statusCode(), payload);
        emitMetric(new AegirDiagnosticsHooks.MetricEvent("aegir.client.request.duration", 0, "ms", OffsetDateTime.now().toString(), Map.of("operation", operation, "status", String.valueOf(response.statusCode()), "errorCode", code)));

        if (response.statusCode() < 200 || response.statusCode() >= 300)
        {
            emitLog(new AegirDiagnosticsHooks.LogEntry("error", "request.error", "Aegir request failed with status " + response.statusCode() + ".", operation, correlationId, OffsetDateTime.now().toString(), Map.of("status", String.valueOf(response.statusCode()), "errorCode", code)));
            emitTrace(new AegirDiagnosticsHooks.TraceEvent("request.error", operation, "request.error", OffsetDateTime.now().toString(), correlationId, Map.of("status", String.valueOf(response.statusCode()), "errorCode", code)));
            throw new AegirSecurityError("Aegir request failed with status " + response.statusCode() + ".", response.statusCode(), code, correlationId, payload);
        }

        emitLog(new AegirDiagnosticsHooks.LogEntry("information", "request.complete", "Completed " + operation + ".", operation, correlationId, OffsetDateTime.now().toString(), Map.of("status", String.valueOf(response.statusCode()))));
        emitTrace(new AegirDiagnosticsHooks.TraceEvent("request.complete", operation, "request.complete", OffsetDateTime.now().toString(), correlationId, Map.of("status", String.valueOf(response.statusCode()))));
        return payload;
    }

    private void emitLog(AegirDiagnosticsHooks.LogEntry entry)
    {
        if (diagnosticsHooks != null)
        {
            diagnosticsHooks.emitLog(entry);
        }
    }

    private void emitMetric(AegirDiagnosticsHooks.MetricEvent event)
    {
        if (diagnosticsHooks != null)
        {
            diagnosticsHooks.emitMetric(event);
        }
    }

    private void emitTrace(AegirDiagnosticsHooks.TraceEvent event)
    {
        if (diagnosticsHooks != null)
        {
            diagnosticsHooks.emitTrace(event);
        }
    }

    private static String resolveErrorCode(int statusCode, Object payload)
    {
        if (payload instanceof Map<?, ?>)
        {
            Map<?, ?> map = (Map<?, ?>) payload;
            Object code = map.get("code");
            if (code instanceof String)
            {
                String text = (String) code;
                if (!text.trim().isEmpty())
                {
                    return text;
                }
            }

            Object error = map.get("error");
            if (error instanceof String)
            {
                String text = (String) error;
                if (!text.trim().isEmpty())
                {
                    return text;
                }
            }
        }

        switch (statusCode)
        {
            case 400:
                return "invalid_request";
            case 401:
                return "unauthorized";
            case 403:
                return "forbidden";
            case 404:
                return "not_found";
            case 409:
                return "conflict";
            case 429:
                return "rate_limited";
            default:
                return statusCode >= 500 ? "server_error" : "unknown_error";
        }
    }

    private static String encode(String value)
    {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object payload)
    {
        return (Map<String, Object>) payload;
    }

    @SuppressWarnings("unchecked")
    private static List<Object> asList(Object payload)
    {
        return (List<Object>) payload;
    }

    private static SecurityModels.ScanIdentityResult toScanIdentityResult(Map<String, Object> payload)
    {
        List<SecurityModels.IdentityActionRecord> actionHistory = new ArrayList<>();
        for (Object item : asList(payload.get("actionHistory")))
        {
            actionHistory.add(new SecurityModels.IdentityActionRecord(asMap(item)));
        }

        return new SecurityModels.ScanIdentityResult(
            payload,
            new SecurityModels.IdentityGraphSnapshot(asMap(payload.get("graph"))),
            new SecurityModels.ExposureSummary(asMap(payload.get("exposure"))),
            actionHistory);
    }
}
