package aegirsecurity

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) Do(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestScanIdentity(t *testing.T) {
	client := NewAegirSecurityClient("https://example.test/apis", "", "", roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return jsonResponse(200, `{"subjectId":"developer:dev_123","graph":{"graphId":"graph:developer:dev_123","generatedAtUtc":"2026-04-07T15:00:00Z","scores":{"exposureScore":0.15,"trustScore":0.92,"connectionClarityScore":0.88},"nodes":[],"edges":[],"metadata":{}},"exposure":{"graphId":"graph:developer:dev_123","generatedAtUtc":"2026-04-07T15:00:00Z","exposureScore":0.15,"findings":[],"summaryText":"Low exposure posture."},"actionHistory":[]}`), nil
	}))

	result, err := client.ScanIdentity("developer:dev_123")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if result.SubjectID != "developer:dev_123" {
		t.Fatalf("unexpected subject id %s", result.SubjectID)
	}
}

func TestHeadersAreAttached(t *testing.T) {
	client := NewAegirSecurityClient("https://example.test/apis", "config-key", "developer-key", roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("X-Aegir-Config-Key") != "config-key" {
			t.Fatalf("missing config header")
		}
		if req.Header.Get("X-Aegir-Developer-Key") != "developer-key" {
			t.Fatalf("missing developer header")
		}
		return jsonResponse(200, `{"graphId":"graph:developer:dev_123","generatedAtUtc":"2026-04-07T15:00:00Z","scores":{"exposureScore":0.15,"trustScore":0.92,"connectionClarityScore":0.88},"nodes":[],"edges":[],"metadata":{}}`), nil
	}))

	_, err := client.GetIdentityGraph("developer:dev_123")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestNonTwoHundredReturnsAegirSecurityError(t *testing.T) {
	client := NewAegirSecurityClient("https://example.test/apis", "", "", roundTripFunc(func(req *http.Request) (*http.Response, error) {
		response := jsonResponse(404, `{"error":"not_found"}`)
		response.Header.Set("X-Correlation-Id", "corr_123")
		return response, nil
	}))

	_, err := client.GetExposureSummary("developer:dev_123")
	if err == nil {
		t.Fatalf("expected error")
	}

	typedError, ok := err.(*AegirSecurityError)
	if !ok {
		t.Fatalf("expected AegirSecurityError, got %T", err)
	}
	if typedError.Code != "not_found" {
		t.Fatalf("expected not_found code, got %s", typedError.Code)
	}
	if typedError.CorrelationID != "corr_123" {
		t.Fatalf("expected corr_123 correlation id, got %s", typedError.CorrelationID)
	}
}

func TestDiagnosticsHooksReceiveEvents(t *testing.T) {
	logs := make([]LogEntry, 0)
	metrics := make([]MetricEvent, 0)
	traces := make([]TraceEvent, 0)

	client := NewAegirSecurityClientWithOptions(ClientOptions{
		BaseURL: "https://example.test/apis",
		HTTPClient: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			response := jsonResponse(200, `{"graphId":"graph:developer:dev_123","generatedAtUtc":"2026-04-07T15:00:00Z","scores":{"exposureScore":0.15,"trustScore":0.92,"connectionClarityScore":0.88},"nodes":[],"edges":[],"metadata":{}}`)
			response.Header.Set("X-Correlation-Id", "corr_diag")
			return response, nil
		}),
		Diagnostics: &DiagnosticsHooks{
			Log: func(entry LogEntry) { logs = append(logs, entry) },
			Metric: func(event MetricEvent) { metrics = append(metrics, event) },
			Trace: func(event TraceEvent) { traces = append(traces, event) },
		},
	})

	if _, err := client.GetIdentityGraph("developer:dev_123"); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if logs[0].EventName != "request.start" {
		t.Fatalf("expected request.start log, got %s", logs[0].EventName)
	}
	if metrics[0].MetricName != "aegir.client.request.duration" {
		t.Fatalf("unexpected metric %s", metrics[0].MetricName)
	}
	if traces[len(traces)-1].CorrelationID != "corr_diag" {
		t.Fatalf("expected corr_diag trace correlation id, got %s", traces[len(traces)-1].CorrelationID)
	}
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}
