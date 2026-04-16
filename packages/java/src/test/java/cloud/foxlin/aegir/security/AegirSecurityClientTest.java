package cloud.foxlin.aegir.security;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.util.ArrayList;
import java.util.List;

public final class AegirSecurityClientTest
{
    public static void main(String[] args) throws Exception
    {
        HttpServer server = HttpServer.create(new InetSocketAddress(0), 0);
        server.createContext("/apis/v1/security/scan/developer:dev_123", exchange -> respond(exchange, 200, "{\"subjectId\":\"developer:dev_123\",\"graph\":{\"graphId\":\"graph:developer:dev_123\",\"generatedAtUtc\":\"2026-04-07T15:00:00Z\",\"scores\":{\"exposureScore\":0.15,\"trustScore\":0.92,\"connectionClarityScore\":0.88},\"nodes\":[],\"edges\":[],\"metadata\":{}},\"exposure\":{\"graphId\":\"graph:developer:dev_123\",\"generatedAtUtc\":\"2026-04-07T15:00:00Z\",\"exposureScore\":0.15,\"findings\":[],\"summaryText\":\"Low exposure posture.\"},\"actionHistory\":[]}"));
        server.createContext("/apis/v1/security/exposure/developer:dev_123", exchange -> respond(exchange, 404, "{\"error\":\"not_found\"}"));
        server.start();

        try
        {
            String baseUrl = "http://127.0.0.1:" + server.getAddress().getPort() + "/apis";
            List<AegirDiagnosticsHooks.LogEntry> logs = new ArrayList<>();
            List<AegirDiagnosticsHooks.MetricEvent> metrics = new ArrayList<>();
            List<AegirDiagnosticsHooks.TraceEvent> traces = new ArrayList<>();
            AegirSecurityClient client = new AegirSecurityClient(
                baseUrl,
                "config-key",
                "developer-key",
                HttpClient.newHttpClient(),
                new AegirDiagnosticsHooks(logs::add, metrics::add, traces::add));

            SecurityModels.ScanIdentityResult result = client.scanIdentity("developer:dev_123");
            if (!"developer:dev_123".equals(result.getSubjectId()))
            {
                throw new AssertionError("Expected subjectId to round-trip.");
            }

            try
            {
                client.getExposureSummary("developer:dev_123");
                throw new AssertionError("Expected AegirSecurityError.");
            }
            catch (AegirSecurityError ex)
            {
                if (ex.getStatus() != 404)
                {
                    throw new AssertionError("Expected status 404.");
                }
                if (!"not_found".equals(ex.getCode()))
                {
                    throw new AssertionError("Expected code not_found.");
                }
            }

            if (!"request.start".equals(logs.get(0).eventName()))
            {
                throw new AssertionError("Expected diagnostics log entry.");
            }
            if (!"aegir.client.request.duration".equals(metrics.get(0).metricName()))
            {
                throw new AssertionError("Expected diagnostics metric entry.");
            }
            if (!"request.complete".equals(traces.get(1).traceName()))
            {
                throw new AssertionError("Expected diagnostics trace completion.");
            }

            PortableSecurity.SafeEnvelopeRecord envelope =
                PortableSecurity.createSafeEnvelope("agent:test", "{\"hello\":\"world\"}", null);
            PortableSecurity.SafeEnvelopeRecord tampered =
                new PortableSecurity.SafeEnvelopeRecord(
                    envelope.getEnvelopeId(),
                    envelope.getPayloadType(),
                    "{\"hello\":\"tampered\"}",
                    envelope.getPayloadHash(),
                    envelope.getCreatedAtUtc(),
                    envelope.getSignatureEnvelope());
            PortableSecurity.SafeEnvelopeValidationResult validation = PortableSecurity.validateSafeEnvelope(tampered);
            if (validation.isValid() || !"payload_hash_mismatch".equals(validation.getReason()))
            {
                throw new AssertionError("Expected tampered envelope to fail.");
            }

            PortableSecurity.InMemoryAgentToAgentProtocol protocol = new PortableSecurity.InMemoryAgentToAgentProtocol();
            PortableSecurity.AgentToAgentMessageRecord message =
                protocol.send("agent:sender", "agent:recipient", "handoff", "{\"hello\":\"world\"}", null, null);
            protocol.getInbox("agent:recipient").set(
                0,
                new PortableSecurity.AgentToAgentMessageRecord(
                    message.getMessageId(),
                    message.getSenderAgentId(),
                    message.getRecipientAgentId(),
                    message.getMessageType(),
                    message.getCorrelationId(),
                    tampered,
                    message.getSentAtUtc(),
                    null));
            PortableSecurity.AgentToAgentReceiveResult receiveResult = protocol.receive("agent:recipient", message.getMessageId());
            if (receiveResult.isAccepted() || !"payload_hash_mismatch".equals(receiveResult.getReason()))
            {
                throw new AssertionError("Expected tampered A2A message to fail.");
            }

            PortableSecurity.InMemoryBudgetEnvelopeService budgetService = new PortableSecurity.InMemoryBudgetEnvelopeService();
            try
            {
                for (int i = 0; i < 11; i++)
                {
                    budgetService.consume("IdentityScan", "subject-1");
                }
                throw new AssertionError("Expected BudgetExhaustedError.");
            }
            catch (PortableSecurity.BudgetExhaustedError ex)
            {
                if (!ex.getEnvelope().isExhausted())
                {
                    throw new AssertionError("Expected exhausted envelope.");
                }
            }

            byte[] payload = "{\"userId\":\"user-1\",\"trustLevel\":4}".getBytes();
            byte[] signature = PortableSecurity.signIdentityTokenPayload(payload);
            if (signature.length != 64)
            {
                throw new AssertionError("Expected 64-byte identity-token signature.");
            }
            if (!PortableSecurity.verifyIdentityTokenPayload(payload, signature))
            {
                throw new AssertionError("Expected identity-token signature to verify.");
            }
            if (PortableSecurity.verifyIdentityTokenPayload("{\"userId\":\"user-2\",\"trustLevel\":4}".getBytes(), signature))
            {
                throw new AssertionError("Expected tampered identity-token payload to fail.");
            }
        }
        finally
        {
            server.stop(0);
        }
    }

    private static void respond(HttpExchange exchange, int statusCode, String body) throws IOException
    {
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.getResponseHeaders().add("X-Correlation-Id", "corr_test");
        exchange.sendResponseHeaders(statusCode, body.getBytes().length);
        try (OutputStream stream = exchange.getResponseBody())
        {
            stream.write(body.getBytes());
        }
    }
}
