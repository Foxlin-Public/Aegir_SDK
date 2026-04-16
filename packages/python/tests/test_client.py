import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from foxlin_aegir_security import (
    AegirDiagnosticsHooks,
    AegirSecurityClient,
    AegirSecurityError,
    BudgetExhaustedError,
    InMemoryAgentToAgentProtocol,
    InMemoryBudgetEnvelopeService,
    PerformIdentityActionRequest,
    create_safe_envelope,
    sign_identity_token_payload,
    validate_safe_envelope,
    verify_identity_token_payload,
)


NOW = "2026-04-07T15:00:00Z"


class AegirSecurityClientTests(unittest.TestCase):
    def test_scan_identity(self):
        client = AegirSecurityClient(base_url="https://example.test/apis", transport=self._transport)
        result = client.scanIdentity("developer:dev_123")
        self.assertEqual("developer:dev_123", result.subjectId)
        self.assertEqual("graph:developer:dev_123", result.graph.graphId)

    def test_headers_are_attached(self):
        captured = {}

        def transport(url, method, headers, body):
            captured["headers"] = headers
            return 200, self._scan_payload()

        client = AegirSecurityClient(
            base_url="https://example.test/apis",
            config_key="config-key",
            developer_key="developer-key",
            transport=transport,
        )

        client.scanIdentity("developer:dev_123")
        self.assertEqual("config-key", captured["headers"]["X-Aegir-Config-Key"])
        self.assertEqual("developer-key", captured["headers"]["X-Aegir-Developer-Key"])

    def test_perform_action_posts_json(self):
        captured = {}

        def transport(url, method, headers, body):
            captured["method"] = method
            captured["body"] = json.loads(body)
            return 200, self._action_payload()

        client = AegirSecurityClient(base_url="https://example.test/apis", transport=transport)
        client.performAction(
            PerformIdentityActionRequest(
                subjectId="developer:dev_123",
                actionType="VerifyConnection",
                targetNodeId="application:app_portal",
                reason="Testing.",
            )
        )

        self.assertEqual("POST", captured["method"])
        self.assertEqual("VerifyConnection", captured["body"]["actionType"])

    def test_raises_aegir_security_error(self):
        client = AegirSecurityClient(base_url="https://example.test/apis", transport=lambda *_: (404, {"error": "not_found", "correlationId": "corr_123"}))
        with self.assertRaises(AegirSecurityError) as context:
            client.getExposureSummary("developer:dev_123")
        self.assertEqual(404, context.exception.status)
        self.assertEqual("not_found", context.exception.code)
        self.assertEqual("corr_123", context.exception.correlationId)

    def test_diagnostics_hooks_receive_events(self):
        logs = []
        metrics = []
        traces = []

        client = AegirSecurityClient(
            base_url="https://example.test/apis",
            diagnostics_hooks=AegirDiagnosticsHooks(log=logs.append, metric=metrics.append, trace=traces.append),
            transport=lambda *_: (200, self._graph_payload() | {"correlationId": "corr_diag"}),
        )

        client.getIdentityGraph("developer:dev_123")

        self.assertEqual("request.start", logs[0]["eventName"])
        self.assertEqual("aegir.client.request.duration", metrics[0]["metricName"])
        self.assertEqual("request.complete", traces[-1]["traceName"])
        self.assertEqual("corr_diag", traces[-1]["correlationId"])

    def test_safe_envelope_detects_tampering(self):
        envelope = create_safe_envelope("agent:test", '{"hello":"world"}')
        envelope.canonicalPayload = '{"hello":"tampered"}'
        result = validate_safe_envelope(envelope)
        self.assertFalse(result.isValid)
        self.assertEqual("payload_hash_mismatch", result.reason)

    def test_agent_to_agent_protocol_rejects_tampered_message(self):
        protocol = InMemoryAgentToAgentProtocol()
        message = protocol.send("agent:sender", "agent:recipient", "handoff", '{"hello":"world"}')
        message.envelope.canonicalPayload = '{"hello":"tampered"}'
        result = protocol.receive("agent:recipient", message.messageId)
        self.assertFalse(result.accepted)
        self.assertEqual("payload_hash_mismatch", result.reason)

    def test_budget_envelope_raises_when_exhausted(self):
        service = InMemoryBudgetEnvelopeService(identity_scan_limit=1)
        service.consume("IdentityScan", "subject-1")
        with self.assertRaises(BudgetExhaustedError) as context:
            service.consume("IdentityScan", "subject-1")
        self.assertTrue(context.exception.envelope.isExhausted)

    def test_identity_token_signature_detects_tampering(self):
        payload = b'{"userId":"user-1","trustLevel":4}'
        signature = sign_identity_token_payload(payload)
        self.assertEqual(64, len(signature))
        self.assertTrue(verify_identity_token_payload(payload, signature))
        self.assertFalse(verify_identity_token_payload(b'{"userId":"user-2","trustLevel":4}', signature))

    def _transport(self, url, method, headers, body):
        if url.endswith("/v1/security/scan/developer%3Adev_123"):
            return 200, self._scan_payload()
        if url.endswith("/v1/security/graphs/developer%3Adev_123"):
            return 200, self._graph_payload()
        if url.endswith("/v1/security/exposure/developer%3Adev_123"):
            return 200, self._exposure_payload()
        if url.endswith("/v1/security/actions") and method == "POST":
            return 200, self._action_payload()
        if url.endswith("/v1/security/actions/history/developer%3Adev_123"):
            return 200, [self._action_payload()]
        return 404, {"error": "not_found"}

    def _scan_payload(self):
        return {
            "subjectId": "developer:dev_123",
            "graph": self._graph_payload(),
            "exposure": self._exposure_payload(),
            "actionHistory": [self._action_payload()],
        }

    def _graph_payload(self):
        return {
            "graphId": "graph:developer:dev_123",
            "generatedAtUtc": NOW,
            "scores": {
                "exposureScore": 0.15,
                "trustScore": 0.92,
                "connectionClarityScore": 0.88,
            },
            "nodes": [
                {
                    "nodeId": "developer:dev_123",
                    "nodeType": "User",
                    "displayName": "dev_123@example.com",
                    "status": "active",
                    "trustTier": "high",
                    "observedAtUtc": NOW,
                    "lastVerifiedAtUtc": NOW,
                    "metadata": {},
                }
            ],
            "edges": [],
            "metadata": {},
        }

    def _exposure_payload(self):
        return {
            "graphId": "graph:developer:dev_123",
            "generatedAtUtc": NOW,
            "exposureScore": 0.15,
            "findings": [],
            "summaryText": "Low exposure posture.",
        }

    def _action_payload(self):
        return {
            "actionId": "action_001",
            "subjectId": "developer:dev_123",
            "actionType": "VerifyConnection",
            "status": "Completed",
            "targetNodeId": "application:app_portal",
            "reason": "Python sample validation.",
            "requestedAtUtc": NOW,
            "reversedAtUtc": None,
            "reverseReason": None,
            "metadata": {},
        }


if __name__ == "__main__":
    unittest.main()
