from __future__ import annotations

import json
from dataclasses import asdict
from typing import Callable
from urllib import parse, request
from urllib.error import HTTPError

from .errors import AegirSecurityError
from .models import ExposureSummary, IdentityActionRecord, IdentityGraphSnapshot, PerformIdentityActionRequest, ScanIdentityResult


Transport = Callable[[str, str, dict[str, str], str | None], tuple[int, object]]


class AegirDiagnosticsHooks:
    def __init__(self, *, log=None, metric=None, trace=None) -> None:
        self.log = log
        self.metric = metric
        self.trace = trace


class AegirSecurityClient:
    def __init__(
        self,
        *,
        base_url: str,
        config_key: str | None = None,
        developer_key: str | None = None,
        transport: Transport | None = None,
        diagnostics_hooks: AegirDiagnosticsHooks | None = None,
    ) -> None:
        if not base_url or not base_url.strip():
            raise ValueError("A base_url is required.")

        self._base_url = base_url.rstrip("/")
        self._config_key = config_key
        self._developer_key = developer_key
        self._transport = transport or self._default_transport
        self._diagnostics_hooks = diagnostics_hooks

    def scanIdentity(self, subjectId: str) -> ScanIdentityResult:
        return ScanIdentityResult.from_json(self._request_json("scanIdentity", f"/security/scan/{parse.quote(subjectId, safe='')}"))

    def getIdentityGraph(self, subjectId: str) -> IdentityGraphSnapshot:
        return IdentityGraphSnapshot.from_json(self._request_json("getIdentityGraph", f"/security/graphs/{parse.quote(subjectId, safe='')}"))

    def getIdentityGraphJson(self, subjectId: str) -> str:
        graph = self.getIdentityGraph(subjectId)
        return json.dumps(asdict(graph))

    def getExposureSummary(self, subjectId: str) -> ExposureSummary:
        return ExposureSummary.from_json(self._request_json("getExposureSummary", f"/security/exposure/{parse.quote(subjectId, safe='')}"))

    def performAction(self, action: PerformIdentityActionRequest) -> IdentityActionRecord:
        return IdentityActionRecord.from_json(
            self._request_json("performAction", "/security/actions", method="POST", body=json.dumps(action.to_json()))
        )

    def reverseAction(self, actionId: str, reason: str | None = None) -> IdentityActionRecord:
        suffix = f"?reason={parse.quote(reason, safe='')}" if reason else ""
        return IdentityActionRecord.from_json(
            self._request_json("reverseAction", f"/security/actions/{parse.quote(actionId, safe='')}/reverse{suffix}", method="POST")
        )

    def getActionHistory(self, subjectId: str) -> list[IdentityActionRecord]:
        payload = self._request_json("getActionHistory", f"/security/actions/history/{parse.quote(subjectId, safe='')}")
        return [IdentityActionRecord.from_json(item) for item in payload]

    def _request_json(self, operation: str, path: str, *, method: str = "GET", body: str | None = None):
        headers = {"Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if self._config_key:
            headers["X-Aegir-Config-Key"] = self._config_key
        if self._developer_key:
            headers["X-Aegir-Developer-Key"] = self._developer_key

        self._emit_trace({
            "traceName": "request.start",
            "operation": operation,
            "tracePhase": "request.start",
            "occurredAtUtc": _utc_now(),
            "correlationId": None,
            "metadata": {"path": path, "method": method},
        })
        self._emit_log({
            "level": "information",
            "eventName": "request.start",
            "message": f"Starting {operation}.",
            "operation": operation,
            "correlationId": None,
            "occurredAtUtc": _utc_now(),
            "metadata": {"path": path, "method": method},
        })

        status, payload = self._transport(f"{self._base_url}/v1{path}", method, headers, body)
        correlation_id = payload.get("correlationId") if isinstance(payload, dict) else None
        code = _resolve_error_code(status, payload)
        self._emit_metric({
            "metricName": "aegir.client.request.duration",
            "value": 0,
            "unit": "ms",
            "observedAtUtc": _utc_now(),
            "dimensions": {"operation": operation, "status": str(status), "errorCode": code},
        })
        if status < 200 or status >= 300:
            self._emit_log({
                "level": "error",
                "eventName": "request.error",
                "message": f"Aegir request failed with status {status}.",
                "operation": operation,
                "correlationId": correlation_id,
                "occurredAtUtc": _utc_now(),
                "metadata": {"status": str(status), "errorCode": code},
            })
            self._emit_trace({
                "traceName": "request.error",
                "operation": operation,
                "tracePhase": "request.error",
                "occurredAtUtc": _utc_now(),
                "correlationId": correlation_id,
                "metadata": {"status": str(status), "errorCode": code},
            })
            raise AegirSecurityError(f"Aegir request failed with status {status}.", status, code, correlation_id, payload)
        self._emit_log({
            "level": "information",
            "eventName": "request.complete",
            "message": f"Completed {operation}.",
            "operation": operation,
            "correlationId": correlation_id,
            "occurredAtUtc": _utc_now(),
            "metadata": {"status": str(status)},
        })
        self._emit_trace({
            "traceName": "request.complete",
            "operation": operation,
            "tracePhase": "request.complete",
            "occurredAtUtc": _utc_now(),
            "correlationId": correlation_id,
            "metadata": {"status": str(status)},
        })
        return payload

    def _emit_log(self, entry) -> None:
        if self._diagnostics_hooks and self._diagnostics_hooks.log:
            self._diagnostics_hooks.log(entry)

    def _emit_metric(self, event) -> None:
        if self._diagnostics_hooks and self._diagnostics_hooks.metric:
            self._diagnostics_hooks.metric(event)

    def _emit_trace(self, event) -> None:
        if self._diagnostics_hooks and self._diagnostics_hooks.trace:
            self._diagnostics_hooks.trace(event)

    @staticmethod
    def _default_transport(url: str, method: str, headers: dict[str, str], body: str | None) -> tuple[int, object]:
        data = body.encode("utf-8") if body is not None else None
        req = request.Request(url, data=data, headers=headers, method=method)
        try:
            with request.urlopen(req) as response:
                text = response.read().decode("utf-8")
                return response.status, json.loads(text) if text else None
        except HTTPError as ex:
            text = ex.read().decode("utf-8")
            try:
                parsed = json.loads(text) if text else None
            except json.JSONDecodeError:
                parsed = text
            return ex.code, parsed


def _utc_now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _resolve_error_code(status: int, payload) -> str:
    if isinstance(payload, dict):
        candidate = payload.get("code") or payload.get("error")
        if isinstance(candidate, str) and candidate:
            return candidate

    if status == 400:
        return "invalid_request"
    if status == 401:
        return "unauthorized"
    if status == 403:
        return "forbidden"
    if status == 404:
        return "not_found"
    if status == 409:
        return "conflict"
    if status == 429:
        return "rate_limited"
    if status >= 500:
        return "server_error"
    return "unknown_error"
