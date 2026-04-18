import os
from datetime import datetime, timezone
from typing import Any

import requests
from fastapi import HTTPException, Request, status

OPA_URL = os.getenv("OPA_URL", "http://opa:8181")
OPA_ALLOW_PATH = "/v1/data/securestorage/authz/allow"
OPA_REASON_PATH = "/v1/data/securestorage/authz/deny_reason"


def build_request_context(request: Request) -> dict[str, Any]:
    client_ip = request.client.host if request.client else "127.0.0.1"

    return {
        "method": request.method,
        "path": request.url.path,
        "client_ip": client_ip,
        "time": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }


def build_subject(user: dict[str, Any]) -> dict[str, Any]:
    return {
        "username": user.get("preferred_username") or user.get("username") or "unknown",
        "roles": user.get("roles", []),
    }


def _query_opa(path: str, payload: dict[str, Any]) -> Any:
    url = f"{OPA_URL}{path}"
    resp = requests.post(url, json={"input": payload}, timeout=5)
    resp.raise_for_status()
    body = resp.json()
    return body.get("result")


def authorize(
    *,
    subject: dict[str, Any],
    action: str,
    resource: dict[str, Any],
    request_context: dict[str, Any],
) -> None:
    payload = {
        "subject": subject,
        "action": action,
        "resource": resource,
        "request": request_context,
    }

    try:
        allowed = _query_opa(OPA_ALLOW_PATH, payload)
    except requests.RequestException as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"OPA unavailable: {exc}",
        ) from exc

    if allowed:
        return

    try:
        reason = _query_opa(OPA_REASON_PATH, payload) or "Недостаточно прав"
    except requests.RequestException:
        reason = "Недостаточно прав"

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=reason,
    )