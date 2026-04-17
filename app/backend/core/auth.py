import os
import secrets
from functools import lru_cache
from typing import Any
from urllib.parse import urlencode

import requests
from fastapi import HTTPException, status
from jose import JWTError, jwt


KEYCLOAK_INTERNAL_URL = os.getenv("KEYCLOAK_INTERNAL_URL", "http://keycloak:8080")
KEYCLOAK_PUBLIC_URL = os.getenv("KEYCLOAK_PUBLIC_URL", "http://localhost:8080")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "secure_storage")
KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "secure-storage-app")
KEYCLOAK_CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET", "")
KEYCLOAK_EXPECTED_ISSUER = os.getenv(
    "KEYCLOAK_EXPECTED_ISSUER",
    f"{KEYCLOAK_PUBLIC_URL}/realms/{KEYCLOAK_REALM}",
)
APP_BASE_URL = os.getenv("APP_BASE_URL", "http://localhost:8000")

OIDC_DISCOVERY_URL = (
    f"{KEYCLOAK_INTERNAL_URL}/realms/{KEYCLOAK_REALM}/.well-known/openid-configuration"
)

CALLBACK_PATH = "/auth/callback"


class CurrentUser(dict):
    @property
    def username(self) -> str:
        return self.get("preferred_username") or self.get("sub", "unknown")

    @property
    def roles(self) -> list[str]:
        return self.get("roles", [])


@lru_cache(maxsize=1)
def get_oidc_config() -> dict[str, Any]:
    try:
        resp = requests.get(OIDC_DISCOVERY_URL, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as exc:
        raise RuntimeError(f"Failed to fetch OIDC config: {exc}") from exc


@lru_cache(maxsize=1)
def get_jwks() -> dict[str, Any]:
    jwks_uri = (
        f"{KEYCLOAK_INTERNAL_URL}/realms/{KEYCLOAK_REALM}"
        f"/protocol/openid-connect/certs"
    )

    try:
        resp = requests.get(jwks_uri, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as exc:
        raise RuntimeError(f"Failed to fetch JWKS: {exc}") from exc


def get_redirect_uri() -> str:
    return f"{APP_BASE_URL}{CALLBACK_PATH}"


def build_login_url(state: str) -> str:
    auth_endpoint = (
        f"{KEYCLOAK_PUBLIC_URL}/realms/{KEYCLOAK_REALM}"
        f"/protocol/openid-connect/auth"
    )

    query = urlencode(
        {
            "client_id": KEYCLOAK_CLIENT_ID,
            "response_type": "code",
            "scope": "openid profile email",
            "redirect_uri": get_redirect_uri(),
            "state": state,
        }
    )
    return f"{auth_endpoint}?{query}"


def exchange_code_for_tokens(code: str) -> dict[str, Any]:
    token_endpoint = (
        f"{KEYCLOAK_INTERNAL_URL}/realms/{KEYCLOAK_REALM}"
        f"/protocol/openid-connect/token"
    )

    data = {
        "grant_type": "authorization_code",
        "client_id": KEYCLOAK_CLIENT_ID,
        "client_secret": KEYCLOAK_CLIENT_SECRET,
        "code": code,
        "redirect_uri": get_redirect_uri(),
    }

    try:
        resp = requests.post(token_endpoint, data=data, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Code exchange failed: {exc}",
        ) from exc


def refresh_tokens(refresh_token: str) -> dict[str, Any]:
    token_endpoint = (
        f"{KEYCLOAK_INTERNAL_URL}/realms/{KEYCLOAK_REALM}"
        f"/protocol/openid-connect/token"
    )

    data = {
        "grant_type": "refresh_token",
        "client_id": KEYCLOAK_CLIENT_ID,
        "client_secret": KEYCLOAK_CLIENT_SECRET,
        "refresh_token": refresh_token,
    }

    try:
        resp = requests.post(token_endpoint, data=data, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token refresh failed: {exc}",
        ) from exc


def revoke_refresh_token(refresh_token: str) -> None:
    revocation_endpoint = (
        f"{KEYCLOAK_INTERNAL_URL}/realms/{KEYCLOAK_REALM}"
        f"/protocol/openid-connect/revoke"
    )

    data = {
        "client_id": KEYCLOAK_CLIENT_ID,
        "client_secret": KEYCLOAK_CLIENT_SECRET,
        "token": refresh_token,
        "token_type_hint": "refresh_token",
    }

    try:
        requests.post(revocation_endpoint, data=data, timeout=10)
    except requests.RequestException:
        pass


def _select_jwk(token: str) -> dict[str, Any]:
    header = jwt.get_unverified_header(token)
    kid = header.get("kid")
    if not kid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing token kid",
        )

    jwks = get_jwks()
    for key in jwks.get("keys", []):
        if key.get("kid") == kid:
            return key

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Signing key not found",
    )


def decode_and_validate_token(token: str) -> dict[str, Any]:
    jwk = _select_jwk(token)

    try:
        payload = jwt.decode(
            token,
            jwk,
            algorithms=["RS256"],
            audience=KEYCLOAK_CLIENT_ID,
            issuer=KEYCLOAK_EXPECTED_ISSUER,
            options={"verify_at_hash": False},
        )
        return payload
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {exc}",
        ) from exc


def user_from_access_token(access_token: str) -> CurrentUser:
    payload = decode_and_validate_token(access_token)

    realm_access = payload.get("realm_access", {})
    roles = realm_access.get("roles", [])

    return CurrentUser(
        {
            "sub": payload.get("sub"),
            "preferred_username": payload.get("preferred_username"),
            "email": payload.get("email"),
            "name": payload.get("name"),
            "roles": roles,
            "raw": payload,
        }
    )


def build_session_payload(tokens: dict[str, Any]) -> dict[str, Any]:
    access_token = tokens["access_token"]
    refresh_token = tokens.get("refresh_token")
    expires_in = tokens.get("expires_in")
    user = user_from_access_token(access_token)

    return {
        "user": dict(user),
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_in": expires_in,
    }


def generate_state() -> str:
    return secrets.token_urlsafe(32)