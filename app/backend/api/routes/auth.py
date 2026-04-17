from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse

from backend.core.auth import (
    CurrentUser,
    build_login_url,
    build_session_payload,
    exchange_code_for_tokens,
    generate_state,
    revoke_refresh_token,
)
from backend.dependencies import get_current_user

router = APIRouter(tags=["auth"])


@router.get("/auth/login")
def login(request: Request):
    state = generate_state()
    request.session["oidc_state"] = state
    return RedirectResponse(url=build_login_url(state), status_code=302)


@router.get("/auth/callback")
def auth_callback(request: Request, code: str | None = None, state: str | None = None):
    expected_state = request.session.get("oidc_state")

    if not code or not state or not expected_state or state != expected_state:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication callback",
        )

    tokens = exchange_code_for_tokens(code)
    session_payload = build_session_payload(tokens)

    request.session.clear()
    request.session.update(session_payload)

    return RedirectResponse(url="/", status_code=302)


@router.get("/auth/logout")
def logout(request: Request):
    refresh_token = request.session.get("refresh_token")
    if refresh_token:
        revoke_refresh_token(refresh_token)

    request.session.clear()
    return RedirectResponse(url="/", status_code=302)


@router.get("/api/me")
def get_me(user: CurrentUser = Depends(get_current_user)):
    return {
        "username": user.get("preferred_username"),
        "email": user.get("email"),
        "name": user.get("name"),
        "roles": user.get("roles", []),
    }