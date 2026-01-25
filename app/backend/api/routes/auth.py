from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from jwt import ExpiredSignatureError, InvalidTokenError

from backend.core import security
from backend.db.database import RefreshToken, User
from backend.dependencies import get_current_user, get_db

router = APIRouter(prefix="/api/auth", tags=["auth"])


class AuthRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=4, max_length=128)


class ChangePasswordRequest(BaseModel):
    old_password: str = Field(..., min_length=4, max_length=128)
    new_password: str = Field(..., min_length=4, max_length=128)


def _store_refresh_token(db: Session, user_id: int, token: str) -> RefreshToken:
    expires_at = datetime.now(timezone.utc) + timedelta(days=security.REFRESH_TOKEN_DAYS)
    refresh_entry = RefreshToken(
        user_id=user_id,
        token_hash=security.hash_token(token),
        expires_at=expires_at,
    )
    db.add(refresh_entry)
    db.commit()
    db.refresh(refresh_entry)
    return refresh_entry


def _set_refresh_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key="refresh_token",
        value=token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=security.REFRESH_TOKEN_DAYS * 24 * 60 * 60,
    )


@router.post("/register")
def register(payload: AuthRequest, response: Response, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.username == payload.username).first()
    if existing:
        raise HTTPException(status_code=409, detail="Пользователь уже существует")

    user = User(
        username=payload.username,
        password_hash=security.hash_password(payload.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    access_token = security.create_access_token(user.id)
    refresh_token = security.create_refresh_token(user.id)
    _store_refresh_token(db, user.id, refresh_token)
    _set_refresh_cookie(response, refresh_token)

    return {"access_token": access_token, "user": {"id": user.id, "username": user.username}}


@router.post("/login")
def login(payload: AuthRequest, response: Response, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == payload.username).first()
    if not user or not security.verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Неверный логин или пароль")

    access_token = security.create_access_token(user.id)
    refresh_token = security.create_refresh_token(user.id)
    _store_refresh_token(db, user.id, refresh_token)
    _set_refresh_cookie(response, refresh_token)

    return {"access_token": access_token, "user": {"id": user.id, "username": user.username}}


@router.post("/refresh")
def refresh_access_token(
    request: Request, response: Response, db: Session = Depends(get_db)
):
    token = request.cookies.get("refresh_token")
    if not token:
        raise HTTPException(status_code=401, detail="Refresh token missing")

    try:
        payload = security.decode_token(token)
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Refresh token expired")
    except InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid token type")

    token_hash = security.hash_token(token)
    stored = (
        db.query(RefreshToken).filter(RefreshToken.token_hash == token_hash).first()
    )
    if not stored or stored.expires_at < datetime.now(timezone.utc):
        if stored:
            db.delete(stored)
            db.commit()
        raise HTTPException(status_code=401, detail="Refresh token revoked")

    access_token = security.create_access_token(int(payload["sub"]))
    return {"access_token": access_token}


@router.post("/logout")
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    token = request.cookies.get("refresh_token")
    if token:
        token_hash = security.hash_token(token)
        stored = (
            db.query(RefreshToken).filter(RefreshToken.token_hash == token_hash).first()
        )
        if stored:
            db.delete(stored)
            db.commit()

    response.delete_cookie("refresh_token")
    return {"status": "logged_out"}


@router.get("/me")
def me(current_user: User = Depends(get_current_user)):
    return {"id": current_user.id, "username": current_user.username}


@router.post("/change-password")
def change_password(
    payload: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not security.verify_password(payload.old_password, current_user.password_hash):
        raise HTTPException(status_code=400, detail="Старый пароль неверен")
    current_user.password_hash = security.hash_password(payload.new_password)
    db.commit()
    return {"status": "updated"}
