from collections.abc import Generator
from typing import Callable

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from backend.core.auth import CurrentUser
from backend.db.database import SessionLocal


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(request: Request) -> CurrentUser:
    session_user = request.session.get("user")
    if not session_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Требуется аутентификация",
        )
    return CurrentUser(session_user)


def require_roles(*allowed_roles: str) -> Callable:
    def dependency(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        user_roles = set(user.roles)
        if not user_roles.intersection(allowed_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Недостаточно прав",
            )
        return user

    return dependency