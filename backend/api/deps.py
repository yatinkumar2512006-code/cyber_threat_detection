import time
from typing import List, Optional
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from config.settings import settings
from storage.db import get_db
from storage.repositories.user_repository import UserRepository
from backend.core.security import decode_token
from backend.core.logging_setup import log_security_event

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)


class CurrentUser:
    """Dataclass representing the active request user."""
    def __init__(self, user_id: str, username: str, email: str, role: str, is_active: bool = True):
        self.user_id = user_id
        self.username = username
        self.email = email
        self.role = role
        self.is_active = is_active


def get_current_user(
    request: Request,
    token: Optional[str] = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> CurrentUser:
    """
    FastAPI dependency for authenticating request users.
    If settings.ENABLE_AUTH is False, returns a default local session user ('analyst').
    If settings.ENABLE_AUTH is True, validates JWT Bearer token and returns authenticated user.
    """
    if not settings.ENABLE_AUTH:
        # Default local session user when auth is toggled off
        return CurrentUser(
            user_id="usr_local_session",
            username="local_analyst",
            email="analyst@sentinel.local",
            role="analyst",
            is_active=True
        )

    if not token:
        client_ip = request.client.host if request.client else "unknown"
        log_security_event(
            event_type="AUTH_MISSING_TOKEN",
            message="Request missing authentication token",
            src_ip=client_ip,
            level=30
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "AUTHENTICATION_REQUIRED", "message": "Bearer authentication token required."},
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = decode_token(token)
        if payload.get("type") != "access":
            raise ValueError("Token is not an access token.")
        
        username = payload.get("sub")
        if not username:
            raise ValueError("Token subject missing.")

        repo = UserRepository(db)
        user = repo.get_by_username(username)
        if not user or not user.is_active:
            raise ValueError("User account inactive or not found.")

        return CurrentUser(
            user_id=user.user_id,
            username=user.username,
            email=user.email,
            role=user.role,
            is_active=user.is_active
        )
    except Exception as exc:
        client_ip = request.client.host if request.client else "unknown"
        log_security_event(
            event_type="AUTH_INVALID_TOKEN",
            message=f"Invalid authentication token: {str(exc)}",
            src_ip=client_ip,
            level=30
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "INVALID_TOKEN", "message": str(exc)},
            headers={"WWW-Authenticate": "Bearer"},
        )


def require_role(allowed_roles: List[str]):
    """Dependency factory checking if current user's role is in allowed_roles."""
    def role_checker(current_user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if current_user.role not in allowed_roles:
            log_security_event(
                event_type="AUTH_PERMISSION_DENIED",
                message=f"User {current_user.username} (role: {current_user.role}) denied access (required: {allowed_roles})",
                user_id=current_user.user_id,
                level=30
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "code": "PERMISSION_DENIED",
                    "message": f"User role '{current_user.role}' is not authorized. Required: {allowed_roles}"
                }
            )
        return current_user
    return role_checker


def assert_no_active_response_action(action_type: str):
    """
    Security check enforcing that active response (IP blocking / firewall rule mutation / quarantine)
    is strictly prohibited on data diode monitoring links.
    """
    if "block" in action_type.lower() or "quarantine" in action_type.lower() or "reset" in action_type.lower():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "ACTIVE_RESPONSE_PROHIBITED",
                "message": (
                    "Active network response (IP blocking / TCP reset / firewall mutation) "
                    "is physically disabled and strictly prohibited on data diode monitoring links. "
                    "OneWay Sentinel is passive detect-and-alert only."
                )
            }
        )
