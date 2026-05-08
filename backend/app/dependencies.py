from __future__ import annotations

from fastapi import Header, HTTPException, status

from .config import Settings, get_settings
from .state import auth_state


# IAM-001 (Identity & Access Management): Authentication, RBAC, session management
# API-001 (API Security): Device API-key authentication, BOLA protection


def require_authenticated_user(authorization: str | None = Header(default=None)) -> dict[str, str]:
    # Control: IAM-001 (authentication)
    # Enforces Bearer token presence and validates JWT signature/expiration
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")

    token = authorization.removeprefix("Bearer ").strip()
    from .security import SecurityError, verify_access_token

    try:
        payload = verify_access_token(token, get_settings().jwt_secret)
    except SecurityError as error:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(error)) from error

    return {"sub": str(payload.get("sub", "")), "role": str(payload.get("role", ""))}


def require_admin_role(authorization: str | None = Header(default=None)) -> dict[str, str]:
    # Control: IAM-001 (RBAC - role-based access control)
    # Enforces admin role requirement; denies non-admin access to admin endpoints
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")

    token = authorization.removeprefix("Bearer ").strip()
    from .security import SecurityError, verify_access_token

    try:
        payload = verify_access_token(token, get_settings().jwt_secret)
    except SecurityError as error:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(error)) from error

    if payload.get("role") != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required")

    return {"sub": str(payload.get("sub", "")), "role": str(payload.get("role", ""))}


def require_device_api_key(x_device_id: str | None = Header(default=None), x_api_key: str | None = Header(default=None)) -> str:
    # Control: IAM-001 (authentication for devices), API-001 (API security)
    # Validates device API key; implements BOLA protection via device ownership checks downstream
    if not x_device_id or not x_api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing device credentials")

    if not auth_state.verify_device_api_key(x_device_id, x_api_key):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid device credentials")

    return x_device_id
