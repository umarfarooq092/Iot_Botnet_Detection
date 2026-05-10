from __future__ import annotations

from urllib.parse import urlencode

from authlib.integrations.starlette_client import OAuth  # type: ignore[reportMissingImports]
from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import RedirectResponse

from .config import Settings, get_settings
from .dependencies import require_admin_role, require_authenticated_user, require_device_api_key
from .schemas import (
    AlertResponse,
    ApiRouteInventoryResponse,
    AuthResponse,
    BackupSnapshotResponse,
    DeviceDeisolationRequest,
    DeviceDeisolationResponse,
    DashboardSummaryResponse,
    DeviceIsolationRequest,
    DeviceIsolationResponse,
    DeviceIngestRequest,
    DeviceIngestResponse,
    DeviceListResponse,
    UserListResponse,
    GoogleSsoInitResponse,
    DeviceRegisterRequest,
    DeviceRegisterResponse,
    LoginResponse,
    LoginRequest,
    MfaCodeRequest,
    MfaValidateRequest,
    MfaSetupResponse,
    MfaStatusResponse,
    RegisterRequest,
    LogoutRequest,
    HealthResponse,
    RefreshRequest,
    PasswordHashRequest,
    PasswordHashResponse,
    PasswordVerifyRequest,
    PasswordVerifyResponse,
    TokenVerifyRequest,
    TokenVerifyResponse,
    RuleCreateRequest,
    RuleResponse,
    RuleStatusRequest,
    SsoLoginRequest,
    RuleUpdateRequest,
)
from .api_inventory import build_api_inventory
from .security import SecurityError, hash_password, issue_access_token, validate_password_strength, verify_access_token, verify_password, verify_sso_assertion
from .ssrf import is_url_allowed
from .state import auth_state


# IAM-001 (Identity & Access Management): RBAC enforcement via require_admin_role decorator
# API-001 (API Security): Admin-only protected API surface
# BACKUP-001 (Backup & Recovery): Snapshot export endpoint with audit trail
# DATA-001 (Data Security & Cryptography): DB encryption integration is in `database.py`
# SEC-001 (Secrets Management): minimal secrets manager stub implemented in `secrets_manager.py`
# LOG-001 (Logging & Monitoring): structured logging configured in `logging_config.py`


api_router = APIRouter(prefix="/api/v1")
INVALID_CREDENTIALS_MESSAGE = "Invalid credentials"
oauth = OAuth()


def _google_oauth_client(settings: Settings):
    client = oauth.create_client("google")
    if client is not None:
        return client
    oauth.register(
        name="google",
        client_id=settings.google_client_id,
        client_secret=settings.google_client_secret,
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )
    return oauth.create_client("google")


def _to_rule_response(rule: object) -> RuleResponse:
    return RuleResponse(
        rule_id=getattr(rule, "rule_id"),
        rule_name=getattr(rule, "rule_name"),
        description=getattr(rule, "description"),
        severity=getattr(rule, "severity"),
        enabled=getattr(rule, "enabled"),
        config=getattr(rule, "config"),
        created_at=getattr(rule, "created_at").isoformat(),
        updated_at=getattr(rule, "updated_at").isoformat(),
    )


@api_router.get("/health", response_model=HealthResponse)
def health(settings: Settings = Depends(get_settings)) -> HealthResponse:
    return HealthResponse(
        status="ok",
        service=settings.app_name,
        environment=settings.environment,
        version="1.0.0",
    )


@api_router.post("/auth/login", response_model=LoginResponse)
def login(payload: LoginRequest, settings: Settings = Depends(get_settings)) -> LoginResponse:
    user = auth_state.get_user(payload.username)
    if user is None:
        raise SecurityError(INVALID_CREDENTIALS_MESSAGE)

    if auth_state.is_user_locked(user):
        raise SecurityError(INVALID_CREDENTIALS_MESSAGE)

    if not auth_state.verify_credentials(payload.username, payload.password):
        raise SecurityError(INVALID_CREDENTIALS_MESSAGE)

    if user.mfa_enabled:
        mfa_pending = auth_state.issue_mfa_pending_token(user.username, user.role)
        return LoginResponse(
            token_type="mfa_pending",
            mfa_pending=mfa_pending,
        )

    auth_state.record_successful_login(payload.username)
    access_token = issue_access_token(
        {"sub": user.username, "role": user.role},
        settings.jwt_secret,
        settings.access_token_ttl_seconds,
    )
    refresh_token = auth_state.issue_refresh_token(user.username, user.role)
    return LoginResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.access_token_ttl_seconds,
    )


@api_router.post("/auth/mfa/setup", response_model=MfaSetupResponse)
def setup_mfa(actor: dict[str, str] = Depends(require_authenticated_user)) -> MfaSetupResponse:
    try:
        secret, provisioning_uri = auth_state.initialize_mfa(actor["sub"])
    except ValueError as error:
        raise SecurityError(str(error)) from error

    auth_state.create_audit_log(
        actor=actor["sub"],
        action="mfa_setup_initialized",
        target=actor["sub"],
        details={},
    )
    return MfaSetupResponse(secret=secret, provisioning_uri=provisioning_uri)


@api_router.post("/auth/mfa/enable", response_model=MfaStatusResponse)
def enable_mfa(payload: MfaCodeRequest, actor: dict[str, str] = Depends(require_authenticated_user)) -> MfaStatusResponse:
    try:
        auth_state.enable_mfa(actor["sub"], payload.code)
    except ValueError as error:
        raise SecurityError(str(error)) from error

    auth_state.create_audit_log(
        actor=actor["sub"],
        action="mfa_enabled",
        target=actor["sub"],
        details={},
    )
    return MfaStatusResponse(enabled=True)


@api_router.post("/auth/mfa/verify", response_model=MfaStatusResponse)
def verify_mfa_setup(payload: MfaCodeRequest, actor: dict[str, str] = Depends(require_authenticated_user)) -> MfaStatusResponse:
    return enable_mfa(payload, actor)


@api_router.post("/auth/mfa/validate", response_model=AuthResponse)
def validate_mfa(payload: MfaValidateRequest, settings: Settings = Depends(get_settings)) -> AuthResponse:
    try:
        user = auth_state.validate_mfa_pending_token(payload.mfa_pending)
    except ValueError as error:
        raise SecurityError(str(error)) from error

    if not user.mfa_enabled or not auth_state.verify_mfa(user.username, payload.code):
        raise SecurityError(INVALID_CREDENTIALS_MESSAGE)

    auth_state.record_successful_login(user.username)
    access_token = issue_access_token(
        {"sub": user.username, "role": user.role},
        settings.jwt_secret,
        settings.access_token_ttl_seconds,
    )
    refresh_token = auth_state.issue_refresh_token(user.username, user.role)
    return AuthResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.access_token_ttl_seconds,
    )


@api_router.post("/auth/sso/google", response_model=GoogleSsoInitResponse)
async def start_google_sso(request: Request, settings: Settings = Depends(get_settings)) -> GoogleSsoInitResponse:
    if not settings.sso_enabled:
        raise SecurityError("SSO is disabled")

    google = _google_oauth_client(settings)
    redirect_uri = settings.google_redirect_uri or str(request.url_for("google_sso_callback"))
    # Control: API-001 (SSRF prevention) - ensure redirect_uri is on the configured whitelist
    if not is_url_allowed(redirect_uri):
        raise SecurityError("Configured redirect URI is not allowed by SSRF whitelist")
    authorization_url, state = google.create_authorization_url(redirect_uri)
    request.session["google_oauth_state"] = state
    return GoogleSsoInitResponse(authorization_url=authorization_url)


@api_router.get("/auth/sso/google/callback", name="google_sso_callback")
async def google_sso_callback(request: Request, code: str = Query(min_length=1), state: str = Query(min_length=1), settings: Settings = Depends(get_settings)) -> RedirectResponse:
    if not settings.sso_enabled:
        raise SecurityError("SSO is disabled")

    expected_state = request.session.get("google_oauth_state")
    if not expected_state or expected_state != state:
        raise SecurityError("Invalid OAuth state")

    google = _google_oauth_client(settings)
    token = await google.authorize_access_token(request)
    user_info = token.get("userinfo") or {}
    email = str(user_info.get("email", "")).strip().lower()
    if not email:
        raise SecurityError("Google account did not return an email address")

    user = auth_state.ensure_sso_user(email, "admin")
    access_token = issue_access_token(
        {"sub": user.username, "role": user.role, "idp": "google", "sso": True},
        settings.jwt_secret,
        settings.access_token_ttl_seconds,
    )
    refresh_token = auth_state.issue_refresh_token(user.username, user.role)
    auth_state.create_audit_log(
        actor=user.username,
        action="sso_google_login",
        target="google",
        details={"email": email},
    )

    request.session.pop("google_oauth_state", None)
    query = urlencode(
        {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": str(settings.access_token_ttl_seconds),
        }
    )
    return RedirectResponse(url=f"{settings.frontend_url}/login?{query}", status_code=302)


@api_router.post("/auth/mfa/disable", response_model=MfaStatusResponse)
def disable_mfa(payload: MfaCodeRequest, actor: dict[str, str] = Depends(require_authenticated_user)) -> MfaStatusResponse:
    try:
        auth_state.disable_mfa(actor["sub"], payload.code)
    except ValueError as error:
        raise SecurityError(str(error)) from error

    auth_state.create_audit_log(
        actor=actor["sub"],
        action="mfa_disabled",
        target=actor["sub"],
        details={},
    )
    return MfaStatusResponse(enabled=False)


@api_router.post("/auth/sso", response_model=AuthResponse)
def login_with_sso(payload: SsoLoginRequest, settings: Settings = Depends(get_settings)) -> AuthResponse:
    if not settings.sso_enabled:
        raise SecurityError("SSO is disabled")

    verify_sso_assertion(
        provider=payload.provider,
        subject=payload.subject,
        email=payload.email,
        role=payload.role,
        issued_at=payload.issued_at,
        signature=payload.signature,
        secret=settings.sso_provider_secret,
        max_clock_skew_seconds=settings.sso_max_clock_skew_seconds,
    )

    user = auth_state.ensure_sso_user(payload.email.strip().lower(), "admin")
    access_token = issue_access_token(
        {"sub": user.username, "role": user.role, "idp": payload.provider.strip().lower(), "sso": True},
        settings.jwt_secret,
        settings.access_token_ttl_seconds,
    )
    refresh_token = auth_state.issue_refresh_token(user.username, user.role)
    auth_state.create_audit_log(
        actor=user.username,
        action="sso_login",
        target=payload.provider,
        details={"subject": payload.subject},
    )
    return AuthResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.access_token_ttl_seconds,
    )


@api_router.post("/auth/register", response_model=AuthResponse)
def register(payload: RegisterRequest, settings: Settings = Depends(get_settings)) -> AuthResponse:
    try:
        validate_password_strength(payload.password)
        # Admin-only mode: all local registrations are forced to admin role.
        user = auth_state.register_user(payload.username, hash_password(payload.password), "admin")
    except ValueError as error:
        raise SecurityError(str(error)) from error

    access_token = issue_access_token(
        {"sub": user.username, "role": user.role},
        settings.jwt_secret,
        settings.access_token_ttl_seconds,
    )
    refresh_token = auth_state.issue_refresh_token(user.username, user.role)
    return AuthResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.access_token_ttl_seconds,
    )


@api_router.post("/auth/refresh", response_model=AuthResponse)
def refresh_token(payload: RefreshRequest, settings: Settings = Depends(get_settings)) -> AuthResponse:
    try:
        new_refresh_token = auth_state.rotate_refresh_token(payload.refresh_token)
    except ValueError as error:
        raise SecurityError("Invalid refresh token") from error

    record = auth_state.refresh_tokens[new_refresh_token]
    access_token = issue_access_token(
        {"sub": record.username, "role": record.role},
        settings.jwt_secret,
        settings.access_token_ttl_seconds,
    )
    return AuthResponse(
        access_token=access_token,
        refresh_token=new_refresh_token,
        token_type="bearer",
        expires_in=settings.access_token_ttl_seconds,
    )


@api_router.post("/auth/logout")
def logout(payload: LogoutRequest) -> dict[str, bool]:
    auth_state.revoke_refresh_token(payload.refresh_token)
    return {"ok": True}


@api_router.post("/security/hash-password", response_model=PasswordHashResponse)
def create_password_hash(payload: PasswordHashRequest) -> PasswordHashResponse:
    return PasswordHashResponse(password_hash=hash_password(payload.password))


@api_router.post("/security/verify-password", response_model=PasswordVerifyResponse)
def check_password(payload: PasswordVerifyRequest) -> PasswordVerifyResponse:
    return PasswordVerifyResponse(valid=verify_password(payload.password_hash, payload.password))


@api_router.post("/security/verify-token", response_model=TokenVerifyResponse)
def check_token(payload: TokenVerifyRequest, settings: Settings = Depends(get_settings)) -> TokenVerifyResponse:
    decoded = verify_access_token(payload.token, settings.jwt_secret)
    return TokenVerifyResponse(valid=True, payload=decoded)


@api_router.post("/devices/register", response_model=DeviceRegisterResponse)
def register_device(payload: DeviceRegisterRequest, actor: dict[str, str] = Depends(require_admin_role)) -> DeviceRegisterResponse:
    device = auth_state.register_device(payload.device_id, payload.name, payload.api_key, owner_username=None)
    auth_state.create_audit_log(
        actor=actor["sub"],
        action="device_registered",
        target=device.device_id,
        details={"device_name": device.name},
    )
    return DeviceRegisterResponse(device_id=device.device_id, name=device.name, api_key=device.api_key, status=device.status)


# Control: IAM-001 (device API-key auth), LOG-001 (detection/alerting)
# Validates device API key, processes ingest, evaluates DB rules, generates alerts
@api_router.post("/devices/ingest", response_model=DeviceIngestResponse)
def ingest_device_traffic(payload: DeviceIngestRequest, device_id: str = Depends(require_device_api_key)) -> DeviceIngestResponse:
    traffic_log, generated_alerts = auth_state.ingest_traffic(
        device_id=device_id,
        destination_ip=payload.destination_ip,
        destination_port=payload.destination_port,
        request_count=payload.request_count,
        payload=payload.payload,
    )
    return DeviceIngestResponse(
        accepted=True,
        device_id=device_id,
        traffic_log_id=traffic_log.traffic_log_id,
        alerts_created=len(generated_alerts),
    )


@api_router.get("/alerts", response_model=list[AlertResponse])
def list_alerts(actor: dict[str, str] = Depends(require_admin_role)) -> list[AlertResponse]:
    alerts = auth_state.list_alerts()
    auth_state.create_audit_log(
        actor=actor["sub"],
        action="alerts_viewed",
        target="alerts",
        details={"count": len(alerts)},
    )
    return [
        AlertResponse(
            alert_id=alert.alert_id,
            device_id=alert.device_id,
            rule_name=alert.rule_name,
            severity=alert.severity,
            message=alert.message,
            status=alert.status,
            created_at=alert.created_at.isoformat(),
            traffic_log_id=alert.traffic_log_id,
            previous_hash=alert.previous_hash,
            record_hash=alert.record_hash,
        )
        for alert in alerts
    ]


@api_router.get("/devices", response_model=list[DeviceListResponse])
def list_devices(actor: dict[str, str] = Depends(require_admin_role)) -> list[DeviceListResponse]:
    devices = auth_state.list_devices()
    auth_state.create_audit_log(
        actor=actor["sub"],
        action="devices_viewed",
        target="devices",
        details={"count": len(devices)},
    )
    return [DeviceListResponse(device_id=device.device_id, name=device.name, status=device.status) for device in devices]


@api_router.delete("/devices/{device_id}")
def delete_device(device_id: str, actor: dict[str, str] = Depends(require_admin_role)) -> dict[str, str | bool]:
    try:
        auth_state.remove_device(device_id)
    except ValueError as error:
        raise SecurityError(str(error)) from error

    auth_state.create_audit_log(
        actor=actor["sub"],
        action="device_removed",
        target=device_id,
        details={},
    )
    return {"ok": True, "removed_device": device_id}


@api_router.get("/admin/users", response_model=list[UserListResponse])
def list_users(actor: dict[str, str] = Depends(require_admin_role)) -> list[UserListResponse]:
    users = auth_state.list_users()
    auth_state.create_audit_log(
        actor=actor["sub"],
        action="users_viewed",
        target="users",
        details={"count": len(users)},
    )
    return [
        UserListResponse(
            username=user.username,
            role=user.role,
            failed_attempts=user.failed_attempts,
            is_locked=auth_state.is_user_locked(user),
        )
        for user in users
    ]


@api_router.get("/admin/api-inventory", response_model=list[ApiRouteInventoryResponse])
def api_inventory(actor: dict[str, str] = Depends(require_admin_role)) -> list[ApiRouteInventoryResponse]:
    # Control: API-001 (API inventory)
    # Exposes an application-generated route catalog for review and documentation.
    inventory = build_api_inventory(api_router)
    auth_state.create_audit_log(
        actor=actor["sub"],
        action="api_inventory_viewed",
        target="api_inventory",
        details={"count": len(inventory)},
    )
    return [ApiRouteInventoryResponse(**route) for route in inventory]


@api_router.delete("/admin/users/{username}")
def delete_user(username: str, actor: dict[str, str] = Depends(require_admin_role)) -> dict[str, str | bool]:
    try:
        auth_state.remove_user(username, actor_username=actor["sub"])
    except ValueError as error:
        raise SecurityError(str(error)) from error

    auth_state.create_audit_log(
        actor=actor["sub"],
        action="user_removed",
        target=username,
        details={},
    )
    return {"ok": True, "removed_user": username}


@api_router.get("/dashboard/summary", response_model=DashboardSummaryResponse)
def get_dashboard_summary(actor: dict[str, str] = Depends(require_admin_role)) -> DashboardSummaryResponse:
    summary = auth_state.dashboard_summary()
    auth_state.create_audit_log(
        actor=actor["sub"],
        action="dashboard_summary_viewed",
        target="dashboard",
        details={"alerts_total": summary["alerts_total"]},
    )
    return DashboardSummaryResponse(**summary)


@api_router.get("/admin/rules", response_model=list[RuleResponse])
def list_rules(actor: dict[str, str] = Depends(require_admin_role)) -> list[RuleResponse]:
    # Control: IAM-001 (RBAC - admin only)
    # Admin endpoint to list all detection rules; audit logged for compliance
    rules = auth_state.list_rules()
    auth_state.create_audit_log(
        actor=actor["sub"],
        action="rules_viewed",
        target="rules",
        details={"count": len(rules)},
    )
    return [_to_rule_response(rule) for rule in rules]


@api_router.post("/admin/rules", response_model=RuleResponse)
def create_rule(payload: RuleCreateRequest, actor: dict[str, str] = Depends(require_admin_role)) -> RuleResponse:
    # Control: IAM-001 (RBAC - admin only), LOG-001 (audit trail)
    # Admin endpoint to create detection rules; audit logged for governance
    try:
        rule = auth_state.create_rule(
            rule_name=payload.rule_name,
            description=payload.description,
            severity=payload.severity,
            config=payload.config,
            enabled=payload.enabled,
        )
    except ValueError as error:
        raise SecurityError(str(error)) from error

    auth_state.create_audit_log(
        actor=actor["sub"],
        action="rule_created",
        target=rule.rule_id,
        details={"rule_name": rule.rule_name},
    )
    return _to_rule_response(rule)


@api_router.patch("/admin/rules/{rule_id}", response_model=RuleResponse)
def update_rule(rule_id: str, payload: RuleUpdateRequest, actor: dict[str, str] = Depends(require_admin_role)) -> RuleResponse:
    # Control: IAM-001 (RBAC - admin only), LOG-001 (audit trail)
    # Admin endpoint to update detection rules; audit logged for forensics
    try:
        rule = auth_state.update_rule(
            rule_id=rule_id,
            rule_name=payload.rule_name,
            description=payload.description,
            severity=payload.severity,
            config=payload.config,
        )
    except ValueError as error:
        raise SecurityError(str(error)) from error

    auth_state.create_audit_log(
        actor=actor["sub"],
        action="rule_updated",
        target=rule.rule_id,
        details={"rule_name": rule.rule_name},
    )
    return _to_rule_response(rule)


@api_router.post("/admin/rules/{rule_id}/status", response_model=RuleResponse)
def set_rule_status(rule_id: str, payload: RuleStatusRequest, actor: dict[str, str] = Depends(require_admin_role)) -> RuleResponse:
    # Control: IAM-001 (RBAC - admin only), LOG-001 (audit trail)
    try:
        rule = auth_state.set_rule_enabled(rule_id=rule_id, enabled=payload.enabled)
    except ValueError as error:
        raise SecurityError(str(error)) from error

    auth_state.create_audit_log(
        actor=actor["sub"],
        action="rule_status_changed",
        target=rule.rule_id,
        details={"rule_name": rule.rule_name, "enabled": rule.enabled},
    )
    return _to_rule_response(rule)


@api_router.post("/admin/rules/{rule_id}/disable", response_model=RuleResponse)
def disable_rule(rule_id: str, actor: dict[str, str] = Depends(require_admin_role)) -> RuleResponse:
    # Control: IAM-001 (RBAC - admin only), LOG-001 (audit trail)
    try:
        rule = auth_state.set_rule_enabled(rule_id=rule_id, enabled=False)
    except ValueError as error:
        raise SecurityError(str(error)) from error

    auth_state.create_audit_log(
        actor=actor["sub"],
        action="rule_disabled",
        target=rule.rule_id,
        details={"rule_name": rule.rule_name},
    )
    return _to_rule_response(rule)


@api_router.post("/admin/rules/{rule_id}/enable", response_model=RuleResponse)
def enable_rule(rule_id: str, actor: dict[str, str] = Depends(require_admin_role)) -> RuleResponse:
    # Control: IAM-001 (RBAC - admin only), LOG-001 (audit trail)
    try:
        rule = auth_state.set_rule_enabled(rule_id=rule_id, enabled=True)
    except ValueError as error:
        raise SecurityError(str(error)) from error

    auth_state.create_audit_log(
        actor=actor["sub"],
        action="rule_enabled",
        target=rule.rule_id,
        details={"rule_name": rule.rule_name},
    )
    return _to_rule_response(rule)


@api_router.post("/response/isolate-device", response_model=DeviceIsolationResponse)
def isolate_device(payload: DeviceIsolationRequest, actor: dict[str, str] = Depends(require_admin_role)) -> DeviceIsolationResponse:
    try:
        device = auth_state.isolate_device(payload.device_id, actor=actor["sub"], reason=payload.reason)
    except ValueError as error:
        raise SecurityError(str(error)) from error

    return DeviceIsolationResponse(device_id=device.device_id, status=device.status, reason=payload.reason)


@api_router.post("/response/deisolate-device", response_model=DeviceDeisolationResponse)
def deisolate_device(payload: DeviceDeisolationRequest, actor: dict[str, str] = Depends(require_admin_role)) -> DeviceDeisolationResponse:
    try:
        device = auth_state.deisolate_device(payload.device_id, actor=actor["sub"], reason=payload.reason)
    except ValueError as error:
        raise SecurityError(str(error)) from error

    return DeviceDeisolationResponse(device_id=device.device_id, status=device.status, reason=payload.reason)


@api_router.get("/admin/backup/snapshot", response_model=BackupSnapshotResponse)
def get_backup_snapshot(actor: dict[str, str] = Depends(require_admin_role)) -> BackupSnapshotResponse:
    auth_state.create_audit_log(
        actor=actor["sub"],
        action="backup_snapshot_exported",
        target="system",
        details={},
    )
    return BackupSnapshotResponse(**auth_state.export_backup_snapshot())


@api_router.post("/admin/rbac-check")
def admin_rbac_check(_: dict[str, str] = Depends(require_admin_role)) -> dict[str, bool]:
    return {"ok": True}
