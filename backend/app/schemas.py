from __future__ import annotations

from pydantic import BaseModel, Field


# DEV-001 (Secure Coding): Input validation via Pydantic models with constraints
# API-001 (API Security): Request/response schema validation


class HealthResponse(BaseModel):
    status: str
    service: str
    environment: str
    version: str


# Control: DEV-001 (input validation)



class PasswordHashRequest(BaseModel):
    password: str = Field(min_length=1)


class PasswordHashResponse(BaseModel):
    password_hash: str


class PasswordVerifyRequest(BaseModel):
    password: str = Field(min_length=1)
    password_hash: str = Field(min_length=1)


class PasswordVerifyResponse(BaseModel):
    valid: bool


class TokenVerifyRequest(BaseModel):
    token: str = Field(min_length=1)


class TokenVerifyResponse(BaseModel):
    valid: bool
    payload: dict[str, object] | None = None
    error: str | None = None


class LoginRequest(BaseModel):
    # Control: DEV-001 (input validation with length/format constraints)
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256)
    mfa_code: str | None = Field(default=None, min_length=6, max_length=6)


class RegisterRequest(BaseModel):
    # Control: DEV-001 (input validation)
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256)
    role: str = Field(default="admin", min_length=1, max_length=64)


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=1)


class LogoutRequest(BaseModel):
    refresh_token: str = Field(min_length=1)


class AuthResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str
    expires_in: int


class LoginResponse(BaseModel):
    access_token: str | None = None
    refresh_token: str | None = None
    token_type: str
    expires_in: int | None = None
    mfa_pending: str | None = None


class MfaSetupResponse(BaseModel):
    secret: str
    provisioning_uri: str


class MfaCodeRequest(BaseModel):
    code: str = Field(min_length=6, max_length=6)


class MfaValidateRequest(BaseModel):
    mfa_pending: str = Field(min_length=16)
    code: str = Field(min_length=6, max_length=6)


class MfaStatusResponse(BaseModel):
    enabled: bool


class SsoLoginRequest(BaseModel):
    provider: str = Field(min_length=1, max_length=64)
    subject: str = Field(min_length=1, max_length=256)
    email: str = Field(min_length=3, max_length=256)
    role: str = Field(default="admin", min_length=1, max_length=64)
    issued_at: int = Field(ge=1)
    signature: str = Field(min_length=8, max_length=512)


class GoogleSsoInitResponse(BaseModel):
    authorization_url: str


class DeviceRegisterRequest(BaseModel):
    device_id: str = Field(min_length=1, max_length=9)
    name: str = Field(min_length=1, max_length=32)
    api_key: str | None = Field(default=None, min_length=1, max_length=256)


class DeviceRegisterResponse(BaseModel):
    device_id: str
    name: str
    api_key: str
    status: str

# Control: DEV-001 (input validation), API-001 (request validation)
    
class DeviceIngestRequest(BaseModel):
    destination_ip: str = Field(min_length=3, max_length=64)
    destination_port: int = Field(ge=1, le=65535)
    request_count: int = Field(ge=1, le=100000)
    payload: dict[str, object]


class DeviceIngestResponse(BaseModel):
    accepted: bool
    device_id: str
    traffic_log_id: str
    alerts_created: int


class AlertResponse(BaseModel):
    alert_id: str
    device_id: str
    rule_name: str
    severity: str
    message: str
    status: str
    created_at: str
    traffic_log_id: str
    previous_hash: str
    record_hash: str


class DeviceListResponse(BaseModel):
    device_id: str
    name: str
    status: str


class UserListResponse(BaseModel):
    username: str
    role: str
    failed_attempts: int
    is_locked: bool


class ApiRouteInventoryResponse(BaseModel):
    path: str
    methods: list[str]
    name: str
    response_model: str | None
    include_in_schema: bool


class DashboardSummaryResponse(BaseModel):
    devices_total: int
    devices_active: int
    devices_isolated: int
    traffic_logs_total: int
    alerts_total: int
    alerts_open: int
    alerts_high_severity: int
    audit_entries_total: int


class DeviceIsolationRequest(BaseModel):
    device_id: str = Field(min_length=1, max_length=128)
    reason: str = Field(min_length=3, max_length=256)


class DeviceIsolationResponse(BaseModel):
    device_id: str
    status: str
    reason: str


class DeviceDeisolationRequest(BaseModel):
    device_id: str = Field(min_length=1, max_length=128)
    reason: str = Field(min_length=3, max_length=256)


class DeviceDeisolationResponse(BaseModel):
    device_id: str
    status: str
    reason: str


class BackupSnapshotResponse(BaseModel):
    exported_at: str
    users: list[dict[str, object]]
    devices: list[dict[str, object]]
    traffic_logs: list[dict[str, object]]
    alerts: list[dict[str, object]]
    audit_logs: list[dict[str, object]]
    rules: list[dict[str, object]]


class RuleCreateRequest(BaseModel):
    rule_name: str = Field(min_length=3, max_length=128)
    description: str = Field(min_length=3, max_length=512)
    severity: str = Field(min_length=3, max_length=32)
    enabled: bool = True
    config: dict[str, object]


class RuleUpdateRequest(BaseModel):
    rule_name: str | None = Field(default=None, min_length=3, max_length=128)
    description: str | None = Field(default=None, min_length=3, max_length=512)
    severity: str | None = Field(default=None, min_length=3, max_length=32)
    config: dict[str, object] | None = None


class RuleStatusRequest(BaseModel):
    enabled: bool


class RuleResponse(BaseModel):
    rule_id: str
    rule_name: str
    description: str
    severity: str
    enabled: bool
    config: dict[str, object]
    created_at: str
    updated_at: str

