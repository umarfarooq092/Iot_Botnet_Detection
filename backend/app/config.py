from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import os
from pathlib import Path
from typing import Final


DEFAULT_APP_NAME: Final = "SSD Assignment 3 API"
DEFAULT_PORT: Final = 8000
DEFAULT_CORS_ORIGIN: Final = "http://localhost:5173,http://localhost:5174,http://127.0.0.1:5173,http://127.0.0.1:5174"
DEFAULT_REQUEST_BODY_LIMIT_BYTES: Final = 1_048_576
DEFAULT_RATE_LIMIT_WINDOW_SECONDS: Final = 60
DEFAULT_RATE_LIMIT_MAX: Final = 120
DEFAULT_ACCESS_TOKEN_TTL_SECONDS: Final = 15 * 60
DEFAULT_DEV_JWT_SECRET: Final = "dev-secret-for-assignment-only-please-change-12345"
DEFAULT_DATABASE_URL: Final = "sqlite:///data/ssd_app.db"
DEFAULT_MFA_ISSUER: Final = "SSD Assignment 3"
DEFAULT_SSO_MAX_CLOCK_SKEW_SECONDS: Final = 300
DEFAULT_DEV_SSO_PROVIDER_SECRET: Final = "dev-sso-secret-for-assignment-only-change-this-123"
DEFAULT_DEV_DATA_ENCRYPTION_KEY: Final = "dev-data-encryption-key-for-assignment-only-change-this-123"
DEFAULT_DEV_DB_ENCRYPTION_KEY: Final = "dev-db-encryption-key-for-assignment-only-change-this-123"


@dataclass(frozen=True)
class Settings:
    app_name: str
    environment: str
    port: int
    cors_origins: list[str]
    request_body_limit_bytes: int
    rate_limit_window_seconds: int
    rate_limit_max: int
    jwt_secret: str
    access_token_ttl_seconds: int
    database_url: str | None
    mfa_issuer: str
    sso_enabled: bool
    sso_provider_secret: str
    sso_max_clock_skew_seconds: int
    google_client_id: str
    google_client_secret: str
    google_redirect_uri: str | None
    frontend_url: str
    data_encryption_key: str
    db_encryption_key: str
    tls_enabled: bool
    tls_certfile: str | None
    tls_keyfile: str | None
    demo_admin_username: str
    demo_admin_password: str
    demo_device_id: str
    demo_device_api_key: str


def _parse_positive_int(value: str, field_name: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise ValueError(f"{field_name} must be an integer") from error

    if parsed <= 0:
        raise ValueError(f"{field_name} must be greater than 0")

    return parsed


def _parse_duration_seconds(value: str) -> int:
    raw = value.strip().lower()
    if raw.isdigit():
        return _parse_positive_int(raw, "ACCESS_TOKEN_TTL")

    suffix_map = {"s": 1, "m": 60, "h": 3600}
    suffix = raw[-1]
    if suffix not in suffix_map:
        raise ValueError("ACCESS_TOKEN_TTL must use seconds, minutes, or hours, such as 900, 15m, or 1h")

    amount = _parse_positive_int(raw[:-1], "ACCESS_TOKEN_TTL")
    return amount * suffix_map[suffix]


def _parse_bool(value: str, field_name: str) -> bool:
    normalized = value.strip().lower()
    truthy = {"1", "true", "yes", "on"}
    falsy = {"0", "false", "no", "off"}
    if normalized in truthy:
        return True
    if normalized in falsy:
        return False
    raise ValueError(f"{field_name} must be a boolean (true/false)")


def _parse_cors_origins(value: str) -> list[str]:
    origins = [origin.strip() for origin in value.split(",") if origin.strip()]
    return origins or [DEFAULT_CORS_ORIGIN]


def _load_env_file() -> None:
    env_path = Path(__file__).resolve().parents[1] / ".env"
    if not env_path.exists():
        return

    for line in env_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue

        key, value = stripped.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def load_settings() -> Settings:
    _load_env_file()
    issues: list[str] = []

    environment = os.getenv("ENVIRONMENT", os.getenv("NODE_ENV", "development")).strip().lower()
    if environment not in {"development", "test", "production"}:
        issues.append("ENVIRONMENT must be development, test, or production")

    port_raw = os.getenv("PORT", str(DEFAULT_PORT))
    try:
        port = _parse_positive_int(port_raw, "PORT")
    except ValueError as error:
        issues.append(str(error))
        port = DEFAULT_PORT

    request_body_limit_raw = os.getenv("REQUEST_BODY_LIMIT_BYTES", str(DEFAULT_REQUEST_BODY_LIMIT_BYTES))
    try:
        request_body_limit_bytes = _parse_positive_int(request_body_limit_raw, "REQUEST_BODY_LIMIT_BYTES")
    except ValueError as error:
        issues.append(str(error))
        request_body_limit_bytes = DEFAULT_REQUEST_BODY_LIMIT_BYTES

    rate_limit_window_raw = os.getenv("RATE_LIMIT_WINDOW_SECONDS", str(DEFAULT_RATE_LIMIT_WINDOW_SECONDS))
    try:
        rate_limit_window_seconds = _parse_positive_int(rate_limit_window_raw, "RATE_LIMIT_WINDOW_SECONDS")
    except ValueError as error:
        issues.append(str(error))
        rate_limit_window_seconds = DEFAULT_RATE_LIMIT_WINDOW_SECONDS

    rate_limit_max_raw = os.getenv("RATE_LIMIT_MAX", str(DEFAULT_RATE_LIMIT_MAX))
    try:
        rate_limit_max = _parse_positive_int(rate_limit_max_raw, "RATE_LIMIT_MAX")
    except ValueError as error:
        issues.append(str(error))
        rate_limit_max = DEFAULT_RATE_LIMIT_MAX

    jwt_secret = os.getenv("JWT_SECRET", "").strip()
    if len(jwt_secret) < 32:
        if environment in {"development", "test"}:
            jwt_secret = DEFAULT_DEV_JWT_SECRET
        else:
            issues.append("JWT_SECRET must be at least 32 characters")

    ttl_raw = os.getenv("ACCESS_TOKEN_TTL", "15m")
    try:
        access_token_ttl_seconds = _parse_duration_seconds(ttl_raw)
    except ValueError as error:
        issues.append(str(error))
        access_token_ttl_seconds = DEFAULT_ACCESS_TOKEN_TTL_SECONDS

    database_url = os.getenv("DATABASE_URL", DEFAULT_DATABASE_URL).strip()

    mfa_issuer = os.getenv("MFA_ISSUER", DEFAULT_MFA_ISSUER).strip() or DEFAULT_MFA_ISSUER

    sso_enabled_raw = os.getenv("SSO_ENABLED", "false")
    try:
        sso_enabled = _parse_bool(sso_enabled_raw, "SSO_ENABLED")
    except ValueError as error:
        issues.append(str(error))
        sso_enabled = False

    sso_provider_secret = os.getenv("SSO_PROVIDER_SECRET", "").strip()
    if len(sso_provider_secret) < 32:
        if environment in {"development", "test"}:
            sso_provider_secret = DEFAULT_DEV_SSO_PROVIDER_SECRET
        else:
            issues.append("SSO_PROVIDER_SECRET must be at least 32 characters")

    sso_max_skew_raw = os.getenv("SSO_MAX_CLOCK_SKEW_SECONDS", str(DEFAULT_SSO_MAX_CLOCK_SKEW_SECONDS))
    try:
        sso_max_clock_skew_seconds = _parse_positive_int(sso_max_skew_raw, "SSO_MAX_CLOCK_SKEW_SECONDS")
    except ValueError as error:
        issues.append(str(error))
        sso_max_clock_skew_seconds = DEFAULT_SSO_MAX_CLOCK_SKEW_SECONDS

    data_encryption_key = os.getenv("DATA_ENCRYPTION_KEY", "").strip()
    if len(data_encryption_key) < 32:
        if environment in {"development", "test"}:
            data_encryption_key = DEFAULT_DEV_DATA_ENCRYPTION_KEY
        else:
            issues.append("DATA_ENCRYPTION_KEY must be at least 32 characters")

    # For development/test we keep SQLCipher disabled so local runs use a fresh
    # plaintext database. Production still requires DB_ENCRYPTION_KEY.
    db_encryption_key = os.getenv("DB_ENCRYPTION_KEY", "").strip()
    if environment in {"development", "test"}:
        db_encryption_key = ""
    elif not db_encryption_key:
        if environment in {"production"}:
            issues.append("DB_ENCRYPTION_KEY must be set in production to enable at-rest encryption")
    else:
        if len(db_encryption_key) < 32:
            issues.append("DB_ENCRYPTION_KEY must be at least 32 characters")

    google_client_id = os.getenv("GOOGLE_CLIENT_ID", "").strip()
    google_client_secret = os.getenv("GOOGLE_CLIENT_SECRET", "").strip()
    google_redirect_uri_raw = os.getenv("GOOGLE_REDIRECT_URI", "").strip()
    google_redirect_uri = google_redirect_uri_raw or None
    frontend_url = os.getenv("FRONTEND_URL", "https://localhost:5173").strip() or "https://localhost:5173"

    if sso_enabled:
        if not google_client_id:
            issues.append("GOOGLE_CLIENT_ID must be set when SSO_ENABLED=true")
        if not google_client_secret:
            issues.append("GOOGLE_CLIENT_SECRET must be set when SSO_ENABLED=true")

    tls_enabled_raw = os.getenv("TLS_ENABLED", "false")
    try:
        tls_enabled = _parse_bool(tls_enabled_raw, "TLS_ENABLED")
    except ValueError as error:
        issues.append(str(error))
        tls_enabled = False

    tls_certfile_raw = os.getenv("TLS_CERTFILE", "").strip()
    tls_keyfile_raw = os.getenv("TLS_KEYFILE", "").strip()
    tls_certfile = tls_certfile_raw or None
    tls_keyfile = tls_keyfile_raw or None
    if tls_enabled and (tls_certfile is None or tls_keyfile is None):
        issues.append("TLS_CERTFILE and TLS_KEYFILE must be set when TLS_ENABLED=true")

    demo_admin_username = os.getenv("DEMO_ADMIN_USERNAME", "").strip()
    demo_admin_password = os.getenv("DEMO_ADMIN_PASSWORD", "")
    demo_device_id = os.getenv("DEMO_DEVICE_ID", "").strip()
    demo_device_api_key = os.getenv("DEMO_DEVICE_API_KEY", "").strip()

    if not demo_admin_username:
        issues.append("DEMO_ADMIN_USERNAME must be set")
    if not demo_admin_password:
        issues.append("DEMO_ADMIN_PASSWORD must be set")
    if not demo_device_id:
        issues.append("DEMO_DEVICE_ID must be set")
    if not demo_device_api_key:
        issues.append("DEMO_DEVICE_API_KEY must be set")

    if issues:
        raise ValueError("Environment validation failed:\n" + "\n".join(issues))

    return Settings(
        app_name=os.getenv("APP_NAME", DEFAULT_APP_NAME),
        environment=environment,
        port=port,
        cors_origins=_parse_cors_origins(os.getenv("CORS_ORIGIN", DEFAULT_CORS_ORIGIN)),
        request_body_limit_bytes=request_body_limit_bytes,
        rate_limit_window_seconds=rate_limit_window_seconds,
        rate_limit_max=rate_limit_max,
        jwt_secret=jwt_secret,
        access_token_ttl_seconds=access_token_ttl_seconds,
        database_url=database_url,
        mfa_issuer=mfa_issuer,
        sso_enabled=sso_enabled,
        sso_provider_secret=sso_provider_secret,
        sso_max_clock_skew_seconds=sso_max_clock_skew_seconds,
        google_client_id=google_client_id,
        google_client_secret=google_client_secret,
        google_redirect_uri=google_redirect_uri,
        frontend_url=frontend_url,
        data_encryption_key=data_encryption_key,
        db_encryption_key=db_encryption_key,
        tls_enabled=tls_enabled,
        tls_certfile=tls_certfile,
        tls_keyfile=tls_keyfile,
        demo_admin_username=demo_admin_username,
        demo_admin_password=demo_admin_password,
        demo_device_id=demo_device_id,
        demo_device_api_key=demo_device_api_key,
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return load_settings()
