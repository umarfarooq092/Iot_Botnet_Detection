from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Awaitable, Callable

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import Response

from .config import get_settings
from .routes import api_router
from .security import SecurityError
from .state import auth_state
from .logging_config import setup_logging


# API-001 (API Security): Rate limiting, BOLA/auth, request validation
# DEV-001 (Secure Coding): Input validation, XSS prevention via CSP headers
# DATA-001 (Data Security): Security headers for defense-in-depth


settings = get_settings()
auth_state.settings = settings
auth_state._seed_demo_data()

# Initialize structured logging (LOG-001)
logger = setup_logging()

app = FastAPI(
    title=settings.app_name,
    version="1.0.0",
    docs_url=None if settings.environment == "production" else "/docs",
    redoc_url=None if settings.environment == "production" else "/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

app.add_middleware(SessionMiddleware, secret_key=settings.jwt_secret, same_site="lax", https_only=settings.tls_enabled)


class RateLimitMiddleware(BaseHTTPMiddleware):
    # Control: API-001 (rate limiting and quotas)
    # Mitigates brute-force, DoS, and API abuse attacks
    def __init__(self, app: FastAPI, window_seconds: int, max_requests: int) -> None:
        super().__init__(app)
        self.window_seconds = window_seconds
        self.max_requests = max_requests
        self.buckets: dict[str, deque[float]] = defaultdict(deque)

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        client = request.client.host if request.client else "unknown"
        bucket = self.buckets[client]
        now = time.monotonic()

        while bucket and now - bucket[0] > self.window_seconds:
            bucket.popleft()

        if len(bucket) >= self.max_requests:
            return JSONResponse(status_code=429, content={"message": "Too many requests"})

        bucket.append(now)
        response = await call_next(request)
        return response


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
    # Control: DEV-001 (secure coding), API-001 (API security)
    # Enforces request size limits, security headers, and XSS/clickjacking prevention
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > settings.request_body_limit_bytes:
                return JSONResponse(status_code=413, content={"message": "Request body too large"})
        except ValueError:
            return JSONResponse(status_code=400, content={"message": "Invalid Content-Length header"})

    response = await call_next(request)
    # Security headers to prevent common web attacks
    response.headers["X-Content-Type-Options"] = "nosniff"  # Prevent MIME sniffing
    response.headers["X-Frame-Options"] = "DENY"  # Prevent clickjacking
    response.headers["Referrer-Policy"] = "no-referrer"  # Protect referrer leakage
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"  # Restrict browser APIs
    docs_paths = {"/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect"}
    if request.url.path in docs_paths:
        response.headers["Content-Security-Policy"] = (
            "default-src 'self' https://cdn.jsdelivr.net; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' data: https:; "
            "font-src 'self' data: https://cdn.jsdelivr.net; "
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
        )
    else:
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
    return response


app.add_middleware(
    RateLimitMiddleware,
    window_seconds=settings.rate_limit_window_seconds,
    max_requests=settings.rate_limit_max,
)

app.include_router(api_router)


@app.get("/")
def root() -> dict[str, str]:
    return {"message": "SSD Python backend is running"}


@app.exception_handler(SecurityError)
async def security_exception_handler(_: Request, exc: SecurityError) -> JSONResponse:
    return JSONResponse(status_code=400, content={"message": str(exc)})


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(status_code=422, content={"message": "Validation failed", "errors": exc.errors()})


@app.exception_handler(Exception)
async def generic_exception_handler(_: Request, __: Exception) -> JSONResponse:
    return JSONResponse(status_code=500, content={"message": "Internal server error"})


def main() -> None:
    import uvicorn

    uvicorn_args: dict[str, object] = {
        "app": "app.main:app",
        "host": "127.0.0.1",
        "port": settings.port,
        "reload": settings.environment != "production",
    }
    if settings.tls_enabled:
        uvicorn_args["ssl_certfile"] = settings.tls_certfile
        uvicorn_args["ssl_keyfile"] = settings.tls_keyfile

    uvicorn.run(**uvicorn_args)


if __name__ == "__main__":
    main()
