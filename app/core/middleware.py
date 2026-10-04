import time
from collections import defaultdict
from typing import Dict, List
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from app.core.config import settings


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        if request.url.path in ("/docs", "/redoc", "/openapi.json"):
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "img-src 'self' data: https://fastapi.tiangolo.com; "
                "frame-ancestors 'none';"
            )
        elif request.url.path.startswith("/recepcao"):
            # Página HTML da recepção usa <style> embutido; scripts continuam bloqueados.
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none';"
            )
        else:
            response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none';"

        return response


class RateLimiter:
    def __init__(self, limit: int = 5, window_seconds: int = 60):
        self.limit = limit
        self.window_seconds = window_seconds
        self.requests: Dict[str, List[float]] = defaultdict(list)

    def is_rate_limited(self, client_ip: str) -> bool:
        now = time.time()
        timestamps = self.requests[client_ip]
        self.requests[client_ip] = [t for t in timestamps if now - t < self.window_seconds]
        if len(self.requests[client_ip]) >= self.limit:
            return True
        self.requests[client_ip].append(now)
        return False

    def reset(self):
        self.requests.clear()


# Compatibilidade com o nome usado nos testes/relatórios anteriores.
LoginRateLimiter = RateLimiter

login_rate_limiter = RateLimiter(
    limit=settings.LOGIN_RATE_LIMIT_PER_MINUTE,
    window_seconds=60,
)

# Limiter separado para a verificação de MFA (códigos de 6 dígitos são brute-forceáveis).
mfa_rate_limiter = RateLimiter(
    limit=settings.MFA_RATE_LIMIT_PER_MINUTE,
    window_seconds=60,
)
