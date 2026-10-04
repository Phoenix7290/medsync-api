import base64
import hashlib
import hmac
import secrets
import struct
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import bcrypt
import jwt

from app.core.config import settings

# Escopos concedidos a cada papel humano (fonte única da verdade).
ROLE_SCOPES: Dict[str, List[str]] = {
    "admin": ["admin:manage", "appointments:read", "appointments:write"],
    "doctor": ["appointments:read", "appointments:write"],
    "receptionist": ["appointments:read"],
}


def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))


# Hash descartável usado para gastar o mesmo tempo quando o usuário não existe
# (evita enumeração de usuários por diferença de tempo de resposta no login).
DUMMY_PASSWORD_HASH = hash_password(secrets.token_urlsafe(16))


def create_access_token(
    data: Dict[str, Any],
    expires_delta: Optional[timedelta] = None,
) -> str:
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"iat": now, "exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_access_token(token: str) -> Dict[str, Any]:
    # "exp" e "sub" são obrigatórios: token sem expiração é rejeitado.
    return jwt.decode(
        token,
        settings.SECRET_KEY,
        algorithms=[settings.ALGORITHM],
        options={"require": ["exp", "sub"]},
    )


# ---------------------------------------------------------------------------
# MFA: TOTP (RFC 6238) implementado apenas com a biblioteca padrão.
# ---------------------------------------------------------------------------
def generate_mfa_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii")


def totp_code(secret_b32: str, for_time: Optional[float] = None, step: int = 30, digits: int = 6) -> str:
    key = base64.b32decode(secret_b32, casefold=True)
    counter = int((time.time() if for_time is None else for_time) // step)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return f"{code:0{digits}d}"


def verify_totp(secret_b32: str, code: str, window: int = 1, step: int = 30) -> bool:
    now = time.time()
    return any(
        hmac.compare_digest(totp_code(secret_b32, now + offset * step, step), code)
        for offset in range(-window, window + 1)
    )
