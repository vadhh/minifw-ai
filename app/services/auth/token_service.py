from datetime import datetime, timedelta, timezone
from typing import Optional

import os

# Use PyJWT if available, fall back to python-jose for dev/test environments
try:
    import jwt as _jwt

    def _encode(payload, secret, algorithm):
        return _jwt.encode(payload, secret, algorithm=algorithm)

    def _decode(token, secret, algorithms):
        return _jwt.decode(token, secret, algorithms=algorithms)

    _JWTError = (_jwt.InvalidTokenError, _jwt.ExpiredSignatureError, _jwt.DecodeError)
except ImportError:
    from jose import jwt as _jose_jwt, JWTError as _JoseJWTError

    def _encode(payload, secret, algorithm):
        return _jose_jwt.encode(payload, secret, algorithm=algorithm)

    def _decode(token, secret, algorithms):
        return _jose_jwt.decode(token, secret, algorithms=algorithms)

    _JWTError = (_JoseJWTError,)

# Secret key - Must be set in environment
if "MINIFW_SECRET_KEY" not in os.environ:
    raise ValueError(
        "MINIFW_SECRET_KEY environment variable is not set. Security critical."
    )
SECRET_KEY = os.environ["MINIFW_SECRET_KEY"]
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create JWT access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire})
    encoded_jwt = _encode(to_encode, SECRET_KEY, ALGORITHM)
    return encoded_jwt


def verify_token(token: str) -> Optional[dict]:
    """Verify JWT token"""
    try:
        payload = _decode(token, SECRET_KEY, [ALGORITHM])
        return payload
    except _JWTError:
        return None
