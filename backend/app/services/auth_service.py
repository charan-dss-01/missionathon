import time
import uuid
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, Tuple
import bcrypt
import jwt
from fastapi import Request, HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from app.config import settings
from app.db.mongodb import db_manager
from app.models.user import UserProfileResponse, AuditRecord

logger = logging.getLogger("phishguard.auth")

http_bearer_scheme = HTTPBearer(auto_error=False)

# Simple IP-based rate limiting dictionary: { ip: [timestamp, ...] }
_rate_limit_cache: Dict[str, list] = {}
RATE_LIMIT_WINDOW_SEC = 300 # 5 minutes
MAX_LOGIN_ATTEMPTS = 15

class AuthService:
    """
    Cryptographic password hashing, JWT session tokens, HTTP-only cookie management,
    and rate limiting protection.
    """

    @staticmethod
    def hash_password(password: str) -> str:
        """
        Hashes password securely using bcrypt with automatic salt.
        """
        salt = bcrypt.gensalt(rounds=12)
        hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
        return hashed.decode("utf-8")

    @staticmethod
    def verify_password(password: str, hashed_password: str) -> bool:
        """
        Validates password against bcrypt hash.
        """
        try:
            return bcrypt.checkpw(password.encode("utf-8"), hashed_password.encode("utf-8"))
        except Exception:
            return False

    @staticmethod
    def create_access_token(user_id: str, email: str, role: str = "user") -> str:
        """
        Generates signed JWT access token.
        """
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
        payload = {
            "sub": user_id,
            "email": email,
            "role": role,
            "iat": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
            "iss": "phishguard-ai"
        }
        token = jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
        return token

    @staticmethod
    def decode_token(token: str) -> Dict[str, Any]:
        """
        Decodes and verifies JWT access token signature and expiry.
        """
        try:
            payload = jwt.decode(
                token,
                settings.JWT_SECRET,
                algorithms=[settings.JWT_ALGORITHM],
                issuer="phishguard-ai"
            )
            return payload
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication token has expired. Please log in again."
            )
        except jwt.InvalidTokenError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token signature."
            )

    @classmethod
    def check_rate_limit(cls, client_ip: str) -> None:
        """
        Protects login/registration endpoints against brute force.
        """
        now = time.time()
        attempts = _rate_limit_cache.get(client_ip, [])
        # Keep only attempts in sliding window
        valid_attempts = [t for t in attempts if now - t < RATE_LIMIT_WINDOW_SEC]
        
        if len(valid_attempts) >= MAX_LOGIN_ATTEMPTS:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many authentication attempts. Please try again after 5 minutes."
            )
        
        valid_attempts.append(now)
        _rate_limit_cache[client_ip] = valid_attempts

    @staticmethod
    async def log_audit_event(
        event_type: str,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Persists security-relevant audit event to MongoDB.
        Never logs passwords, tokens, or raw credentials.
        """
        try:
            record = AuditRecord(
                id=f"audit-{uuid.uuid4().hex[:12]}",
                user_id=user_id,
                event_type=event_type,
                timestamp=datetime.now(timezone.utc),
                ip_address=ip_address,
                details=details or {}
            )
            if db_manager.is_connected:
                col = db_manager.get_audit_col()
                await col.insert_one(record.model_dump())
            else:
                from app.storage.memory_store import store
                store.add_audit(record.model_dump())
        except Exception as e:
            logger.warning(f"Could not persist audit log: {e}")


async def get_current_user(
    request: Request,
    bearer: Optional[HTTPAuthorizationCredentials] = Depends(http_bearer_scheme)
) -> UserProfileResponse:
    """
    FastAPI dependency that authenticates the user via either:
    1. Authorization: Bearer <token> header, OR
    2. HTTP-only session cookie (phishguard_session)
    """
    token = None

    # Check Bearer header first
    if bearer and bearer.credentials:
        token = bearer.credentials
    else:
        # Check HTTP-only cookie
        token = request.cookies.get(settings.COOKIE_NAME)

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please log in to continue.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    payload = AuthService.decode_token(token)
    user_id = payload.get("sub")

    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload.")

    # Retrieve user from MongoDB or in-memory store
    if db_manager.is_connected:
        users_col = db_manager.get_users_col()
        doc = await users_col.find_one({"id": user_id})
    else:
        from app.storage.memory_store import store
        doc = store.get_user_by_id(user_id)

    if not doc:
        # Fallback to token payload if user not in memory / db
        return UserProfileResponse(
            id=user_id,
            name=payload.get("email", "User").split("@")[0].title(),
            email=payload.get("email", ""),
            role=payload.get("role", "user"),
            status="active",
            created_at=datetime.now(timezone.utc)
        )
    if doc.get("status") == "suspended":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your account has been suspended by an administrator."
        )
    return UserProfileResponse(
        id=doc["id"],
        name=doc["name"],
        email=doc["email"],
        role=doc.get("role", "user"),
        status=doc.get("status", "active"),
        created_at=doc["created_at"],
        last_login=doc.get("last_login")
    )


async def get_optional_current_user(
    request: Request,
    bearer: Optional[HTTPAuthorizationCredentials] = Depends(http_bearer_scheme)
) -> Optional[UserProfileResponse]:
    """
    Permissive authentication dependency: returns user profile if authenticated, else None.
    """
    try:
        return await get_current_user(request, bearer)
    except HTTPException:
        return None
