import uuid
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from app.config import settings
from app.db.mongodb import db_manager
from app.models.user import (
    UserRegisterRequest,
    UserLoginRequest,
    PasswordChangeRequest,
    UserProfileResponse,
    AuthTokenResponse
)
from app.services.auth_service import AuthService, get_current_user

auth_router = APIRouter(prefix="/api/auth", tags=["Authentication"])

def _set_auth_cookie(response: Response, token: str) -> None:
    """
    Sets secure, HTTP-only session cookie for the browser.
    """
    max_age_sec = settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60
    response.set_cookie(
        key=settings.COOKIE_NAME,
        value=token,
        max_age=max_age_sec,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
        path="/"
    )

@auth_router.post("/register", response_model=AuthTokenResponse, status_code=status.HTTP_201_CREATED)
async def register(req: UserRegisterRequest, request: Request, response: Response):
    """
    Registers a new standard user account.
    Validates password strength, hashes securely with bcrypt, sets HTTP-only cookie.
    """
    client_ip = request.client.host if request.client else "unknown"
    AuthService.check_rate_limit(client_ip)

    if not db_manager.is_connected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database service unavailable. Cannot create account at this time."
        )

    users_col = db_manager.get_users_col()
    
    # Check if email is already registered
    existing_user = await users_col.find_one({"email": req.email})
    if existing_user:
        await AuthService.log_audit_event("REGISTER_DUPLICATE_ATTEMPT", ip_address=client_ip, details={"email": req.email})
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this email address already exists."
        )

    user_id = f"user-{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc)
    hashed_pwd = AuthService.hash_password(req.password)

    user_doc = {
        "id": user_id,
        "name": req.name.strip(),
        "email": req.email,
        "password_hash": hashed_pwd,
        "role": "user", # Public registration always creates a standard user
        "status": "active",
        "created_at": now,
        "updated_at": now,
        "last_login": now
    }

    await users_col.insert_one(user_doc)
    await AuthService.log_audit_event("REGISTER_SUCCESS", user_id=user_id, ip_address=client_ip)

    # Issue JWT
    token = AuthService.create_access_token(user_id, req.email, "user")
    _set_auth_cookie(response, token)

    safe_profile = UserProfileResponse(
        id=user_id,
        name=req.name.strip(),
        email=req.email,
        role="user",
        status="active",
        created_at=now,
        last_login=now
    )

    return AuthTokenResponse(
        access_token=token,
        token_type="bearer",
        user=safe_profile
    )

@auth_router.post("/login", response_model=AuthTokenResponse)
async def login(req: UserLoginRequest, request: Request, response: Response):
    """
    Authenticates user credentials, sets HTTP-only session cookie, updates last_login timestamp.
    """
    client_ip = request.client.host if request.client else "unknown"
    AuthService.check_rate_limit(client_ip)

    if not db_manager.is_connected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database service unavailable. Please try again later."
        )

    users_col = db_manager.get_users_col()
    user_doc = await users_col.find_one({"email": req.email})

    if not user_doc or not AuthService.verify_password(req.password, user_doc.get("password_hash", "")):
        await AuthService.log_audit_event("LOGIN_FAILED", ip_address=client_ip, details={"email": req.email})
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    if user_doc.get("status") == "suspended":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is suspended. Contact security administrator."
        )

    now = datetime.now(timezone.utc)
    await users_col.update_one({"id": user_doc["id"]}, {"$set": {"last_login": now}})
    await AuthService.log_audit_event("LOGIN_SUCCESS", user_id=user_doc["id"], ip_address=client_ip)

    token = AuthService.create_access_token(user_doc["id"], user_doc["email"], user_doc.get("role", "user"))
    _set_auth_cookie(response, token)

    safe_profile = UserProfileResponse(
        id=user_doc["id"],
        name=user_doc["name"],
        email=user_doc["email"],
        role=user_doc.get("role", "user"),
        status=user_doc.get("status", "active"),
        created_at=user_doc["created_at"],
        last_login=now
    )

    return AuthTokenResponse(
        access_token=token,
        token_type="bearer",
        user=safe_profile
    )

@auth_router.get("/me", response_model=UserProfileResponse)
async def get_me(current_user: UserProfileResponse = Depends(get_current_user)):
    """
    Returns current authenticated user profile.
    Requires valid JWT token or session cookie.
    """
    return current_user

@auth_router.post("/logout")
async def logout(response: Response, request: Request, current_user: Optional[UserProfileResponse] = Depends(get_current_user)):
    """
    Clears HTTP-only session cookie and registers logout audit event.
    """
    response.delete_cookie(key=settings.COOKIE_NAME, path="/")
    client_ip = request.client.host if request.client else "unknown"
    if current_user:
        await AuthService.log_audit_event("LOGOUT", user_id=current_user.id, ip_address=client_ip)
    return {"message": "Logged out successfully."}

@auth_router.post("/password")
async def change_password(
    req: PasswordChangeRequest,
    request: Request,
    response: Response,
    current_user: UserProfileResponse = Depends(get_current_user)
):
    """
    Allows authenticated users to change their password securely.
    Verifies current password before updating to new bcrypt hash.
    """
    if not db_manager.is_connected:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Database unavailable.")

    users_col = db_manager.get_users_col()
    user_doc = await users_col.find_one({"id": current_user.id})

    if not user_doc or not AuthService.verify_password(req.current_password, user_doc.get("password_hash", "")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password verification failed."
        )

    new_hash = AuthService.hash_password(req.new_password)
    now = datetime.now(timezone.utc)

    await users_col.update_one(
        {"id": current_user.id},
        {"$set": {"password_hash": new_hash, "updated_at": now}}
    )

    client_ip = request.client.host if request.client else "unknown"
    await AuthService.log_audit_event("PASSWORD_CHANGE", user_id=current_user.id, ip_address=client_ip)

    # Issue refreshed token and update cookie
    new_token = AuthService.create_access_token(current_user.id, current_user.email, current_user.role)
    _set_auth_cookie(response, new_token)

    return {"message": "Password changed successfully."}
