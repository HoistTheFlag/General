import os
import time
import secrets
from typing import Optional, List, Callable


import pyotp
from argon2 import PasswordHasher
from fastapi import FastAPI, Depends, HTTPException, status, Form
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from pydantic import BaseModel, EmailStr


from sqlalchemy import create_engine, Column, Integer, String, Boolean
from sqlalchemy.orm import declarative_base, sessionmaker, Session


# ----------------------------
# Config
# ----------------------------
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./iam_demo")
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")  # use a real secret manager in prod
JWT_ALG = "HS256"
ACCESS_TOKEN_TTL_SECONDS = 15 * 60


# Permissions per role (RBAC)
ROLE_PERMS = {
   "user": ["read:profile"],
   "admin": ["read:profile", "read:admin", "write:admin"],
}


ph = PasswordHasher()


# ----------------------------
# DB setup
# ----------------------------
Base = declarative_base()
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)




class User(Base):
   __tablename__ = "users"


   id = Column(Integer, primary_key=True)
   email = Column(String, unique=True, index=True, nullable=False)
   password_hash = Column(String, nullable=False)
   role = Column(String, nullable=False, default="user")


   mfa_enabled = Column(Boolean, nullable=False, default=False)
   mfa_secret = Column(String, nullable=True)  # TOTP secret (store encrypted in prod)




Base.metadata.create_all(bind=engine)


# ----------------------------
# FastAPI + auth helpers
# ----------------------------
app = FastAPI(title="Vibecoded IAM (FastAPI + JWT + RBAC + TOTP)")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")




def get_db():
   db = SessionLocal()
   try:
       yield db
   finally:
       db.close()




def create_access_token(*, sub: str, role: str) -> str:
   now = int(time.time())
   payload = {
       "sub": sub,
       "role": role,
       "iat": now,
       "exp": now + ACCESS_TOKEN_TTL_SECONDS,
   }
   return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)




def decode_token(token: str) -> dict:
   try:
       return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
   except JWTError:
       raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")




def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)) -> User:
   payload = decode_token(token)
   email = payload.get("sub")
   if not email:
       raise HTTPException(status_code=401, detail="Token missing subject")


   user = db.query(User).filter(User.email == email).first()
   if not user:
       raise HTTPException(status_code=401, detail="User not found")


   return user




def require_permission(permission: str) -> Callable:
   """
   Dependency factory: checks if current user's role includes permission.
   """
   def _check(user: User = Depends(get_current_user)) -> User:
       perms = ROLE_PERMS.get(user.role, [])
       if permission not in perms:
           raise HTTPException(status_code=403, detail=f"Missing permission: {permission}")
       return user
   return _check




# ----------------------------
# Schemas
# ----------------------------
class RegisterIn(BaseModel):
   email: EmailStr
   password: str
   role: Optional[str] = "user"  # in prod, don't let self-register choose admin




class LoginIn(BaseModel):
   email: EmailStr
   password: str
   totp_code: Optional[str] = None




class TokenOut(BaseModel):
   access_token: str
   token_type: str = "bearer"




class MFASetupOut(BaseModel):
   secret: str
   provisioning_uri: str




class MFAVerifyIn(BaseModel):
   totp_code: str




# ----------------------------
# Routes
# ----------------------------
@app.post("/auth/register")
def register(payload: RegisterIn, db: Session = Depends(get_db)):
   if db.query(User).filter(User.email == payload.email).first():
       raise HTTPException(400, "Email already registered")


   # Hash password (Argon2)
   pw_hash = ph.hash(payload.password)


   role = payload.role or "user"
   if role not in ROLE_PERMS:
       role = "user"


   user = User(email=payload.email, password_hash=pw_hash, role=role)
   db.add(user)
   db.commit()
   return {"message": "Registered", "email": user.email, "role": user.role}




@app.post("/auth/login", response_model=TokenOut)
def login(
    username: str = Form(...),          # Swagger uses "username"
    password: str = Form(...),
    totp_code: Optional[str] = Form(None),
    db: Session = Depends(get_db),
):
    # Treat username as email
    user = db.query(User).filter(User.email == username).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    try:
        ph.verify(user.password_hash, password)
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if user.mfa_enabled:
        if not totp_code:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="MFA required: provide totp_code")
        totp = pyotp.TOTP(user.mfa_secret)
        if not totp.verify(totp_code, valid_window=1):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA code")

    token = create_access_token(sub=user.email, role=user.role)
    return TokenOut(access_token=token)




@app.get("/me")
def me(user: User = Depends(get_current_user)):
   return {"email": user.email, "role": user.role, "mfa_enabled": user.mfa_enabled}




@app.get("/admin/read")
def admin_read(_: User = Depends(require_permission("read:admin"))):
   return {"message": "You can read admin data."}




@app.post("/admin/write")
def admin_write(_: User = Depends(require_permission("write:admin"))):
   return {"message": "You can write admin data."}




# ---- MFA setup flow ----
@app.post("/mfa/setup", response_model=MFASetupOut)
def mfa_setup(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
   """
   Generates a TOTP secret and provisioning URI for an authenticator app.
   User scans QR (you can render the URI as a QR code client-side).
   """
   if user.mfa_enabled:
       raise HTTPException(400, "MFA already enabled")


   secret = pyotp.random_base32()
   # store secret for the user (encrypt at rest in prod!)
   user.mfa_secret = secret
   db.add(user)
   db.commit()


   issuer = "VibecodedIAM"
   provisioning_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=user.email, issuer_name=issuer)
   return MFASetupOut(secret=secret, provisioning_uri=provisioning_uri)




@app.post("/mfa/verify")
def mfa_verify(payload: MFAVerifyIn, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
   """
   Verifies the TOTP code and flips mfa_enabled to True.
   """
   if not user.mfa_secret:
       raise HTTPException(400, "Run /mfa/setup first")


   totp = pyotp.TOTP(user.mfa_secret)
   if not totp.verify(payload.totp_code, valid_window=1):
       raise HTTPException(400, "Invalid code")


   user.mfa_enabled = True
   db.add(user)
   db.commit()
   return {"message": "MFA enabled"}




@app.post("/mfa/disable")
def mfa_disable(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
   user.mfa_enabled = False
   user.mfa_secret = None
   db.add(user)
   db.commit()
   return {"message": "MFA disabled"}


