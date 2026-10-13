import os
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pwdlib import PasswordHash
from sqlalchemy import select
from sqlalchemy.orm import Session

from .database import get_db
from .models import User

JWT_SECRET = os.environ["JWT_SECRET"]
if len(JWT_SECRET) < 32 or JWT_SECRET == "changeme":
    raise RuntimeError("JWT_SECRET absent, trop court ou non modifié (32 caractères minimum).")
JWT_ALGORITHM = "HS256"
TOKEN_DURATION = timedelta(hours=8)

password_hash = PasswordHash.recommended()
security = HTTPBearer()

# Sert à faire durer le login autant pour un utilisateur inconnu que connu.
DUMMY_HASH = password_hash.hash("mot-de-passe-factice-pour-le-timing")


def hash_password(password: str) -> str:
    return password_hash.hash(password)


def verify_password(password: str, stored_hash: str) -> bool:
    return password_hash.verify(password, stored_hash)


def create_access_token(user_id: int) -> str:
    expires_at = datetime.now(timezone.utc) + TOKEN_DURATION
    return jwt.encode(
        {"sub": str(user_id), "exp": expires_at},
        JWT_SECRET,
        algorithm=JWT_ALGORITHM,
    )


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
) -> User:
    try:
        payload = jwt.decode(
            credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM]
        )
        user_id = int(payload["sub"])
    except (jwt.InvalidTokenError, KeyError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Jeton de connexion invalide ou expiré.",
        )

    user = db.scalar(select(User).where(User.id == user_id))
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Utilisateur introuvable.",
        )
    return user
