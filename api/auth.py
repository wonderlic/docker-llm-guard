from __future__ import annotations

import os

from fastapi import Header, HTTPException, status


def require_bearer_token(authorization: str | None = Header(default=None)) -> None:
    token = os.environ.get("AUTH_TOKEN", "")
    if not token:
        return

    if authorization != f"Bearer {token}":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing bearer token",
        )
