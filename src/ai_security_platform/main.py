"""ASGI factory: uvicorn ai_security_platform.main:create_app --factory."""

from ai_security_platform.api.app import create_app

__all__ = ["create_app"]
