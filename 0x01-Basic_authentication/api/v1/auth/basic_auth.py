#!/usr/bin/env python3
"""Basic Auth"""

import base64
from typing import TypeVar

from .auth import Auth


class BasicAuth(Auth):
    """BasicAuth class"""

    def extract_base64_authorization_header(self, authorization_header: str) -> str:
        """Extract the base64 part of the Authorization header"""
        if (
            authorization_header is None
            or not isinstance(authorization_header, str)
            or not authorization_header.startswith("Basic ")
        ):
            return None
        return authorization_header.lstrip("Basic ")

    def decode_base64_authorization_header(
        self, base64_authorization_header: str
    ) -> str:
        """Decode the value of base64 in the Authorization header"""
        if base64_authorization_header is None or not isinstance(
            base64_authorization_header, str
        ):
            return None
        try:
            decoded_header = base64.b64decode(base64_authorization_header)
        except Exception:
            return None
        return decoded_header.decode(errors="ignore")

    def extract_user_credentials(
        self, decoded_base64_authorization_header: str
    ) -> (str, str):
        """Extract credencials from base64"""
        decoded = decoded_base64_authorization_header
        if decoded is None:
            return None, None
        if not isinstance(decoded, str):
            return None, None
        if ":" not in decoded:
            return None, None
        user_email, user_pwd = decoded.split(":", 1)
        return user_email, user_pwd
