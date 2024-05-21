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
