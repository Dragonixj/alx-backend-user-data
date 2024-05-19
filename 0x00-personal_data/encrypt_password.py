#!/usr/bin/env python3
"""Task 5: Encrypting passwords"""
import bcrypt


def hash_password(password: str) -> bytes:
    """Encrypting passwords"""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
