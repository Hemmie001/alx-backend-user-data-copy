#!/usr/bin/env python3
"""
This module implements a hash_password function
that expects one string argument name password and
returns a salted, hashed password, which is a byte string
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """This function ashes a password using a random salt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    This function 'Checks' is a hashed password
    formed from the given password.
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
