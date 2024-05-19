#!/usr/bin/env python3
"""Regex-ing"""

import re
from typing import List


def filter_datum(
    fields: List[str], redaction: str, message: str, separator: str
) -> str:
    """Returns the log message obfuscated"""
    keys = "=|".join(fields)
    return re.sub(rf"({keys}=)[^{separator}]*", rf"\1{redaction}", message)
