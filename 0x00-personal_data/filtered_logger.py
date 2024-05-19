#!/usr/bin/env python3
"""Regex-ing"""

import logging
import os
import re
from typing import List

import mysql

PII_FIELDS = ("name", "fields", "phone", "ssn", "password")


def filter_datum(
    fields: List[str], redaction: str, message: str, separator: str
) -> str:
    """Returns the log message obfuscated"""
    keys = "=|".join(fields)
    return re.sub(rf"({keys}=)[^{separator}]*", rf"\1{redaction}", message)


class RedactingFormatter(logging.Formatter):
    """Redacting Formatter class"""

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """Filter logs using filter_datum"""
        msg = super().format(record)
        return filter_datum(self.fields, self.REDACTION, msg, self.SEPARATOR)


def get_logger() -> logging.Logger:
    """Create a logger"""
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(RedactingFormatter(PII_FIELDS))
    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """Connect to secure database"""
    username = os.environ.get("PERSONAL_DATA_DB_USERNAME", "root")
    host = os.environ.get("PERSONAL_DATA_DB_HOST", "localhost")
    psw = os.environ.get("PERSONAL_DATA_DB_PASSWORD", "")
    db_name = os.environ.get("PERSONAL_DATA_DB_NAME")
    conn = mysql.connector.connect(
        host=host, database=db_name, user=username, password=psw
    )
    return conn
