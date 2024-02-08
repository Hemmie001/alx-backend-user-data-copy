import os
import re
import logging
import mysql.connector
from typing import List, Pattern


patterns: dict[str, Pattern[str]] = {
    'extract': lambda x, y: re.compile(r'(?P<field>{})=[^{}]*'.format('|'.join(x), y)),
    'replace': lambda x: r'\g<field>={}'.format(x),
}
PII_FIELDS: tuple[str, ...] = ("name", "email", "phone", "ssn", "password")


def filter_datum(
    fields: List[str], redaction: str, message: str, separator: str
) -> str:
    """Filter sensitive information in a log message."""
    extract, replace = patterns["extract"], patterns["replace"]
    return re.sub(extract(fields, separator), replace(redaction), message)


class RedactingFormatter(logging.Formatter):
    """Custom logging formatter for redacting sensitive information."""

    def __init__(self, fields: List[str]) -> None:
        super().__init__()
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        for field in self.fields:
            setattr(record, field, "REDACTED")
        return super().format(record)


def get_logger() -> logging.Logger:
    """Create a logger for user data."""
    logger = logging.getLogger("user_data")
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(RedactingFormatter(PII_FIELDS))
    logger.setLevel(logging.INFO)
    logger.propagate = False
    logger.addHandler(stream_handler)
    return logger
