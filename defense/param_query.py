"""Parameterized query wrapper for SQL injection prevention."""

from __future__ import annotations

import sqlite3
from typing import Any, Optional


class ParamQuery:
    """Wrapper that enforces parameterized queries — the primary defense against SQLi."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(self.db_path)
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def execute(self, query: str, params: tuple = ()) -> sqlite3.Cursor:
        """Execute a parameterized query. Never concatenates user input into SQL."""
        cursor = self.conn.cursor()
        cursor.execute(query, params)
        self.conn.commit()
        return cursor

    def fetch_one(self, query: str, params: tuple = ()) -> Optional[sqlite3.Row]:
        cursor = self.conn.cursor()
        cursor.execute(query, params)
        return cursor.fetchone()

    def fetch_all(self, query: str, params: tuple = ()) -> list[sqlite3.Row]:
        cursor = self.conn.cursor()
        cursor.execute(query, params)
        return cursor.fetchall()

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None
