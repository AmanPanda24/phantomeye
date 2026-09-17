"""
PhantomEye — Database Manager
SQLite-backed persistent session storage.
"""

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from ..config import Config


class Database:
    def __init__(self):
        cfg = Config.load()
        db_path = Path(cfg.db_path)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(db_path))
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self):
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS sessions (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                target_type TEXT    NOT NULL,
                target      TEXT    NOT NULL,
                created_at  TEXT    NOT NULL
            );

            CREATE TABLE IF NOT EXISTS results (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL REFERENCES sessions(id),
                data       TEXT    NOT NULL,
                saved_at   TEXT    NOT NULL
            );
        """)
        self.conn.commit()

    def new_session(self, target_type: str, target: str) -> int:
        cur = self.conn.execute(
            "INSERT INTO sessions (target_type, target, created_at) VALUES (?, ?, ?)",
            (target_type, target, datetime.utcnow().isoformat()),
        )
        self.conn.commit()
        return cur.lastrowid

    def save_results(self, session_id: int, data: dict):
        self.conn.execute(
            "INSERT INTO results (session_id, data, saved_at) VALUES (?, ?, ?)",
            (session_id, json.dumps(data, default=str), datetime.utcnow().isoformat()),
        )
        self.conn.commit()

    def list_sessions(self, limit: int = 20) -> List[dict]:
        cur = self.conn.execute(
            "SELECT id, target_type, target, created_at FROM sessions "
            "ORDER BY created_at DESC LIMIT ?",
            (limit,),
        )
        return [dict(row) for row in cur.fetchall()]

    def get_session_results(self, session_id: int) -> Optional[dict]:
        cur = self.conn.execute(
            "SELECT data FROM results WHERE session_id = ? ORDER BY saved_at DESC LIMIT 1",
            (session_id,),
        )
        row = cur.fetchone()
        return json.loads(row["data"]) if row else None

    def close(self):
        self.conn.close()
