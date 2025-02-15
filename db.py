import sqlite3
from datetime import datetime
from logger import log_event


def get_timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def create_tables() -> None:
    conn = sqlite3.connect("honeypot.db")
    c = conn.cursor()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS login_data (
            session_id TEXT PRIMARY KEY,
            username TEXT,
            password TEXT,
            pubkey TEXT,
            timestamp TEXT
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS command_data (
            session_id TEXT,
            command TEXT,
            timestamp TEXT
        )
        """
    )
    conn.commit()
    conn.close()


def insert_login_data(session_id, username, password=None, pubkey=None) -> None:
    timestamp = get_timestamp()
    log_event(
        f"Login attempt adding to DB: {username} with password: {password} session_id: {session_id}"
    )
    conn = sqlite3.connect("honeypot.db", check_same_thread=False)
    c = conn.cursor()
    try:
        c.execute(
            """
            INSERT INTO login_data VALUES (?, ?, ?, ?, ?)
            """,
            (session_id, username, password, pubkey, timestamp),
        )
    except Exception as e:
        pass
    conn.commit()
    conn.close()


def insert_command_data(session_id, command) -> None:
    timestamp = get_timestamp()
    conn = sqlite3.connect("honeypot.db", check_same_thread=False)
    c = conn.cursor()
    try:
        c.execute(
            """
            INSERT INTO command_data VALUES (?, ?, ?)
            """,
            (session_id, command, timestamp),
        )
    except Exception as e:
        pass

    conn.commit()
    conn.close()
