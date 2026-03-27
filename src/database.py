
import sqlite3
from src.models import FrameEvent, Alert


DB_PATH = "drone_security.db"


def init_db():
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()


    c.execute("""
        CREATE TABLE IF NOT EXISTS events (
            event_id        INTEGER PRIMARY KEY AUTOINCREMENT,
            frame_id        INTEGER NOT NULL,
            timestamp       TEXT NOT NULL,
            zone            TEXT,
            object_type     TEXT,
            color           TEXT,
            vehicle_model   TEXT,
            action          TEXT,
            person_count    INTEGER DEFAULT 0,
            suspicious      BOOLEAN DEFAULT 0,
            raw_caption     TEXT
        )
    """)

   
    c.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            alert_id    INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            alert_type  TEXT,
            severity    TEXT,
            message     TEXT,
            frame_id    INTEGER,
            zone        TEXT,
            FOREIGN KEY (frame_id) REFERENCES events(frame_id)
        )
    """)

   
    c.execute("CREATE INDEX IF NOT EXISTS idx_timestamp    ON events(timestamp)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_object_type  ON events(object_type)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_zone         ON events(zone)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_alert_type   ON alerts(alert_type)")

    conn.commit()
    conn.close()
    print("[DB] Initialized successfully.")


def insert_event(event: FrameEvent):
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        INSERT INTO events 
        (frame_id, timestamp, zone, object_type, color, vehicle_model,
         action, person_count, suspicious, raw_caption)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        event.frame_id, event.timestamp, event.zone,
        event.object_type, event.color, event.vehicle_model,
        event.action, event.person_count, int(event.suspicious),
        event.raw_caption
    ))
    conn.commit()
    conn.close()


def insert_alert(alert: Alert):
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        INSERT INTO alerts (timestamp, alert_type, severity, message, frame_id, zone)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        alert.timestamp, alert.alert_type, alert.severity,
        alert.message, alert.frame_id, alert.zone
    ))
    conn.commit()
    conn.close()


def get_events_by_object(object_type: str, color: str = None) -> list:
   
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    if color:
        c.execute(
            "SELECT * FROM events WHERE object_type=? AND color=?",
            (object_type, color)
        )
    else:
        c.execute("SELECT * FROM events WHERE object_type=?", (object_type,))
    rows = c.fetchall()
    conn.close()
    return rows


def get_events_by_zone(zone: str) -> list:
   
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM events WHERE zone LIKE ?", (f"%{zone}%",))
    rows = c.fetchall()
    conn.close()
    return rows



def get_vehicle_count_today(color: str, model: str, date: str = None) -> int:
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Use provided date or fall back to today
    if date is None:
        from datetime import datetime
        date = datetime.now().strftime("%Y-%m-%d")

    c.execute("""
        SELECT COUNT(*) FROM events
        WHERE object_type='vehicle'
          AND color=?
          AND vehicle_model=?
          AND timestamp LIKE ?
    """, (color, model, f"{date}%"))

    count = c.fetchone()[0]
    conn.close()
    return count


def get_all_alerts() -> list:
    """Fetch all alerts ordered by most recent first. Used by Streamlit UI."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM alerts ORDER BY timestamp DESC")
    rows = c.fetchall()
    conn.close()
    return rows


def get_all_events() -> list:
    """Fetch all events ordered by most recent first. Used by Streamlit UI."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM events ORDER BY timestamp DESC")
    rows = c.fetchall()
    conn.close()
    return rows


def get_daily_summary_data() -> dict:
    """
    Pulls aggregate stats for the daily security brief.
    Returns counts per object type, alert severity breakdown, etc.
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("SELECT COUNT(*) FROM events WHERE object_type='vehicle'")
    vehicle_count = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM events WHERE object_type='person'")
    person_count = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM alerts WHERE severity='HIGH'")
    high_alerts = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM alerts WHERE severity='MEDIUM'")
    medium_alerts = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM alerts")
    total_alerts = c.fetchone()[0]

    conn.close()
    return {
        "vehicle_count": vehicle_count,
        "person_count": person_count,
        "high_alerts": high_alerts,
        "medium_alerts": medium_alerts,
        "total_alerts": total_alerts
    }