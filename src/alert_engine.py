
from src.models import FrameEvent, Alert
from src.database import get_vehicle_count_today


RESTRICTED_ZONES = ["garage", "back perimeter", "server room", "storage"]


NIGHT_START = 22   # 10pm
NIGHT_END = 6      # 6am


def _get_hour(timestamp: str) -> int:
    """
    Extracts the hour integer from a timestamp string.
    Handles formats like '2025-01-15 23:45' or '23:45'.
    Returns 12 (noon) as a safe default if parsing fails.
    """
    try:
        
        time_part = timestamp.split(" ")[1] if " " in timestamp else timestamp
        return int(time_part.split(":")[0])
    except (IndexError, ValueError):
        return 12


def _is_night(hour: int, caption: str = "") -> bool:
    # If VLM explicitly says nighttime in caption, trust it
    night_keywords = ["night", "nighttime", "dark", "midnight", "after hours", "evening"]
    if any(kw in caption.lower() for kw in night_keywords):
        return True
    return hour >= NIGHT_START or hour < NIGHT_END


def _is_restricted_zone(zone: str) -> bool:
    
    return any(rz in zone.lower() for rz in RESTRICTED_ZONES)




def rule_loitering(event: FrameEvent, hour: int, caption: str = "") -> Alert | None:
    
    if (
        event.object_type in ["person", "human", "individual"]
        and event.action in ["loitering", "standing", "idle", "waiting", "present"]
        and _is_night(hour)
    ):
        return Alert(
            timestamp=event.timestamp,
            alert_type="loitering",
            severity="HIGH",
            message=f"Person loitering at {event.zone} at {event.timestamp}. Immediate attention required.",
            frame_id=event.frame_id,
            zone=event.zone
        )
    return None


def rule_person_at_gate_after_hours(event: FrameEvent, hour: int, caption:str = "") -> Alert | None:
    
    if (
        event.object_type == "person"
        and "gate" in event.zone.lower()
        and _is_night(hour)
    ):
        return Alert(
            timestamp=event.timestamp,
            alert_type="unauthorized_access",
            severity="HIGH",
            message=f"Person detected at {event.zone} after hours ({event.timestamp}). Possible unauthorized access.",
            frame_id=event.frame_id,
            zone=event.zone
        )
    return None


def rule_repeated_vehicle(event: FrameEvent) -> Alert | None:
    if (
        event.object_type == "vehicle"
        and event.color
        and event.vehicle_model
        and event.action in ["entering", "unknown"]
    ):
        
        event_date = event.timestamp.split(" ")[0] if " " in event.timestamp else None

        count = get_vehicle_count_today(
            event.color,
            event.vehicle_model,
            date=event_date   
        )
        if count >= 2:
            return Alert(
                timestamp=event.timestamp,
                alert_type="repeated_vehicle",
                severity="MEDIUM",
                message=f"{event.color.title()} {event.vehicle_model} has entered {count} times today. Last seen at {event.zone}, {event.timestamp}.",
                frame_id=event.frame_id,
                zone=event.zone
            )
    return None

def rule_restricted_zone(event: FrameEvent, hour: int, caption: str = "") -> Alert | None:
    
    if _is_restricted_zone(event.zone) and _is_night(hour):
        return Alert(
            timestamp=event.timestamp,
            alert_type="restricted_zone",
            severity="HIGH",
            message=f"Activity detected in restricted zone '{event.zone}' at {event.timestamp}. Investigate immediately.",
            frame_id=event.frame_id,
            zone=event.zone
        )
    return None


def rule_suspicious_flag(event: FrameEvent) -> Alert | None:
    """
    Rule: The VLM or parser flagged this frame as suspicious.
    This is our catch-all — if the AI noticed something unusual
    that doesn't match other rules, we still want to log it.
    """
    if event.suspicious:
        return Alert(
            timestamp=event.timestamp,
            alert_type="suspicious_activity",
            severity="MEDIUM",
            message=f"Suspicious activity flagged at {event.zone}, {event.timestamp}: \"{event.raw_caption[:120]}\"",
            frame_id=event.frame_id,
            zone=event.zone
        )
    return None


# ─── Main Entry Point ────────────────────────────────────────────────────────

def run_alert_rules(event: FrameEvent) -> list[Alert]:
    """
    Args:
        event: the structured FrameEvent to check

    Returns:
        List of Alert objects (can be empty if no rules fire)
    """
    hour = _get_hour(event.timestamp)
    caption = event.raw_caption or ""
    alerts = []

    for rule_fn in [
        lambda e: rule_loitering(e, hour, caption),
        lambda e: rule_person_at_gate_after_hours(e, hour, caption),
        lambda e: rule_repeated_vehicle(e),
        lambda e: rule_restricted_zone(e, hour, caption),
        lambda e: rule_suspicious_flag(e),
    ]:
        result = rule_fn(event)
        if result is not None:
            alerts.append(result)

    return alerts