
import time
from datetime import datetime, timedelta
from src.frame_extractor import extract_frames
from src.vlm_captioner import caption_frame
from src.parser import parse_caption_to_event
from src.alert_engine import run_alert_rules
from src.database import init_db, insert_event, insert_alert, get_daily_summary_data
from src.models import FrameEvent
from src.vlm_captioner import caption_frame, identify_zone

# Zones we rotate through based on frame_id
# In a real system, each camera has a fixed zone — here we simulate rotation
ZONE_MAP = [
    "Main Gate",
    "Parking Lot",
    "Garage",
    "Back Perimeter",
    "Side Entrance"
]


SIMULATION_START_TIME = datetime(2025, 1, 15, 8, 0, 0)


def _get_simulated_timestamp(frame_id: int, interval_seconds: int) -> str:
    """
    Maps a frame_id to a simulated wall-clock timestamp.
    Frame 0 = 08:00, Frame 1 = 08:05 (if interval=5), etc.
    This lets us test night-time rules even with daytime footage
    by advancing the simulated clock past midnight.
    """
    simulated_time = SIMULATION_START_TIME + timedelta(seconds=frame_id * interval_seconds)
    return simulated_time.strftime("%Y-%m-%d %H:%M:%S")


def _get_zone(frame_id: int) -> str:
    """Rotates through zones based on frame number."""
    return ZONE_MAP[frame_id % len(ZONE_MAP)]


def process_video(
    video_path: str,
    every_n_seconds: int = 5,
    delay_between_frames: float = 0.5,
    progress_callback=None
) -> list[dict]:
    
    # Step 0: make sure DB tables exist before we try to insert anything
    init_db()

    # Step 1: extract all frames from the video upfront
   
    print(f"\n{'='*60}")
    print(f"[Pipeline] Starting processing: {video_path}")
    print(f"{'='*60}")

    frame_paths = extract_frames(video_path, every_n_seconds)
    total_frames = len(frame_paths)

    if total_frames == 0:
        raise ValueError("No frames were extracted. Check your video path and format.")

    print(f"[Pipeline] Processing {total_frames} frames...\n")

    results = []

    # Step 2: process each frame one at a time
    for frame_info in frame_paths:
        frame_id = frame_info["frame_id"]
        image_path = frame_info["path"]

    # ── Real timestamp from video metadata ──────────────────────────
        timestamp = frame_info["timestamp"]   # ← from extractor, not simulated

    
        zone = identify_zone(image_path)
        print(f"\n[Frame {frame_id:03d}/{total_frames-1}] Zone: {zone} | {timestamp}")

        
        caption = caption_frame(image_path, zone, timestamp)
        print(f"  VLM Caption: {caption[:120]}{'...' if len(caption) > 120 else ''}")

        
        event = parse_caption_to_event(caption, frame_id, timestamp, zone)
        print(f"  Parsed → type: {event.object_type} | "
              f"color: {event.color} | model: {event.vehicle_model} | "
              f"action: {event.action} | suspicious: {event.suspicious}")

        
        insert_event(event)

        
        #index_event(event)

        
        alerts = run_alert_rules(event)
        for alert in alerts:
            insert_alert(alert)
            print(f"  🚨 [{alert.severity}] {alert.alert_type.upper()}: {alert.message}")

        
        results.append({
            "frame_id": frame_id,
            "timestamp": timestamp,
            "zone": zone,
            "event": event,
            "alerts": alerts,
            "caption": caption
        })

        
        if progress_callback:
            progress_callback(frame_id, total_frames, event, alerts, image_path, caption)

        
        time.sleep(delay_between_frames)

    
    summary = get_daily_summary_data()
    print(f"\n{'='*60}")
    print(f"[Pipeline] ✅ Complete — {total_frames} frames processed")
    print(f"  Vehicles detected: {summary['vehicle_count']}")
    print(f"  People detected:   {summary['person_count']}")
    print(f"  Total alerts:      {summary['total_alerts']} "
          f"({summary['high_alerts']} HIGH, {summary['medium_alerts']} MEDIUM)")
    print(f"{'='*60}\n")

    return results


def generate_daily_brief(results: list[dict], groq_client) -> str:
    
    summary = get_daily_summary_data()

    
    event_lines = []
    for r in results:
        e = r["event"]
        line = f"- {r['timestamp']} | {r['zone']} | {e.object_type}"
        if e.color and e.vehicle_model:
            line += f" ({e.color} {e.vehicle_model})"
        if e.action:
            line += f" — {e.action}"
        if r["alerts"]:
            line += f" ⚠️ {', '.join(a.alert_type for a in r['alerts'])}"
        event_lines.append(line)

    events_text = "\n".join(event_lines[:30])  # cap at 30 to stay within token limits

    prompt = f"""You are a security analyst. Write a concise 2-3 sentence daily security brief 
based on the following drone monitoring data from today.

Stats:
- Vehicles detected: {summary['vehicle_count']}
- People detected: {summary['person_count']}
- Total alerts: {summary['total_alerts']} ({summary['high_alerts']} HIGH severity)

Events:
{events_text}

Write a professional security brief summarising the day's activity, key incidents, and risk level."""

    response = groq_client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=200,
        temperature=0.3
    )
    return response.choices[0].message.content.strip()