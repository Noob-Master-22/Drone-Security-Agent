
import json
import os
from groq import Groq
from dotenv import load_dotenv
from src.models import FrameEvent

load_dotenv()
client = Groq(api_key=os.getenv("GROQ_API_KEY"))

TEXT_MODEL = "llama-3.3-70b-versatile"

# The schema we want back — defined inline in the prompt so the LLM
# knows exactly what fields to populate
EXTRACTION_PROMPT = """You are a data extraction assistant. Extract structured security event data from a drone camera frame description.

Frame Description: "{caption}"
Zone: {zone}
Timestamp: {timestamp}

Return ONLY a valid JSON object with these exact fields:
{{
  "object_type": "vehicle" or "person" or "unknown",
  "color": "the colour if it's a vehicle (e.g. blue, white, red), null if person or unknown",
  "vehicle_model": "truck, car, van, motorcycle, bus — null if not a vehicle",
  "action": "one of: entering, exiting, parked, loitering, walking, running, standing, unknown",
  "person_count": integer — number of people visible in the frame,
  "suspicious": true if anything unusual/suspicious is mentioned, false otherwise
}}

Rules:
- If both a vehicle and person are present, set object_type to whichever is the primary subject
- suspicious = true if words like: loitering, suspicious, unusual, threatening, running at night appear
- Return ONLY the JSON. No explanation, no markdown, no code blocks."""


def parse_caption_to_event(
    caption: str,
    frame_id: int,
    timestamp: str,
    zone: str
) -> FrameEvent:
    """
    Uses an LLM to extract structured fields from a VLM caption.

    Args:
        caption:    raw text from the VLM captioner
        frame_id:   which frame this is
        timestamp:  when it was captured
        zone:       which zone of the property

    Returns:
        A FrameEvent Pydantic model with all fields populated.
        Falls back to safe defaults if JSON parsing fails.
    """
    prompt = EXTRACTION_PROMPT.format(
        caption=caption,
        zone=zone,
        timestamp=timestamp
    )

    try:
        response = client.chat.completions.create(
            model=TEXT_MODEL,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=200,
            temperature=0.0   
        )

        raw_output = response.choices[0].message.content.strip()

        # LLMs sometimes wrap JSON in markdown code blocks even when told not to
        # Strip those out before parsing
        raw_output = raw_output.replace("```json", "").replace("```", "").strip()

        data = json.loads(raw_output)

    except json.JSONDecodeError as e:
       
        print(f"[Parser] JSON decode failed for frame {frame_id}: {e}")
        print(f"[Parser] Raw output was: {raw_output}")
        data = {
            "object_type": "unknown",
            "color": None,
            "vehicle_model": None,
            "action": "unknown",
            "person_count": 0,
            "suspicious": False
        }

    except Exception as e:
        print(f"[Parser] LLM call failed for frame {frame_id}: {e}")
        data = {
            "object_type": "unknown",
            "color": None,
            "vehicle_model": None,
            "action": "unknown",
            "person_count": 0,
            "suspicious": False
        }

    # Build and return the Pydantic model — this validates the data automatically
    return FrameEvent(
        frame_id=frame_id,
        timestamp=timestamp,
        zone=zone,
        raw_caption=caption,
        object_type=data.get("object_type", "unknown"),
        color=data.get("color"),
        vehicle_model=data.get("vehicle_model"),
        action=data.get("action", "unknown"),
        person_count=int(data.get("person_count", 0)),
        suspicious=bool(data.get("suspicious", False))
    )