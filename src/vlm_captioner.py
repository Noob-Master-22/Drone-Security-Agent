

import base64
import os
from groq import Groq
from dotenv import load_dotenv

load_dotenv()
client = Groq(api_key=os.getenv("GROQ_API_KEY"))


VLM_MODEL = "meta-llama/llama-4-scout-17b-16e-instruct"


SYSTEM_PROMPT = """You are an AI security analyst reviewing live drone camera footage 
of a private property. Your job is to describe each frame clearly and concisely, 
focusing ONLY on security-relevant details.

Always mention:
- People: how many, what they're doing, anything suspicious
- Vehicles: type (truck/car/van), colour, movement direction, approximate plate if visible
- Location context: gate, parking area, perimeter, garage
- Any unusual or suspicious activity

Keep your description under 3 sentences. Be specific and factual."""


def caption_frame(image_path: str, zone: str, timestamp: str) -> str:
    """

    Args:
        image_path: local path to the .jpg frame file
        zone:       which part of the property this camera covers
        timestamp:  when this frame was captured (used for context in prompt)

    Returns:
        A plain text description of the frame from a security perspective.
    """
    
    with open(image_path, "rb") as f:
        image_b64 = base64.b64encode(f.read()).decode("utf-8")

    try:
        response = client.chat.completions.create(
            model=VLM_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": SYSTEM_PROMPT
                },
                {
                    "role": "user",
                    "content": [
                        
                        {
                            "type": "image_url",
                            "image_url": {
                                "url": f"data:image/jpeg;base64,{image_b64}"
                            }
                        },
                       
                        {
                            "type": "text",
                            "text": f"Camera Zone: {zone} | Timestamp: {timestamp}\n\nDescribe what you see in this frame."
                        }
                    ]
                }
            ],
            max_tokens=250,    
            temperature=0.2    
        )
        caption = response.choices[0].message.content.strip()
        return caption

    except Exception as e:
       
        print(f"[VLM] Caption failed for {image_path}: {e}")
        return f"[VLM ERROR] Could not caption frame at {zone}, {timestamp}."
    
    


ZONE_CLASSIFICATION_PROMPT = """You are a drone security camera system analyzing a frame.

Based ONLY on what you can visually see in this image, classify the location into ONE of these zones:
- Main Gate (if you see a gate, entrance, barrier, or driveway entry)
- Parking Lot (if you see parked vehicles, parking spaces, open tarmac area)
- Garage (if you see a garage door, workshop, enclosed vehicle storage)
- Back Perimeter (if you see a fence, wall, boundary, backyard area)
- Side Entrance (if you see a side door, walkway, side path)
- Unknown (if you cannot determine the location)

Reply with ONLY the zone name from the list above. Nothing else."""


def identify_zone(image_path: str) -> str:
    
    with open(image_path, "rb") as f:
        image_b64 = base64.b64encode(f.read()).decode("utf-8")

    VALID_ZONES = [
        "Main Gate", "Parking Lot", "Garage",
        "Back Perimeter", "Side Entrance", "Unknown"
    ]

    try:
        response = client.chat.completions.create(
            model=VLM_MODEL,
            messages=[
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "image_url",
                            "image_url": {"url": f"data:image/jpeg;base64,{image_b64}"}
                        },
                        {
                            "type": "text",
                            "text": ZONE_CLASSIFICATION_PROMPT
                        }
                    ]
                }
            ],
            max_tokens=10,      # we only need one short phrase back
            temperature=0.0     # zero temp = deterministic classification
        )

        raw = response.choices[0].message.content.strip()

        # Validate the response is one of our expected zones
        for zone in VALID_ZONES:
            if zone.lower() in raw.lower():
                return zone

        return "Unknown"

    except Exception as e:
        print(f"[VLM] Zone identification failed: {e}")
        return "Unknown"