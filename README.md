# Drone Security Analyst Agent

An AI-powered drone security monitoring system that processes real video footage frame-by-frame, detects security events using a Vision Language Model (VLM), generates real-time alerts, and answers natural language questions about the session via an intelligent agent.

Built as part of a FlytBase AI Engineer assignment — designed to showcase a production-grade agentic AI pipeline using modern LLM tooling.

---

## Features

- **Real Video Processing** — Extracts frames from actual video footage using OpenCV with real timestamps from video metadata
- **Automatic Zone Detection** — VLM visually classifies which zone of the property each frame shows (Main Gate, Garage, Parking Lot, etc.)
- **VLM Captioning** — Groq Vision (LLaMA 4 Scout) describes each frame from a security perspective
- **Structured Event Parsing** — LLM extracts `object_type`, `color`, `vehicle_model`, `action`, and `suspicious` flag from captions
- **Real-time Alert Engine** — Rule-based system triggers HIGH/MEDIUM alerts for loitering, repeated vehicles, restricted zone access, and suspicious activity
- **Dual Storage** — SQLite for structured queries + ChromaDB for semantic vector search
- **AI Security Agent** — Groq native tool-calling agent with session memory answers natural language queries
- **Daily Security Brief** — LLM-generated paragraph summarising the full monitoring session
- **Streamlit Dashboard** — Live processing feed, alerts dashboard, and agent Q&A chat in one UI
- **37 Passing Unit Tests** — Fully isolated test suite with zero API calls required

---

## Architecture

```

Video File (.mp4)
│
▼
┌──────────────────────┐
│ Frame Extractor │ OpenCV — extracts 1 frame every N seconds
│ │ Real timestamps from video file metadata
└──────────┬───────────┘
│
▼
┌──────────────────────────────────────────────┐
│ Perception Layer │
│ Zone Identification (Groq Vision) │ "Main Gate"
│ VLM Caption (Groq Vision LLaMA 4 Scout) │ "White SUV entering..."
└──────────┬───────────────────────────────────┘
│
▼
┌──────────────────────────────────────────────┐
│ Structuring Layer │
│ Caption → Structured JSON Event │ LLaMA 3.3 70B
│ {object_type, color, model, action, │
│ suspicious, person_count} │
└──────────┬───────────────────────────────────┘
│
├────────────────────┐
▼ ▼
┌────────────────┐ ┌──────────────────┐
│ SQLite DB │ │ ChromaDB │
│ events table │ │ vector index │
│ alerts table │ │ semantic search │
└───────┬────────┘ └────────┬─────────┘
│ │
▼ │
┌────────────────┐ │
│ Alert Engine │ │
│ (rule-based) │ │
│ HIGH / MEDIUM │ │
└───────┬────────┘ │
│ │
└──────────┬───────────┘
▼
┌──────────────────────────────────────────────┐
│ Security Agent │
│ Groq Native Tool Calling + Session Memory │
│ Answers natural language security questions │
└──────────────────┬───────────────────────────┘
│
▼
┌──────────────────────────────────────────────┐
│ Streamlit UI │
│ Tab 1: Live Feed │ Tab 2: Alerts │
│ Tab 3: Agent Q&A Chat │
└──────────────────────────────────────────────┘

```

---

## 🛠️ Tech Stack

| Component | Tool | Reason |
|---|---|---|
| Frame extraction | OpenCV | Industry standard, frame-level ms-accurate timestamps |
| VLM captioning | Groq Vision (LLaMA 4 Scout) | Fast inference, strong scene understanding |
| Zone identification | Groq Vision (LLaMA 4 Scout) | Visual classification, no hardcoded mapping |
| Event structuring | Groq LLM (LLaMA 3.3 70B) | Reliable structured JSON extraction |
| Structured storage | SQLite | Zero setup, relational queries, no infra needed |
| Semantic search | ChromaDB | Persistent local vector store, no API key required |
| Agent | Groq Native Tool Calling | Stable, OpenAI-compatible, no LangChain version issues |
| UI | Streamlit | Rapid prototyping, live progress updates |
| Testing | Pytest | Isolated unit tests, mocked API calls, zero dependencies |

---

## 📁 Project Structure

```
drone-security-agent/
│
├── src/
│ ├── models.py # Pydantic data models (FrameEvent, Alert)
│ ├── database.py # SQLite schema, insert, and query functions
│ ├── frame_extractor.py # OpenCV frame extraction with real timestamps
│ ├── vlm_captioner.py # Groq Vision captioning + zone identification
│ ├── parser.py # LLM caption → structured FrameEvent
│ ├── alert_engine.py # Rule-based alert logic (5 alert rules)
│ ├── indexer.py # ChromaDB semantic vector indexing
│ ├── pipeline.py # End-to-end orchestrator
│ └── agent.py # Groq tool-calling security agent
│
├── tests/
│ └── test_pipeline.py # 37 unit tests across all components
│
├── frames/ # Auto-created — extracted frames saved here
├── chroma_db/ # Auto-created — ChromaDB persists here
├── assets/ # Input video files (excluded from git)
│
├── app.py # Streamlit UI entry point
├── main.py # CLI entry point
├── requirements.txt # Python dependencies
├── .env.example # Environment variable template
├── .gitignore
└── README.md
```
---

## ⚙️ Setup & Installation

### Prerequisites

- Python 3.11+
- A Groq API key — free at [console.groq.com](https://console.groq.com)
- A video file to process (MP4 recommended)

### 1. Clone the repository
```
git clone https://github.com/yourusername/drone-security-agent.git
cd drone-security-agent
```
### 2. Create and activate virtual environment
```
python3 -m venv venv
source venv/bin/activate # Mac/Linux
```
### 3. Install dependencies
```
pip install -r requirements.txt
```
### 4. Configure environment variables
```
cp .env.example .env

Edit `.env` and add your key:

GROQ_API_KEY=your_groq_api_key_here
```

### 5. Add your input video
```
cp /path/to/your/video.mp4 assets/input_video.mp4
```
---

## 🚀 Running the System

### Option A — Streamlit UI (Recommended for demo)

python -m streamlit run app.py


Open `http://localhost:8501` in your browser.

**Workflow:**
1. Upload your video via the sidebar file uploader
2. Adjust the frame interval slider (default: every 5 seconds)
3. Click **Start Processing**
4. Watch Tab 1 — frames processed live with VLM captions
5. Switch to Tab 2 — view all triggered alerts with severity
6. Switch to Tab 3 — ask the agent natural language questions

### Option B — CLI Mode

Basic run
```
python3 main.py --video assets/input_video.mp4
```

Sample every 10 seconds instead of 5
```
python3 main.py --video assets/input_video.mp4 --interval 10
```
Clear all previous data and start fresh
```
python3 main.py --video assets/input_video.mp4 --fresh
```

### Running Tests

Run all 37 tests with verbose output
```
pytest tests/ -v
```
With coverage report
```
pip install pytest-cov
pytest tests/ -v --cov=src --cov-report=term-missing
```


---

## 🚨 Alert Rules

| Rule | Trigger Condition | Severity |
|---|---|---|
| **Loitering** | Person standing/loitering between 10 PM – 6 AM | HIGH |
| **After-hours gate access** | Any person near a gate between 10 PM – 6 AM | HIGH |
| **Restricted zone** | Activity in Garage or Back Perimeter at night | HIGH |
| **Repeated vehicle** | Same vehicle (color + model) seen 2+ times in one day | MEDIUM |
| **Suspicious activity** | VLM/parser flags the event as suspicious | MEDIUM |

---

## 🤖 Agent Capabilities

The security agent supports natural language queries using Groq tool calling with session memory. Example questions:

```
"What vehicles were detected today?"
"Were there any HIGH severity alerts?"
"Show me all events near the main gate"
"Was any vehicle seen more than once?"
"What happened after midnight?"
"Were there any suspicious activities at night?"
"Summarise today's security posture"
"What is your recommendation for tonight?"
```

The agent selects from 6 tools automatically:

| Tool | Purpose |
|---|---|
| `get_all_alerts` | Retrieve all triggered alerts |
| `get_events_by_object` | Filter events by person/vehicle + optional color |
| `get_events_by_zone` | Filter events by property zone |
| `get_session_summary` | Aggregate counts (vehicles, people, alerts) |
| `semantic_search` | Natural language search over ChromaDB frame index |
| `get_all_events` | Retrieve all logged events |

---


## 📋 Sample Output

```
============================================================
[Pipeline] Starting processing: assets/input_video.mp4
============================================================

[Frame 000] Main Gate | 2025-01-15 08:30:00
VLM Caption: A white SUV slowly entering through the main gate.
Driver briefly visible through windshield.
Parsed → type: vehicle | color: white | model: car | action: entering | suspicious: False

[Frame 003] Parking Lot | 2025-01-15 12:00:00
VLM Caption: A large brown delivery truck parked near the entrance.
Two workers unloading boxes onto a trolley.
Parsed → type: vehicle | color: brown | model: truck | action: parked | suspicious: False

[Frame 007] Main Gate | 2025-01-15 17:00:00
VLM Caption: The same white SUV re-entering through the main gate.
Parsed → type: vehicle | color: white | model: car | action: entering
🚨 [MEDIUM] REPEATED_VEHICLE: White car has entered 2 times today.

[Frame 012] Main Gate | 2025-01-16 00:01:00
VLM Caption: A person in dark clothing standing motionless near the gate,
repeatedly looking left and right.
Parsed → type: person | action: loitering | suspicious: True
🚨 [HIGH] LOITERING: Person loitering at Main Gate at 2025-01-16 00:01:00
🚨 [HIGH] UNAUTHORIZED_ACCESS: Person at Main Gate after hours.

============================================================
[Pipeline] ✅ Complete — 13 frames processed
Vehicles detected: 6
People detected: 7
Total alerts: 4 (2 HIGH, 2 MEDIUM)
============================================================

📋 DAILY SECURITY BRIEF:
Today's monitoring identified 6 vehicle entries and 7 person detections across
the property. A HIGH severity loitering incident occurred at the Main Gate at
midnight, and a white car triggered a repeated vehicle alert after entering twice.
Overall risk level is elevated for after-hours activity — recommend reviewing
gate access logs and increasing overnight patrol frequency.
```

