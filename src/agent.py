import os
import json
from groq import Groq
from dotenv import load_dotenv
from src.database import (
    get_all_alerts, get_all_events,
    get_events_by_object, get_events_by_zone,
    get_daily_summary_data
)
from src.indexer import semantic_search
from groq import BadRequestError

load_dotenv()
client = Groq(api_key=os.getenv("GROQ_API_KEY"))
MODEL = "llama-3.3-70b-versatile"


TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "get_all_alerts",
            "description": "Get all security alerts from this session.",
            "parameters": {"type": "object", "properties": {}, "required": []}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_events_by_object",
            "description": "Get events by object type. Use for questions about vehicles or people.",
            "parameters": {
                "type": "object",
                "properties": {
                    "object_type": {
                        "type": "string",
                        "enum": ["vehicle", "person", "unknown"]
                    },
                    "color": {"type": "string"}
                },
                "required": ["object_type"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_events_by_zone",
            "description": "Get events from a specific zone like Main Gate, Garage, Parking Lot.",
            "parameters": {
                "type": "object",
                "properties": {
                    "zone": {"type": "string"}
                },
                "required": ["zone"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_session_summary",
            "description": "Get total counts of vehicles, people, and alerts.",
            "parameters": {"type": "object", "properties": {}, "required": []}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "semantic_search",
            "description": "Search frame descriptions by natural language.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"}
                },
                "required": ["query"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_all_events",
            "description": "Get all events from the session.",
            "parameters": {"type": "object", "properties": {}, "required": []}
        }
    }
]


def execute_tool(tool_name: str, tool_args: dict) -> str:
 
    if tool_args is None:
        tool_args = {}
    try:
        if tool_name == "get_all_alerts":
            rows = get_all_alerts()
            if not rows:
                return "No alerts have been triggered in this session."
            lines = []
            for row in rows:
                # (alert_id, timestamp, alert_type, severity, message, frame_id, zone)
                lines.append(f"[{row[3]}] {row[2].upper()} at {row[1]} | Zone: {row[6]}\n  → {row[4]}")
            return "\n\n".join(lines)

        elif tool_name == "get_events_by_object":
            rows = get_events_by_object(
                tool_args.get("object_type"),
                tool_args.get("color")
            )
            if not rows:
                return f"No {tool_args.get('object_type')} events found."
            lines = []
            for row in rows:
                # (event_id, frame_id, timestamp, zone, object_type, color, vehicle_model, action, person_count, suspicious, raw_caption)
                lines.append(
                    f"Frame {row[1]} | {row[2]} | {row[3]}\n"
                    f"  {row[4]} — {row[5] or ''} {row[6] or ''} | action: {row[7] or 'unknown'}"
                )
            return f"Found {len(rows)} event(s):\n\n" + "\n\n".join(lines)

        elif tool_name == "get_events_by_zone":
            rows = get_events_by_zone(tool_args.get("zone", ""))
            if not rows:
                return f"No events found in zone: {tool_args.get('zone')}"
            lines = []
            for row in rows:
                lines.append(
                    f"Frame {row[1]} | {row[2]} | {row[3]}\n"
                    f"  {row[4]} — {row[5] or ''} {row[6] or ''} | action: {row[7] or 'unknown'}"
                )
            return f"Found {len(rows)} event(s) in {tool_args.get('zone')}:\n\n" + "\n\n".join(lines)

        elif tool_name == "get_session_summary":
            data = get_daily_summary_data()
            return (
                f"Session Summary:\n"
                f"  Vehicles detected: {data['vehicle_count']}\n"
                f"  People detected:   {data['person_count']}\n"
                f"  Total alerts:      {data['total_alerts']}\n"
                f"  HIGH alerts:       {data['high_alerts']}\n"
                f"  MEDIUM alerts:     {data['medium_alerts']}"
            )

        elif tool_name == "semantic_search":
            results = semantic_search(tool_args.get("query", ""), n_results=5)
            if not results:
                return "No matching frames found."
            lines = []
            for r in results:
                lines.append(
                    f"Frame {r['frame_id']} | {r['timestamp']} | {r['zone']}\n"
                    f"  Caption: {r['caption']}\n"
                    f"  Relevance: {r['similarity']}"
                )
            return "\n\n".join(lines)

        elif tool_name == "get_all_events":
            rows = get_all_events()
            if not rows:
                return "No events recorded yet."
            lines = []
            for row in rows[:20]:  # cap at 20 to avoid token overflow
                lines.append(
                    f"Frame {row[1]} | {row[2]} | {row[3]} | {row[4]} "
                    f"{row[5] or ''} {row[6] or ''} | {row[7] or ''}"
                )
            return f"Total events: {len(rows)} (showing first 20):\n\n" + "\n".join(lines)

        else:
            return f"Unknown tool: {tool_name}"

    except Exception as e:
        return f"Tool execution error: {e}"


class DroneSecurityAgent:
    
   # A stateful agent that maintains conversation history across queries.
  

    def __init__(self):
        # Conversation history — grows as the session progresses
        
        self.messages = [
            {
                "role": "system",
                "content": (
                    "You are a Drone Security Analyst AI. You monitor a property "
                    "using drone camera footage and answer questions about security events.\n\n"
                    "You have tools to query the event database, search frames semantically, "
                    "and retrieve alerts. Always be factual, concise, and security-focused.\n"
                    "Include timestamps and zones in your answers. "
                    "Recommend actions for HIGH severity alerts."
                )
            }
        ]

    def inject_frame_context(self, event, alerts: list) -> None:
        
        note = f"[Observation] Frame {event.frame_id} | {event.timestamp} | {event.zone}: "

        if event.object_type == "vehicle" and event.color and event.vehicle_model:
            note += f"{event.color} {event.vehicle_model} — {event.action or 'detected'}."
        elif event.object_type == "person":
            note += f"{event.person_count} person(s) — {event.action or 'detected'}."
        else:
            note += f"{event.object_type} — {event.action or 'detected'}."

        if alerts:
            note += " ⚠️ Alerts: " + ", ".join(f"[{a.severity}] {a.alert_type}" for a in alerts)

        # Inject as a system message so it's part of context but not a user turn
        self.messages.append({"role": "system", "content": note})

    def query(self, user_input: str) -> str:
        self.messages.append({"role": "user", "content": user_input})

   
   
        max_attempts = 3
        attempt = 0

        while attempt < max_attempts:
            attempt += 1
            try:
                response = client.chat.completions.create(
                    model=MODEL,
                    messages=self.messages,
                    tools=TOOLS,
                    tool_choice="auto",
                    temperature=0.1,
                    max_tokens=1000
                )

                message = response.choices[0].message
                finish_reason = response.choices[0].finish_reason

            # No tool call — LLM gave a direct answer
                if finish_reason == "stop" or not message.tool_calls:
                    answer = message.content or "No information available."
                    self.messages.append({"role": "assistant", "content": answer})
                    return answer

            # Process tool calls
                self.messages.append(message)
                all_tools_succeeded = True

                for tool_call in message.tool_calls:
                    tool_name = tool_call.function.name

                    try:
                        raw_args = tool_call.function.arguments
                        if not raw_args or raw_args.strip() in ["", "null", "None"]:
                            tool_args = {}
                        else:
                            tool_args = json.loads(raw_args)
                    except (json.JSONDecodeError, TypeError):
                        tool_args = {}

                    print(f"  [Agent] Calling tool: {tool_name}({tool_args})")
                    result = execute_tool(tool_name, tool_args)

                    self.messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": str(result)
                        })

            except Exception as e:
                error_str = str(e)
                print(f"  [Agent] Attempt {attempt} failed: {error_str}")

            
                if "tool_use_failed" in error_str or "Failed to call a function" in error_str:
                    print(f"  [Agent] Tool call malformed — switching to direct answer mode")
                    break  

            # For other errors, retry
                if attempt >= max_attempts:
                    break

    # ── Fallback — answer directly without any tools ──────────────────────
    # Remove any failed tool messages from history before retry
        clean_messages = [
            m for m in self.messages
            if not (isinstance(m, dict) and m.get("role") == "tool")
            and not (hasattr(m, "tool_calls") and m.tool_calls)
        ]

    
        clean_messages.append({
            "role": "user",
            "content": (
                f"{user_input}\n\n"
                f"(Answer based on what you know from the session context. "
                f"Do not use any tools.)"
            )
        })

        try:
            fallback_response = client.chat.completions.create(
                model=MODEL,
                messages=clean_messages,
                temperature=0.1,
                max_tokens=500
                # No tools parameter — forces plain text answer
            )
            answer = fallback_response.choices[0].message.content or "I couldn't find that information."
            self.messages.append({"role": "assistant", "content": answer})
            return answer

        except Exception as e:
            return f"I encountered an error: {e}. Please try rephrasing your question."




def build_agent() -> DroneSecurityAgent:
    """Creates and returns a fresh DroneSecurityAgent instance."""
    return DroneSecurityAgent()


def inject_frame_context(agent: DroneSecurityAgent, event, alerts: list) -> None:
    
    agent.inject_frame_context(event, alerts)