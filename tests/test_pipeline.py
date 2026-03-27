

import pytest
import os
import sys
import json
import sqlite3
from unittest.mock import patch, MagicMock
from datetime import datetime


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.models import FrameEvent, Alert
from src.alert_engine import (
    run_alert_rules,
    rule_loitering,
    rule_person_at_gate_after_hours,
    rule_repeated_vehicle,
    rule_restricted_zone,
    rule_suspicious_flag,
    _get_hour,
    _is_night
)


TEST_DB_PATH = "test_drone_security.db"


def use_test_db(monkeypatch):
    """
    Automatically redirects all DB operations to test DB for every test.
    Cleans up after each test so tests don't interfere with each other.
    """
    import src.database as db_module
    import src.alert_engine as alert_module

    monkeypatch.setattr(db_module, "DB_PATH", TEST_DB_PATH)
    monkeypatch.setattr(alert_module, "DB_PATH", TEST_DB_PATH) if hasattr(alert_module, "DB_PATH") else None

    # Initialize fresh test DB
    db_module.init_db()
    yield

    # Teardown — remove test DB after each test
    if os.path.exists(TEST_DB_PATH):
        os.remove(TEST_DB_PATH)


#
def make_vehicle_event(
    frame_id=1,
    timestamp="2025-01-15 08:30:00",
    zone="Main Gate",
    color="blue",
    vehicle_model="truck",
    action="entering",
    suspicious=False
) -> FrameEvent:
    return FrameEvent(
        frame_id=frame_id,
        timestamp=timestamp,
        zone=zone,
        raw_caption=f"{color} {vehicle_model} at {zone}",
        object_type="vehicle",
        color=color,
        vehicle_model=vehicle_model,
        action=action,
        person_count=0,
        suspicious=suspicious
    )


def make_person_event(
    frame_id=2,
    timestamp="2025-01-15 00:01:00",
    zone="Main Gate",
    action="loitering",
    suspicious=False,
    person_count=1
) -> FrameEvent:
    return FrameEvent(
        frame_id=frame_id,
        timestamp=timestamp,
        zone=zone,
        raw_caption=f"Person {action} at {zone}",
        object_type="person",
        color=None,
        vehicle_model=None,
        action=action,
        person_count=person_count,
        suspicious=suspicious
    )


# ══════════════════════════════════════════════════════════════════════════════
# 1. DATA MODEL TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestDataModels:
    """Tests that Pydantic models validate and store data correctly."""

    def test_frame_event_creates_correctly(self):
        """FrameEvent should store all fields accurately."""
        event = make_vehicle_event(
            frame_id=5,
            color="blue",
            vehicle_model="truck",
            zone="Garage"
        )
        assert event.frame_id == 5
        assert event.color == "blue"
        assert event.vehicle_model == "truck"
        assert event.zone == "Garage"
        assert event.object_type == "vehicle"
        assert event.suspicious is False

    def test_frame_event_defaults(self):
        """Optional fields should fall back to safe defaults."""
        event = FrameEvent(
            frame_id=1,
            timestamp="2025-01-15 08:00:00",
            zone="Main Gate",
            raw_caption="empty frame",
            object_type="unknown"
        )
        assert event.color is None
        assert event.vehicle_model is None
        assert event.person_count == 0
        assert event.suspicious is False

    def test_alert_creates_correctly(self):
        """Alert model should hold all required fields."""
        alert = Alert(
            timestamp="2025-01-15 00:01:00",
            alert_type="loitering",
            severity="HIGH",
            message="Person loitering at Main Gate",
            frame_id=3,
            zone="Main Gate"
        )
        assert alert.severity == "HIGH"
        assert alert.alert_type == "loitering"
        assert alert.frame_id == 3


# ══════════════════════════════════════════════════════════════════════════════
# 2. DATABASE TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestDatabase:
    """Tests that events and alerts are stored and retrieved correctly."""

    def test_event_inserted_and_retrieved(self):
        """An inserted event should be retrievable from the DB."""
        from src.database import insert_event, get_all_events

        event = make_vehicle_event(
            frame_id=1,
            color="blue",
            vehicle_model="truck",
            zone="Garage"
        )
        insert_event(event)
        rows = get_all_events()

        assert len(rows) == 1
        # row = (event_id, frame_id, timestamp, zone, object_type, color, vehicle_model...)
        assert rows[0][4] == "vehicle"   # object_type
        assert rows[0][5] == "blue"      # color
        assert rows[0][6] == "truck"     # vehicle_model

    def test_vehicle_logged_with_correct_details(self):
        """
        Assignment requirement: 'Blue Ford F150 spotted at garage, 12:00'
        Verify the DB stores this correctly.
        """
        from src.database import insert_event, get_events_by_object

        event = make_vehicle_event(
            frame_id=1,
            timestamp="2025-01-15 12:00:00",
            zone="Garage",
            color="blue",
            vehicle_model="truck"
        )
        insert_event(event)

        # Query by object type
        vehicles = get_events_by_object("vehicle")
        assert len(vehicles) == 1
        assert vehicles[0][5] == "blue"
        assert vehicles[0][3] == "Garage"

    def test_query_by_color_filter(self):
        """get_events_by_object with color filter should return only matching events."""
        from src.database import insert_event, get_events_by_object

        insert_event(make_vehicle_event(frame_id=1, color="blue", vehicle_model="truck"))
        insert_event(make_vehicle_event(frame_id=2, color="white", vehicle_model="car"))
        insert_event(make_vehicle_event(frame_id=3, color="blue", vehicle_model="van"))

        blue_vehicles = get_events_by_object("vehicle", color="blue")
        assert len(blue_vehicles) == 2

        white_vehicles = get_events_by_object("vehicle", color="white")
        assert len(white_vehicles) == 1

    def test_query_by_zone(self):
        """get_events_by_zone should return only events from that zone."""
        from src.database import insert_event, get_events_by_zone

        insert_event(make_vehicle_event(frame_id=1, zone="Main Gate"))
        insert_event(make_vehicle_event(frame_id=2, zone="Garage"))
        insert_event(make_vehicle_event(frame_id=3, zone="Main Gate"))

        gate_events = get_events_by_zone("Main Gate")
        assert len(gate_events) == 2

        garage_events = get_events_by_zone("Garage")
        assert len(garage_events) == 1

    def test_alert_inserted_and_retrieved(self):
        """An inserted alert should be retrievable from the DB."""
        from src.database import insert_alert, get_all_alerts

        alert = Alert(
            timestamp="2025-01-15 00:01:00",
            alert_type="loitering",
            severity="HIGH",
            message="Person loitering at Main Gate at 00:01",
            frame_id=1,
            zone="Main Gate"
        )
        insert_alert(alert)
        alerts = get_all_alerts()

        assert len(alerts) == 1
        # row = (alert_id, timestamp, alert_type, severity, message, frame_id, zone)
        assert alerts[0][2] == "loitering"
        assert alerts[0][3] == "HIGH"
        assert alerts[0][6] == "Main Gate"

    def test_multiple_events_stored_independently(self):
        """Multiple events should all be stored without overwriting each other."""
        from src.database import insert_event, get_all_events

        for i in range(5):
            insert_event(make_vehicle_event(frame_id=i))

        rows = get_all_events()
        assert len(rows) == 5

    def test_daily_summary_counts_correctly(self):
        """get_daily_summary_data should return correct aggregate counts."""
        from src.database import insert_event, insert_alert, get_daily_summary_data

        # Insert 2 vehicles, 3 people
        insert_event(make_vehicle_event(frame_id=1))
        insert_event(make_vehicle_event(frame_id=2))
        insert_event(make_person_event(frame_id=3))
        insert_event(make_person_event(frame_id=4))
        insert_event(make_person_event(frame_id=5))

        # Insert 1 HIGH + 1 MEDIUM alert
        insert_alert(Alert(
            timestamp="2025-01-15 00:01:00", alert_type="loitering",
            severity="HIGH", message="test", frame_id=3, zone="Main Gate"
        ))
        insert_alert(Alert(
            timestamp="2025-01-15 08:00:00", alert_type="suspicious_activity",
            severity="MEDIUM", message="test", frame_id=1, zone="Garage"
        ))

        summary = get_daily_summary_data()
        assert summary["vehicle_count"] == 2
        assert summary["person_count"] == 3
        assert summary["total_alerts"] == 2
        assert summary["high_alerts"] == 1
        assert summary["medium_alerts"] == 1


# ══════════════════════════════════════════════════════════════════════════════
# 3. ALERT ENGINE TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestAlertEngine:
    """Tests for each individual alert rule and the main run_alert_rules function."""

    # ── Utility tests ─────────────────────────────────────────────────────────

    def test_get_hour_parses_datetime_string(self):
        assert _get_hour("2025-01-15 08:30:00") == 8
        assert _get_hour("2025-01-15 00:01:00") == 0
        assert _get_hour("2025-01-15 23:59:00") == 23

    def test_get_hour_parses_time_only(self):
        assert _get_hour("14:30") == 14
        assert _get_hour("00:01") == 0

    def test_is_night_correctly_identifies_night_hours(self):
        assert _is_night(0) is True    # midnight
        assert _is_night(2) is True    # 2am
        assert _is_night(5) is True    # 5am
        assert _is_night(22) is True   # 10pm
        assert _is_night(23) is True   # 11pm
        assert _is_night(8) is False   # morning
        assert _is_night(14) is False  # afternoon

    # ── Rule: Loitering ───────────────────────────────────────────────────────

    def test_loitering_alert_triggered_at_midnight(self):
        """
        Assignment requirement: 'Person loitering at main gate, 00:01'
        This must trigger a HIGH alert.
        """
        event = make_person_event(
            timestamp="2025-01-15 00:01:00",
            zone="Main Gate",
            action="loitering"
        )
        alert = rule_loitering(event, hour=0)

        assert alert is not None
        assert alert.severity == "HIGH"
        assert alert.alert_type == "loitering"
        assert "Main Gate" in alert.message

    def test_loitering_not_triggered_during_daytime(self):
        """Loitering rule should NOT fire during business hours."""
        event = make_person_event(
            timestamp="2025-01-15 14:00:00",
            action="loitering"
        )
        alert = rule_loitering(event, hour=14)
        assert alert is None

    def test_loitering_not_triggered_for_vehicle(self):
        """Loitering rule should only apply to persons."""
        event = make_vehicle_event(
            timestamp="2025-01-15 00:01:00",
            action="parked"
        )
        alert = rule_loitering(event, hour=0)
        assert alert is None

    def test_loitering_not_triggered_for_walking_at_night(self):
        """Walking at night is suspicious but not 'loitering' — different rule."""
        event = make_person_event(
            timestamp="2025-01-15 00:01:00",
            action="walking"   # walking, not loitering
        )
        alert = rule_loitering(event, hour=0)
        assert alert is None

    # ── Rule: Person at gate after hours ──────────────────────────────────────

    def test_person_at_gate_after_hours_triggers(self):
        """Any person near a gate at night should trigger unauthorized access alert."""
        event = make_person_event(
            timestamp="2025-01-16 00:01:00",
            zone="Main Gate",
            action="walking"
        )
        alert = rule_person_at_gate_after_hours(event, hour=0)

        assert alert is not None
        assert alert.alert_type == "unauthorized_access"
        assert alert.severity == "HIGH"

    def test_person_at_gate_during_day_no_alert(self):
        """Person at gate during daytime is normal — no alert."""
        event = make_person_event(
            timestamp="2025-01-15 09:00:00",
            zone="Main Gate",
            action="walking"
        )
        alert = rule_person_at_gate_after_hours(event, hour=9)
        assert alert is None

    def test_person_not_at_gate_no_alert(self):
        """Person loitering in parking lot at night — different rule handles this."""
        event = make_person_event(
            timestamp="2025-01-16 00:01:00",
            zone="Parking Lot",  # not a gate
            action="loitering"
        )
        alert = rule_person_at_gate_after_hours(event, hour=0)
        assert alert is None

    # ── Rule: Repeated vehicle ────────────────────────────────────────────────

    def test_repeated_vehicle_alert_triggered_on_second_entry(self):
        """
        Assignment requirement: 'a blue Ford F150 entered twice today'
        Second entry of same vehicle must trigger MEDIUM alert.
        """
        from src.database import insert_event

        # Insert first entry into DB
        first_entry = make_vehicle_event(
            frame_id=1,
            timestamp="2025-01-15 08:30:00",
            color="blue",
            vehicle_model="truck",
            action="entering"
        )
        insert_event(first_entry)

        # Second entry of same vehicle — this should trigger the alert
        second_entry = make_vehicle_event(
            frame_id=2,
            timestamp="2025-01-15 17:00:00",
            color="blue",
            vehicle_model="truck",
            action="entering"
        )
        # Insert second entry too (pipeline inserts before checking)
        insert_event(second_entry)

        alert = rule_repeated_vehicle(second_entry)
        assert alert is not None
        assert alert.alert_type == "repeated_vehicle"
        assert alert.severity == "MEDIUM"
        assert "blue" in alert.message.lower()
        assert "truck" in alert.message.lower()

    def test_first_vehicle_entry_no_alert(self):
        """First time a vehicle appears — no repeated vehicle alert."""
        event = make_vehicle_event(
            frame_id=1,
            color="white",
            vehicle_model="car",
            action="entering"
        )
        # Don't insert to DB — first time seeing this vehicle
        alert = rule_repeated_vehicle(event)
        assert alert is None

    def test_different_vehicles_no_cross_alert(self):
        """Different vehicle colours should not trigger each other's repeated alert."""
        from src.database import insert_event

        # Blue truck enters
        insert_event(make_vehicle_event(
            frame_id=1, color="blue", vehicle_model="truck", action="entering"
        ))

        # White car enters — different vehicle, should not trigger repeated alert
        white_car = make_vehicle_event(
            frame_id=2, color="white", vehicle_model="car", action="entering"
        )
        insert_event(white_car)

        alert = rule_repeated_vehicle(white_car)
        assert alert is None

    # ── Rule: Restricted zone ─────────────────────────────────────────────────

    def test_restricted_zone_alert_at_night(self):
        """Activity in garage at night should trigger HIGH alert."""
        event = make_person_event(
            timestamp="2025-01-16 02:00:00",
            zone="Garage",
            action="walking"
        )
        alert = rule_restricted_zone(event, hour=2)

        assert alert is not None
        assert alert.severity == "HIGH"
        assert alert.alert_type == "restricted_zone"
        assert "Garage" in alert.message

    def test_restricted_zone_no_alert_during_day(self):
        """Garage access during business hours is normal."""
        event = make_vehicle_event(
            timestamp="2025-01-15 10:00:00",
            zone="Garage",
            action="entering"
        )
        alert = rule_restricted_zone(event, hour=10)
        assert alert is None

    def test_non_restricted_zone_no_alert(self):
        """Parking lot is not restricted — no alert even at night."""
        event = make_person_event(
            timestamp="2025-01-16 01:00:00",
            zone="Parking Lot",  # not in RESTRICTED_ZONES
            action="walking"
        )
        alert = rule_restricted_zone(event, hour=1)
        assert alert is None

    # ── Rule: Suspicious flag ─────────────────────────────────────────────────

    def test_suspicious_flag_triggers_alert(self):
        """If VLM/parser marks event as suspicious, alert should fire."""
        event = make_person_event(
            timestamp="2025-01-15 14:00:00",
            action="walking",
            suspicious=True   # VLM flagged this
        )
        alert = rule_suspicious_flag(event)

        assert alert is not None
        assert alert.alert_type == "suspicious_activity"
        assert alert.severity == "MEDIUM"

    def test_non_suspicious_event_no_alert(self):
        """Normal events should not trigger suspicious alert."""
        event = make_vehicle_event(suspicious=False)
        alert = rule_suspicious_flag(event)
        assert alert is None

    # ── Run all rules ─────────────────────────────────────────────────────────

    def test_multiple_rules_can_fire_simultaneously(self):
        """
        A single frame can trigger multiple alerts.
        Midnight loitering at gate = loitering + unauthorized_access both fire.
        """
        event = make_person_event(
            timestamp="2025-01-16 00:01:00",
            zone="Main Gate",
            action="loitering",
            suspicious=True   # also flagged suspicious
        )
        alerts = run_alert_rules(event)

        # Should get: loitering + unauthorized_access + suspicious_activity
        alert_types = [a.alert_type for a in alerts]
        assert "loitering" in alert_types
        assert "unauthorized_access" in alert_types
        assert "suspicious_activity" in alert_types
        assert len(alerts) >= 3

    def test_normal_daytime_event_no_alerts(self):
        """A normal daytime vehicle entry should produce zero alerts."""
        event = make_vehicle_event(
            timestamp="2025-01-15 09:00:00",
            zone="Main Gate",
            action="entering",
            suspicious=False
        )
        alerts = run_alert_rules(event)
        assert len(alerts) == 0


# ══════════════════════════════════════════════════════════════════════════════
# 4. PARSER TESTS (mocked — no actual API calls)
# ══════════════════════════════════════════════════════════════════════════════

class TestParser:
    """Tests for the LLM caption parser — mocked so no API calls are made."""

    @patch("src.parser.client")
    def test_parser_extracts_vehicle_correctly(self, mock_client):
        """Parser should correctly extract vehicle details from a caption."""
        from src.parser import parse_caption_to_event

        # Mock the Groq API response
        mock_response = MagicMock()
        mock_response.choices[0].message.content = json.dumps({
            "object_type": "vehicle",
            "color": "blue",
            "vehicle_model": "truck",
            "action": "entering",
            "person_count": 0,
            "suspicious": False
        })
        mock_client.chat.completions.create.return_value = mock_response

        event = parse_caption_to_event(
            caption="A blue truck is entering through the main gate",
            frame_id=1,
            timestamp="2025-01-15 08:30:00",
            zone="Main Gate"
        )

        assert event.object_type == "vehicle"
        assert event.color == "blue"
        assert event.vehicle_model == "truck"
        assert event.action == "entering"
        assert event.suspicious is False

    @patch("src.parser.client")
    def test_parser_extracts_person_correctly(self, mock_client):
        """Parser should correctly identify a person loitering."""
        from src.parser import parse_caption_to_event

        mock_response = MagicMock()
        mock_response.choices[0].message.content = json.dumps({
            "object_type": "person",
            "color": None,
            "vehicle_model": None,
            "action": "loitering",
            "person_count": 1,
            "suspicious": True
        })
        mock_client.chat.completions.create.return_value = mock_response

        event = parse_caption_to_event(
            caption="A person is loitering near the gate at midnight",
            frame_id=2,
            timestamp="2025-01-16 00:01:00",
            zone="Main Gate"
        )

        assert event.object_type == "person"
        assert event.action == "loitering"
        assert event.suspicious is True
        assert event.person_count == 1

    @patch("src.parser.client")
    def test_parser_handles_malformed_json_gracefully(self, mock_client):
        """If LLM returns bad JSON, parser should fall back to safe defaults."""
        from src.parser import parse_caption_to_event

        mock_response = MagicMock()
        # Simulate LLM returning garbage
        mock_response.choices[0].message.content = "Sorry I cannot help with that."
        mock_client.chat.completions.create.return_value = mock_response

        event = parse_caption_to_event(
            caption="something happened",
            frame_id=1,
            timestamp="2025-01-15 08:00:00",
            zone="Main Gate"
        )

        # Should not crash — should return safe defaults
        assert event.object_type == "unknown"
        assert event.suspicious is False
        assert event.frame_id == 1


# ══════════════════════════════════════════════════════════════════════════════
# 5. INDEXER TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestIndexer:
    """Tests for ChromaDB semantic indexing."""

    @pytest.fixture(autouse=True)
    def reset_chroma(self):
        """Create a fresh ChromaDB collection for each test."""
        import chromadb
        # Use in-memory client for tests — no disk writes
        test_client = chromadb.EphemeralClient()

        with patch("src.indexer.collection",
                   test_client.get_or_create_collection("test_frames")):
            with patch("src.indexer.chroma_client", test_client):
                yield

    def test_event_indexed_successfully(self):
        """An event should be findable after indexing."""
        from src.indexer import index_event, semantic_search

        event = make_vehicle_event(
            frame_id=1,
            zone="Main Gate",
            color="blue",
            vehicle_model="truck"
        )
        event = event.model_copy(update={
            "raw_caption": "A blue truck entering the main gate slowly"
        })

        index_event(event)
        results = semantic_search("blue truck at gate", n_results=1)

        assert len(results) >= 1
        assert "blue" in results[0]["caption"].lower() or "truck" in results[0]["caption"].lower()

    def test_semantic_search_returns_relevant_results(self):
        """Semantic search should return the most relevant frames for a query."""
        from src.indexer import index_event, semantic_search

        # Index a truck event and a person event
        truck_event = make_vehicle_event(frame_id=1)
        truck_event = truck_event.model_copy(update={
            "raw_caption": "Blue truck entering main gate"
        })

        person_event = make_person_event(frame_id=2)
        person_event = person_event.model_copy(update={
            "raw_caption": "Person standing near fence at night"
        })

        index_event(truck_event)
        index_event(person_event)

        # Search for person — should return person event as top result
        results = semantic_search("person standing at fence", n_results=2)
        assert len(results) > 0


# ══════════════════════════════════════════════════════════════════════════════
# 6. END-TO-END INTEGRATION TEST
# ══════════════════════════════════════════════════════════════════════════════

class TestIntegration:
    """
    End-to-end test of the full pipeline without external API calls.
    Mocks VLM and LLM calls so we can test the full flow deterministically.
    """

    @patch("src.vlm_captioner.client")
    @patch("src.parser.client")
    def test_full_pipeline_single_frame(self, mock_parser_client, mock_vlm_client):
        """
        Simulates processing one frame end-to-end:
        VLM caption → parse → store → alert check
        All external calls are mocked.
        """
        from src.vlm_captioner import caption_frame
        from src.parser import parse_caption_to_event
        from src.database import insert_event, insert_alert, get_all_events, get_all_alerts

        # Mock VLM response
        vlm_response = MagicMock()
        vlm_response.choices[0].message.content = "A blue Ford truck entering through the main gate at 8:30 AM."
        mock_vlm_client.chat.completions.create.return_value = vlm_response

        # Mock parser response
        parser_response = MagicMock()
        parser_response.choices[0].message.content = json.dumps({
            "object_type": "vehicle",
            "color": "blue",
            "vehicle_model": "truck",
            "action": "entering",
            "person_count": 0,
            "suspicious": False
        })
        mock_parser_client.chat.completions.create.return_value = parser_response

        # Run the pipeline steps manually
        # (We skip frame extraction since we don't have a real video in tests)
        caption = "A blue Ford truck entering through the main gate at 8:30 AM."
        event = parse_caption_to_event(caption, 1, "2025-01-15 08:30:00", "Main Gate")
        insert_event(event)
        alerts = run_alert_rules(event)
        for alert in alerts:
            insert_alert(alert)

        # Verify event was stored correctly
        events = get_all_events()
        assert len(events) == 1
        assert events[0][5] == "blue"      # color
        assert events[0][6] == "truck"     # vehicle_model
        assert events[0][3] == "Main Gate" # zone

        # Daytime vehicle entry — should not trigger any alerts
        stored_alerts = get_all_alerts()
        assert len(stored_alerts) == 0

    @patch("src.vlm_captioner.client")
    @patch("src.parser.client")
    def test_midnight_loitering_triggers_high_alert(self, mock_parser_client, mock_vlm_client):
        """
        Full flow for the most important assignment scenario:
        Person loitering at main gate at midnight → HIGH alert.
        """
        from src.parser import parse_caption_to_event
        from src.database import insert_event, insert_alert, get_all_alerts

        mock_response = MagicMock()
        mock_response.choices[0].message.content = json.dumps({
            "object_type": "person",
            "color": None,
            "vehicle_model": None,
            "action": "loitering",
            "person_count": 1,
            "suspicious": True
        })
        mock_parser_client.chat.completions.create.return_value = mock_response

        event = parse_caption_to_event(
            "Person loitering near main gate at midnight",
            frame_id=1,
            timestamp="2025-01-16 00:01:00",
            zone="Main Gate"
        )
        insert_event(event)
        alerts = run_alert_rules(event)
        for alert in alerts:
            insert_alert(alert)

        stored_alerts = get_all_alerts()
        high_alerts = [a for a in stored_alerts if a[3] == "HIGH"]

        assert len(high_alerts) >= 1
        assert any(a[2] == "loitering" for a in high_alerts)