import streamlit as st
import os
import shutil
import time
from src.pipeline import process_video, generate_daily_brief
from src.agent import build_agent, inject_frame_context
from src.database import get_all_alerts, get_all_events, init_db, get_daily_summary_data
from groq import Groq
from dotenv import load_dotenv


load_dotenv()

st.set_page_config(
    page_title="Drone Security Analyst",
    page_icon="🚁",
    layout="wide"
)

st.title("Drone Security Analyst Agent")
st.caption("Real-time drone monitoring powered by VLM + Groq")


if "pending_query" not in st.session_state:
    st.session_state.pending_query = None

if "agent" not in st.session_state:
    st.session_state.agent = build_agent()

if "pipeline_done" not in st.session_state:
    st.session_state.pipeline_done = False

if "pipeline_results" not in st.session_state:
    st.session_state.pipeline_results = []

if "chat_history" not in st.session_state:
    st.session_state.chat_history = []

if "daily_brief" not in st.session_state:
    st.session_state.daily_brief = None

if "security_report" not in st.session_state:
    st.session_state.security_report = None

init_db()


with st.sidebar:
    st.header("⚙️ Controls")

    uploaded_file = st.file_uploader(
        "Upload drone footage (.mp4)",
        type=["mp4", "avi", "mov"]
    )

    frame_interval = st.slider(
        "Extract 1 frame every N seconds",
        min_value=2,
        max_value=30,
        value=5,
        help="Lower = more frames = more API calls. 5s is a good balance."
    )

    run_pipeline = st.button(
        "▶️ Start Processing",
        disabled=uploaded_file is None,
        use_container_width=True
    )

    if st.session_state.pipeline_done:
        summary = get_daily_summary_data()
        st.divider()
        st.metric("Frames Processed", len(st.session_state.pipeline_results))
        st.metric("Total Alerts", summary["total_alerts"])
        col1, col2 = st.columns(2)
        col1.metric("🔴 HIGH", summary["high_alerts"])
        col2.metric("🟡 MEDIUM", summary["medium_alerts"])

   
    st.divider()
    if st.button("🗑️ Clear Session", use_container_width=True):
        # Wipe databases
        if os.path.exists("drone_security.db"):
            os.remove("drone_security.db")
        if os.path.exists("chroma_db"):
            shutil.rmtree("chroma_db")

        # Reset all session state
        st.session_state.pipeline_done = False
        st.session_state.pipeline_results = []
        st.session_state.chat_history = []
        st.session_state.daily_brief = None
        st.session_state.security_report = None
        st.session_state.pending_query = None
        st.session_state.agent = build_agent()

        init_db()
        st.success("Session cleared. Ready for new video.")
        st.rerun()



tab1, tab2, tab3 = st.tabs(["📹 Live Feed", "🚨 Alerts", "🤖 Agent Q&A"])



with tab1:
    if not st.session_state.pipeline_done and not run_pipeline:
        st.info("Upload a video file and click **Start Processing** to begin.")

    if run_pipeline and uploaded_file is not None:
        video_path = f"temp_{uploaded_file.name}"
        with open(video_path, "wb") as f:
            f.write(uploaded_file.getvalue())

        st.success(f"Video uploaded: {uploaded_file.name}")

        progress_bar = st.progress(0)
        status_text = st.empty()
        col_img, col_info = st.columns([1, 1])

        with col_img:
            frame_display = st.empty()

        with col_info:
            caption_display = st.empty()
            event_display = st.empty()
            alert_display = st.empty()

        def update_ui(frame_id, total, event, alerts, image_path, caption):
            progress = (frame_id + 1) / total
            progress_bar.progress(progress)
            status_text.text(f"Processing frame {frame_id + 1} of {total} — {event.zone} | {event.timestamp}")

            frame_display.image(image_path, caption=f"Frame {frame_id} — {event.zone}", use_column_width=True)

            caption_display.markdown(f"**🔍 VLM Caption:**\n\n_{caption}_")

            event_display.markdown(
                f"**📋 Parsed Event:**\n"
                f"- Type: `{event.object_type}`\n"
                f"- Color: `{event.color or 'N/A'}`\n"
                f"- Model: `{event.vehicle_model or 'N/A'}`\n"
                f"- Action: `{event.action or 'N/A'}`\n"
                f"- Suspicious: `{event.suspicious}`"
            )

            if alerts:
                for a in alerts:
                    msg = f"🚨 **[{a.severity}]** {a.alert_type.upper()}: {a.message}"
                    if a.severity == "HIGH":
                        alert_display.error(msg)
                    elif a.severity == "MEDIUM":
                        alert_display.warning(msg)
                    else:
                        alert_display.info(msg)
            else:
                alert_display.success("✅ No alerts for this frame")

            inject_frame_context(st.session_state.agent, event, alerts)

        with st.spinner("Running pipeline..."):
            results = process_video(
                video_path=video_path,
                every_n_seconds=frame_interval,
                delay_between_frames=0.3,
                progress_callback=update_ui
            )

        st.session_state.pipeline_results = results
        st.session_state.pipeline_done = True

        groq_client = Groq(api_key=os.getenv("GROQ_API_KEY"))
        st.session_state.daily_brief = generate_daily_brief(results, groq_client)

        os.remove(video_path)

        status_text.text("✅ Pipeline complete!")
        progress_bar.progress(1.0)

    if st.session_state.pipeline_done and st.session_state.daily_brief:
        st.divider()
        st.subheader("📋 Daily Security Brief")
        st.info(st.session_state.daily_brief)



with tab2:
    st.subheader("🚨 Security Alerts")

    if not st.session_state.pipeline_done:
        st.info("Run the pipeline first to see alerts.")
    else:
        alerts = get_all_alerts()

        if not alerts:
            st.success("✅ No alerts triggered during this session.")
        else:
            # Summary counts at the top
            high_count = sum(1 for r in alerts if r[3] == "HIGH")
            med_count  = sum(1 for r in alerts if r[3] == "MEDIUM")
            low_count  = sum(1 for r in alerts if r[3] == "LOW")

            c1, c2, c3 = st.columns(3)
            c1.metric("🔴 HIGH", high_count)
            c2.metric("🟡 MEDIUM", med_count)
            c3.metric("🟢 LOW", low_count)

            st.divider()

            for row in alerts:
                alert_id, timestamp, alert_type, severity, message, frame_id, zone = row

                content = (
                    f"**{alert_type.replace('_', ' ').title()}** — {zone}  \n"
                    f"🕐 {timestamp} &nbsp;|&nbsp; Frame `{frame_id}`  \n"
                    f"{message}"
                )

                if severity == "HIGH":
                    st.error(f"🔴 **HIGH** — {content}")
                elif severity == "MEDIUM":
                    st.warning(f"🟡 **MEDIUM** — {content}")
                else:
                    st.success(f"🟢 **LOW** — {content}")


# ── Tab 3: Agent Q&A ───────────────────────────────────────────────────────────
with tab3:
    st.subheader("🤖 Ask the Security Agent")

    if not st.session_state.pipeline_done:
        st.info("Run the pipeline first so the agent has data to answer questions about.")
    else:
        # ── Generate Security Report Button ────────────────────────────────────
        if st.button("📄 Generate Security Report", use_container_width=True):
            with st.spinner("Generating report..."):
                try:
                    report = st.session_state.agent.query(
                        "Generate a detailed security report for today. Include: "
                        "total vehicles and persons detected, all alerts with severity, "
                        "zones with most activity, and your security recommendation for tonight."
                    )
                    st.session_state.security_report = report
                except Exception as e:
                    st.session_state.security_report = f"Error generating report: {e}"

        if st.session_state.security_report:
            st.divider()
            st.subheader("📋 Security Report")
            st.info(st.session_state.security_report)
            st.divider()

        # ── Suggestion Buttons ─────────────────────────────────────────────────
        suggestions = [
            "What vehicles were detected today?",
            "Were there any HIGH severity alerts?",
            "Show all events near the main gate",
            "Was any vehicle seen more than once?",
            "Summarise what happened today",
            "Were there any suspicious activities at night?"
        ]

        cols = st.columns(3)
        for i, suggestion in enumerate(suggestions):
            if cols[i % 3].button(suggestion, key=f"sug_{i}"):
                st.session_state.pending_query = suggestion
                st.rerun()

        st.divider()

        # Display existing chat history
        for msg in st.session_state.chat_history:
            with st.chat_message(msg["role"]):
                st.write(msg["content"])

        user_input = st.chat_input("Ask anything about the drone session...")

        query_to_run = None
        if user_input:
            query_to_run = user_input
        elif st.session_state.pending_query:
            query_to_run = st.session_state.pending_query
            st.session_state.pending_query = None

        if query_to_run:
            st.session_state.chat_history.append({"role": "user", "content": query_to_run})

            with st.chat_message("user"):
                st.write(query_to_run)

            with st.chat_message("assistant"):
                with st.spinner("Thinking..."):
                    try:
                        answer = st.session_state.agent.query(query_to_run)
                    except Exception as e:
                        answer = f"Error: {e}"
                st.write(answer)
                st.session_state.chat_history.append({"role": "assistant", "content": answer})