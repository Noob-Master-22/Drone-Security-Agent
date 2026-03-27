import argparse
from src.pipeline import process_video, generate_daily_brief
from src.agent import build_agent, inject_frame_context
from groq import Groq
from dotenv import load_dotenv
from src.indexer import make_chroma_client, index_event
import os


load_dotenv()


def main():
    parser = argparse.ArgumentParser(description="Drone Security Analyst Agent")
    parser.add_argument("--video", required=True, help="Path to input video file")
    parser.add_argument("--interval", type=int, default=5, help="Seconds between frame samples")
    args = parser.parse_args()

    if not os.path.exists(args.video):
        print(f"Error: Video file not found: {args.video}")
        return

    # Run the full pipeline
    results = process_video(
        video_path=args.video,
        every_n_seconds=args.interval
    )
    
    _, collection = make_chroma_client()
    for r in results:
        index_event(r["event"], collection)

    # Generate daily brief
    groq_client = Groq(api_key=os.getenv("GROQ_API_KEY"))
    brief = generate_daily_brief(results, groq_client)
    print(f"\n📋 DAILY SECURITY BRIEF:\n{brief}\n")

    # Interactive agent session in the terminal
    print("=" * 60)
    print("Agent is ready. Ask questions about the session (type 'exit' to quit).")
    print("=" * 60)

    agent = build_agent()

    # Inject all frame context into agent memory first
    for r in results:
        inject_frame_context(agent, r["event"], r["alerts"])

    while True:
        query = input("\nYou: ").strip()
        if query.lower() in ["exit", "quit", "q"]:
            break
        if not query:
            continue
        try:
            response = agent.query(query)
            print(f"\nAgent: {response}")
        except Exception as e:
            print(f"Error: {e}")


if __name__ == "__main__":
    main()