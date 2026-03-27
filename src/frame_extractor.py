import cv2
import os
from datetime import datetime, timedelta


def get_video_creation_time(video_path: str) -> datetime:
    """
    Gets the video file's creation/modification time as the base timestamp.
    On Mac, st_birthtime is true creation time.
    Falls back to modification time on Linux.
    """
    stat = os.stat(video_path)
    try:
        # Mac has true creation time
        created = datetime.fromtimestamp(stat.st_birthtime)
    except AttributeError:
        # Linux fallback
        created = datetime.fromtimestamp(stat.st_mtime)
    return created


def extract_frames(
    video_path: str,
    every_n_seconds: int = 5,
    output_dir: str = "frames/"
) -> list[dict]:
    os.makedirs(output_dir, exist_ok=True)
    cap = cv2.VideoCapture(video_path)

    if not cap.isOpened():
        raise ValueError(f"Could not open video file: {video_path}")

    fps = cap.get(cv2.CAP_PROP_FPS)
    total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    duration_seconds = total_frames / fps if fps > 0 else 0
    interval = max(1, int(fps * every_n_seconds))

    # Get real base time from video file metadata
    video_base_time = get_video_creation_time(video_path)

    print(f"[Extractor] Video: {video_path}")
    print(f"[Extractor] FPS: {fps:.1f} | Duration: {duration_seconds:.1f}s")
    print(f"[Extractor] Base timestamp: {video_base_time.strftime('%Y-%m-%d %H:%M:%S')}")

    frame_count = 0
    saved_count = 0
    frame_paths = []

    while cap.isOpened():
        ret, frame = cap.read()
        if not ret:
            break

        if frame_count % interval == 0:
            # Get exact millisecond position of this frame in the video
            frame_ms = cap.get(cv2.CAP_PROP_POS_MSEC)

            # Real timestamp = video creation time + frame offset
            real_timestamp = video_base_time + timedelta(milliseconds=frame_ms)
            timestamp_str = real_timestamp.strftime("%Y-%m-%d %H:%M:%S")

            filename = f"frame_{saved_count:04d}.jpg"
            path = os.path.join(output_dir, filename)
            cv2.imwrite(path, frame)

            frame_paths.append({
                "frame_id": saved_count,
                "path": path,
                "timestamp": timestamp_str,          
                "video_offset_seconds": round(frame_ms / 1000, 2)
            })
            saved_count += 1

        frame_count += 1

    cap.release()
    print(f"[Extractor] Done — saved {saved_count} frames")
    return frame_paths