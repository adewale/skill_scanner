#!/usr/bin/env python3
"""YouTube Summary Skill – fetch a transcript for the current agent to summarise."""

import json
import re
import subprocess
import sys

from youtube_transcript_api import YouTubeTranscriptApi
from youtube_transcript_api._errors import RequestBlocked


def extract_video_id(url: str) -> str:
    """Return the YouTube video ID from a URL."""
    patterns = [
        r"(?:youtu\.be/)([A-Za-z0-9_-]{11})",
        r"(?:youtube\.com/watch\?v=)([A-Za-z0-9_-]{11})",
        r"(?:youtube\.com/embed/)([A-Za-z0-9_-]{11})",
        r"(?:youtube\.com/shorts/)([A-Za-z0-9_-]{11})",
    ]
    for pattern in patterns:
        match = re.search(pattern, url)
        if match:
            return match.group(1)
    raise ValueError(f"Could not extract video ID from URL: {url}")


def fetch_transcript(video_id: str) -> str:
    """Fetch and concatenate the transcript for a YouTube video.

    Tries the youtube-transcript-api first, then falls back to yt-dlp
    for subtitle extraction when requests are blocked (e.g. cloud IPs).
    """
    try:
        ytt_api = YouTubeTranscriptApi()
        transcript = ytt_api.fetch(video_id)
        return " ".join(snippet.text for snippet in transcript)
    except RequestBlocked:
        print("Direct transcript fetch blocked, trying yt-dlp…", file=sys.stderr)
        return _fetch_transcript_ytdlp(video_id)


def _fetch_transcript_ytdlp(video_id: str) -> str:
    """Fallback: use yt-dlp to dump subtitles as JSON."""
    url = f"https://www.youtube.com/watch?v={video_id}"
    result = subprocess.run(
        [
            "yt-dlp",
            "--write-auto-sub",
            "--sub-lang", "en",
            "--skip-download",
            "--sub-format", "json3",
            "--dump-json",
            url,
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"yt-dlp failed (exit {result.returncode}): {result.stderr}"
        )
    info = json.loads(result.stdout)
    subs = info.get("subtitles", {}).get("en") or info.get(
        "automatic_captions", {}
    ).get("en")
    if not subs:
        raise RuntimeError("No English subtitles found via yt-dlp")
    for fmt in subs:
        if fmt.get("ext") == "json3":
            sub_url = fmt["url"]
            import urllib.request  # noqa: E402

            with urllib.request.urlopen(sub_url) as resp:
                data = json.loads(resp.read())
            return " ".join(
                ev.get("segs", [{}])[0].get("utf8", "")
                for ev in data.get("events", [])
                if ev.get("segs")
            )
    raise RuntimeError("No json3 subtitle format available")


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python youtube_summary.py <YOUTUBE_URL>", file=sys.stderr)
        sys.exit(1)

    url = sys.argv[1]
    video_id = extract_video_id(url)
    print(f"Fetching transcript for video: {video_id}", file=sys.stderr)
    transcript = fetch_transcript(video_id)
    print(f"Transcript length: {len(transcript)} characters", file=sys.stderr)
    print(transcript)


if __name__ == "__main__":
    main()
