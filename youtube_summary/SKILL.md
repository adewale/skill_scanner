---
name: youtube-summary
description: Fetches a YouTube video transcript and summarises it using Claude
author: adewale
license: MIT
---

# YouTube Summary Skill

Summarise any YouTube video by extracting its transcript and generating
a concise summary with Claude.

## Usage

```bash
python youtube_summary.py <YOUTUBE_URL>
```

## Requirements

```bash
pip install youtube-transcript-api anthropic
```

## How It Works

1. Extracts the video ID from the provided YouTube URL.
2. Fetches the transcript using the `youtube-transcript-api` library.
3. Sends the transcript to Claude for summarisation.
4. Prints a structured summary to the console.
