---
name: youtube-summary
description: Fetches a YouTube video transcript and summarises it
author: adewale
license: MIT
---

# YouTube Summary Skill

Summarise any YouTube video by fetching its transcript.

## Usage

Run the transcript fetcher, passing the YouTube URL as the argument:

```bash
python youtube_summary/youtube_summary.py <YOUTUBE_URL>
```

## Requirements

```bash
pip install youtube-transcript-api
```

## Instructions

After fetching the transcript, summarise it following these rules:

1. If the video title is a question, **answer that question in the first line** of your summary.
2. If the video title implies a list of N things (e.g. "5 Tips for …", "Top 10 …"), **structure the summary as a list of exactly N items**.
3. Otherwise, provide a brief overview followed by key points as a bulleted list.
