# Lessons Learned — Skill Scanner

This file records durable, project-specific lessons from testing the scanner's untrusted content
boundaries. Each lesson should identify the executable guard that prevents recurrence.

## 2026-08-31 — Hostile parsers need both totality and semantic generators

**Problem:** Random corrupt bytes are useful for finding crashes in the PNG, JPEG, GIF, WebP, and
ICO metadata extractors, but they almost never form a valid metadata record. A parser can therefore
pass a large arbitrary-byte campaign while corrupting or dropping every valid payload.

**Lesson:** Use two complementary generator layers at hostile parser boundaries: arbitrary corrupt
input for totality, truncation, and length handling; and structured-valid input with a known
semantic oracle for deep parser behavior.

**Rule:**
- Keep arbitrary Unicode/Markdown flowing through `SkillScanner.scan_content` and format-prefixed
  arbitrary bytes flowing through every supported image metadata extractor.
- Pair those totality checks with format-valid builders that assert the exact extracted metadata;
  `test_png_text_chunk_round_trips_to_scannable_text` is the first generated semantic oracle.
- Add a structured-valid oracle when expanding a metadata format, rather than treating a
  no-exception result on random bytes as proof that valid records are preserved.
- Keep `test_properties.py` in the normal pytest CI job so both layers are continuously collected
  and executed.
