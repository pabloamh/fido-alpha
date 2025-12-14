import asyncio
import pytest
from fido.package import _parse_cue_sheet_async
from aiopath import AsyncPath
from tempfile import NamedTemporaryFile


@pytest.mark.asyncio
async def test_parse_cue_sheet_async():
    """Test the internal async CUE sheet parser."""
    cue_content = """
REM GENRE "Electronic"
REM DATE 1998
PERFORMER "Armin van Buuren"
TITLE "A State of Trance"
FILE "MyTranceAlbum.bin" BINARY
  TRACK 01 AUDIO
    TITLE "Track 1"
    PERFORMER "Armin van Buuren"
    INDEX 01 00:00:00
"""
    with NamedTemporaryFile(mode='w', delete=False, suffix=".cue", encoding='utf-8') as tmp_cue:
        tmp_cue.write(cue_content)
        tmp_cue_path = tmp_cue.name

    bin_filename = await _parse_cue_sheet_async(tmp_cue_path)
    assert bin_filename == "MyTranceAlbum.bin"