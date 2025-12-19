import asyncio
import os
import zipfile
import tarfile
import gzip
import bz2
import pytest
from fido.package import _parse_cue_sheet_async, ZipPackage, TarPackage, GzipPackage, Bzip2Package
from aiopath import AsyncPath
from tempfile import NamedTemporaryFile, TemporaryDirectory


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


@pytest.mark.asyncio
async def test_zip_package_walk_async():
    """Test the async walk method for ZipPackage."""
    with TemporaryDirectory() as tmpdir:
        zip_path = os.path.join(tmpdir, "test.zip")
        with zipfile.ZipFile(zip_path, 'w') as zf:
            zf.writestr("file1.txt", b"content1")
            zf.writestr("file2.txt", b"content2")

        package = ZipPackage(zip_path)
        members = [member async for member in package.walk()]

        assert len(members) == 2
        names = sorted([m[0] for m in members])
        assert names == ["file1.txt", "file2.txt"]


@pytest.mark.asyncio
async def test_tar_package_walk_async():
    """Test the async walk method for TarPackage."""
    with TemporaryDirectory() as tmpdir:
        tar_path = os.path.join(tmpdir, "test.tar")
        with tarfile.open(tar_path, 'w') as tf:
            # Create and add a file
            with open(os.path.join(tmpdir, "file1.txt"), "wb") as f:
                f.write(b"content1")
            tf.add(os.path.join(tmpdir, "file1.txt"), arcname="file1.txt")

        package = TarPackage(tar_path)
        members = [member async for member in package.walk()]

        assert len(members) == 1
        assert members[0][0] == "file1.txt"
        content = members[0][1].read()
        assert content == b"content1"


@pytest.mark.asyncio
async def test_gzip_package_walk_async():
    """Test the async walk method for GzipPackage."""
    with TemporaryDirectory() as tmpdir:
        gz_path = os.path.join(tmpdir, "test.txt.gz")
        with gzip.open(gz_path, 'wb') as gf:
            gf.write(b"gzipped content")

        package = GzipPackage(gz_path)
        members = [member async for member in package.walk()]

        assert len(members) == 1
        # The name is derived from the filename without the .gz extension
        assert members[0][0] == "test.txt"
        content = members[0][1].read()
        assert content == b"gzipped content"


@pytest.mark.asyncio
async def test_bzip2_package_walk_async():
    """Test the async walk method for Bzip2Package."""
    with TemporaryDirectory() as tmpdir:
        bz2_path = os.path.join(tmpdir, "test.txt.bz2")
        with bz2.open(bz2_path, 'wb') as bf:
            bf.write(b"bzipped content")

        package = Bzip2Package(bz2_path)
        members = [member async for member in package.walk()]

        assert len(members) == 1
        # The name is derived from the filename without the .bz2 extension
        assert members[0][0] == "test.txt"
        content = members[0][1].read()
        assert content == b"bzipped content"