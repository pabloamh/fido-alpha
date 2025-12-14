"""
FIDO Data Models

This module contains the data classes that represent the core concepts
of FIDO's format identification logic, such as Signatures, Patterns, and
FileFormats.
"""
from dataclasses import dataclass, field
from typing import List, Optional, Set
import re


@dataclass
class Pattern:
    """Represents a single regex pattern within a signature."""
    position: str
    regex: re.Pattern
    pronom_pattern: str


@dataclass
class Signature:
    """Represents a signature for a file format."""
    name: str
    patterns: List[Pattern]
    note: Optional[str] = None


@dataclass
class FileFormat:
    """Represents a file format with its signatures and metadata."""
    puid: str
    name: str
    version: Optional[str] = None
    mime: Optional[str] = None
    signatures: List[Signature] = field(default_factory=list)
    extensions: List[str] = field(default_factory=list)
    has_priority_over: Set[str] = field(default_factory=set)
    container: Optional[str] = None