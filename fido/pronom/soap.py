"""
FIDO: Format Identifier for Digital Objects.

Copyright 2010 The Open Preservation Foundation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

PRONOM format signatures SOAP calls.
"""
import logging

from defusedxml import ElementTree as DET
from typing import Dict, Tuple, Any
from ..config import PRONOM_DEFAULTS
from fido import __version__


class PronomServiceError(Exception):
    """Custom exception for PRONOM service errors."""

ENCODING = "utf-8"
XML_PROC = f'<?xml version="1.0" encoding="{ENCODING}"?>'
TNA_DOMAIN: str = "nationalarchives.gov.uk"
PRONOM_HOST = f"www.{TNA_DOMAIN}"
PRONOM_NS = f"http://pronom.{TNA_DOMAIN}"
SIG_NS = f"http://{PRONOM_HOST}/pronom/SignatureFile"

NS = {
    'soap': 'http://schemas.xmlsoap.org/soap/envelope/',
    'xsi': 'http://www.w3.org/2001/XMLSchema-instance',
    'xsd': 'http://www.w3.org/2001/XMLSchema',
    'pronom': PRONOM_NS,
    'sig': SIG_NS
}

HEADERS: Dict[str, str] = {
    "Host": PRONOM_HOST,
    "User-Agent": f"PRONOOM UTILS v{__version__} (OPF)",
    'Content-type': 'text/xml; charset="UTF-8"'
}

def _process_droid_signature_xml(xml: str) -> int:
    """Helper to parse DROID signature XML and count FileFormat elements."""
    root_ele = DET.fromstring(xml)
    return len(root_ele.findall('.//{http://www.nationalarchives.gov.uk/pronom/SignatureFile}FileFormat'))
