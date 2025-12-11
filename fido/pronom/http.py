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

PRONOM format signatures HTTP calls.
"""
import requests
import asyncio
import aiohttp
from ..config import PRONOM_DEFAULTS


def get_sig_xml_for_puid(puid: str) -> bytes:
    """Return the full PRONOM signature XML for the passed PUID."""
    response = requests.get(PRONOM_DEFAULTS['pronom_url'].format(puid=puid))
    response.raise_for_status()
    return response.content


async def get_sig_xml_for_puid_async(session: aiohttp.ClientSession, puid: str) -> bytes:
    """Asynchronously return the full PRONOM signature XML for the passed PUID."""
    url = PRONOM_DEFAULTS['pronom_url'].format(puid=puid)
    async with session.get(url) as response:
        response.raise_for_status()
        return await response.read()
