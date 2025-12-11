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
import requests
import xml.etree.ElementTree as ET
from typing import Dict, Tuple, Any

from ..config import PRONOM_DEFAULTS
from fido import __version__


class PronomServiceError(Exception):
    """Custom exception for PRONOM service errors."""

ENCODING = 'utf-8'
XML_PROC = '<?xml version="1.0" encoding="{}"?>'.format(ENCODING)
TNA_DOMAIN: str = 'nationalarchives.gov.uk'
PRONOM_HOST = 'www.{}'.format(TNA_DOMAIN)
PRONOM_NS = 'http://pronom.{}'.format(TNA_DOMAIN)
SIG_NS = 'http://{}/pronom/SignatureFile'.format(PRONOM_HOST)

NS = {
    'soap': 'http://schemas.xmlsoap.org/soap/envelope/',
    'xsi': 'http://www.w3.org/2001/XMLSchema-instance',
    'xsd': 'http://www.w3.org/2001/XMLSchema',
    'pronom': PRONOM_NS,
    'sig': SIG_NS
}

HEADERS: Dict[str, str] = {
    'Host': PRONOM_HOST,
    'User-Agent': 'PRONOM UTILS v{0} (OPF)'.format(__version__),
    'Content-type': 'text/xml; charset="UTF-8"'
}


def get_pronom_sig_version() -> int:
    """
    Get PRONOM signature version.

    Return latest signature file version number as an int.
    Raises an HTTPError if there are problems.
    """
    tree: ET.Element = _get_soap_ele_tree('getSignatureFileVersionV1')
    ver_ele = tree.find('.//pronom:Version/pronom:Version', NS)
    return int(ver_ele.text)


def get_droid_signatures(version):
    """
    Get a DROID signature file by version.

    Return a tuple comprising the requested signature XML file as string
    and a count of the FileFormat elements contained as an integer.
    Upon error, write to `stderr` and return the tuple [], False.
    """
    xml: str = ""
    format_count = 0
    try:
        response = requests.get(PRONOM_DEFAULTS['droid_sig_url'].format(version=version))
        response.raise_for_status()
        xml = response.text
        root_ele = ET.fromstring(xml)
        format_count = len(root_ele.findall('.//{http://www.nationalarchives.gov.uk/pronom/SignatureFile}FileFormat'))
    except requests.exceptions.RequestException as httpe:
        logging.warning("get_droid_signatures(): could not download signature file v{version} due to exception: %s", httpe)
    return xml, format_count


def _get_soap_ele_tree(soap_action: str) -> ET.Element:
    soap_string = '{}<soap:Envelope xmlns:xsi="{}" xmlns:xsd="{}" xmlns:soap="{}"><soap:Body><{} xmlns="{}" /></soap:Body></soap:Envelope>'.format(XML_PROC, NS.get('xsi'), NS.get('xsd'), NS.get('soap'), soap_action, PRONOM_NS).encode(ENCODING)
    soap_action = '\"{}:{}In\"'.format(PRONOM_NS, soap_action)
    xml = _get_soap_response(soap_action, soap_string)
    for prefix, uri in NS.items():
        ET.register_namespace(prefix, uri)
    return ET.fromstring(xml)


def _get_soap_response(soap_action: str, soap_string: bytes) -> str:
    try:
        headers = HEADERS.copy()
        headers['SOAPAction'] = soap_action
        response = requests.post(
            PRONOM_DEFAULTS['pronom_service_url'],
            data=soap_string,
            headers=headers
        )
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        raise PronomServiceError(f"There was a problem contacting the PRONOM service: {e}") from e
