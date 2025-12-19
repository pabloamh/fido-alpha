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
"""
import requests
from .soap import PronomServiceError


class PronomClient:
    """A client for the PRONOM SOAP web service."""

    def __init__(self, url="http://www.nationalarchives.gov.uk/pronom/service.asmx"):
        """
        Initialize the PRONOM client.
        @param url: The URL of the PRONOM SOAP service.
        """
        self.url = url

    def get_signature_file_url(self) -> str:
        """
        Get the URL of the latest signature file from the PRONOM service.
        @return: The URL of the signature file.
        """
        headers = {"Content-Type": "text/xml; charset=utf-8"}
        body = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <getSignatureFileVersionV1 xmlns="http://pronom.nationalarchives.gov.uk" />
  </soap:Body>
</soap:Envelope>"""

        try:
            response = requests.post(self.url, data=body, headers=headers)
            response.raise_for_status()  # Raise an exception for bad status codes

            # Basic XML parsing without heavy dependencies
            content = response.text
            if "<Path>" in content and "</Path>" in content:
                start = content.find("<Path>") + len("<Path>")
                end = content.find("</Path>")
                return content[start:end]
            else:
                raise PronomServiceError("Could not find Path in PRONOM response.")

        except requests.RequestException as e:
            raise PronomServiceError(f"PRONOM service request failed: {e}")

    def get_signature_file(self) -> bytes:
        """Download the latest signature file."""
        url = self.get_signature_file_url()
        response = requests.get(url)
        response.raise_for_status()
        return response.content