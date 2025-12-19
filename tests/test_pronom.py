import pytest
from unittest.mock import patch, MagicMock, AsyncMock

from fido.pronom.client import PronomClient


@pytest.fixture
def pronom_client():
    """Fixture for PronomClient."""
    return PronomClient()


@patch('requests.post')
def test_get_pronom_sig_version(mock_post, pronom_client):
    """Test synchronous fetching of PRONOM signature version."""
    mock_response = MagicMock()
    mock_response.text = """
    <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
      <soap:Body>
        <getSignatureFileVersionV1Response xmlns="http://pronom.nationalarchives.gov.uk">
          <Version>
            <Version>99</Version>
          </Version>
        </getSignatureFileVersionV1Response>
      </soap:Body>
    </soap:Envelope>
    """
    mock_response.raise_for_status.return_value = None
    mock_post.return_value = mock_response

    version = pronom_client.get_pronom_sig_version()
    assert version == 99


@pytest.mark.asyncio
async def test_get_pronom_sig_version_async(pronom_client):
    """Test asynchronous fetching of PRONOM signature version."""
    mock_response = AsyncMock()
    mock_response.text.return_value = """
    <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
      <soap:Body>
        <getSignatureFileVersionV1Response xmlns="http://pronom.nationalarchives.gov.uk">
          <Version>
            <Version>101</Version>
          </Version>
        </getSignatureFileVersionV1Response>
      </soap:Body>
    </soap:Envelope>
    """
    mock_response.raise_for_status.return_value = None

    # Mock the session and its post method
    mock_session = AsyncMock()
    mock_session.post.return_value.__aenter__.return_value = mock_response
    pronom_client._async_session = mock_session

    version = await pronom_client.get_pronom_sig_version_async()
    assert version == 101


@patch('requests.get')
def test_get_droid_signatures(mock_get, pronom_client):
    """Test synchronous fetching of DROID signatures."""
    mock_response = MagicMock()
    mock_response.text = """
    <SignatureFile xmlns="http://www.nationalarchives.gov.uk/pronom/SignatureFile">
        <FileFormatCollection>
            <FileFormat ID="1" Name="Test Format 1" PUID="fmt/1"/>
            <FileFormat ID="2" Name="Test Format 2" PUID="fmt/2"/>
        </FileFormatCollection>
    </SignatureFile>
    """
    mock_response.raise_for_status.return_value = None
    mock_get.return_value = mock_response

    xml, count = pronom_client.get_droid_signatures(99)
    assert count == 2
    assert 'fmt/1' in xml