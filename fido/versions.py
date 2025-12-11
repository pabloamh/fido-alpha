"""
PRONOM UTILS.

PYTHON FUNCTION TO QUERY PRONOM VERSION
AND DOWNLOAD SIGNATUREFILE
USES PRONOM SOAP SERVICE

Open Planets Foundation (http://www.openplanetsfoundation.org)
See License.txt for license information.
Download from: http://github.com/openplanets/fido/downloads
Author: Maurice de Rooij (OPF/NANETH), 2012

PRONOM UTILS is a library used by FIDO.
FIDO uses the UK National Archives (TNA) PRONOM File Format and Container descriptions.
PRONOM is available from http://www.nationalarchives.gov.uk/pronom/
"""

import importlib.resources as importlib_resources
from pathlib import Path
from xml.etree import ElementTree as ET

from fido import CONFIG_DIR


class LocalVersions(object):
    """
    Parse local versions XML file.

    This is what the XML document should look like:

    <?xml version="1.0" encoding="UTF-8"?>
    <versions>
        <pronomVersion>84</pronomVersion>
        <pronomSignature>formats-v84.xml</pronomSignature>
        <pronomContainerSignature>container-signature-20160121.xml</pronomContainerSignature>
        <fidoExtensionSignature>format_extensions.xml</fidoExtensionSignature>
        <updateScript>1.2.2</updateScript>
        <updateSite>https://fidosigs.openpreservation.org</updateSite>
    </versions>
    """

    PROPS_MAPPING = {
        'pronom_version': 'pronomVersion',
        'pronom_signature': 'pronomSignature',
        'pronom_container_signature': 'pronomContainerSignature',
        'fido_extension_signature': 'fidoExtensionSignature',
        'update_script': 'updateScript',
        'update_site': 'updateSite',
    }

    ROOT_ELEMENT = 'versions'

    def __init__(self, versions_file):
        """Instantiate class based on the file indicated in `versions_file`."""
        self.versions_file = versions_file
        self.conf_dir = Path(versions_file).parent.resolve()
        try:
            self.tree = ET.parse(versions_file)
            self.root = self.tree.getroot()
        except (ParseError, IOError):
            self.root = ET.Element(self.ROOT_ELEMENT)
            self.tree = ET.ElementTree(self.root)

    def __getattr__(self, name):
        """Extract the element's text content."""
        if name in self.PROPS_MAPPING:
            return self.root.find(self.PROPS_MAPPING[name]).text

    def __setattr__(self, name, value):
        """Update the element's text content."""
        if name in self.PROPS_MAPPING:
            try:
                self.root.find(self.PROPS_MAPPING[name]).text = value
            except AttributeError:
                elem = ET.SubElement(self.root, self.PROPS_MAPPING[name])
                elem.text = value
        else:
            object.__setattr__(self, name, value)

    def get_zip_file(self):
        """Obtain location to the PRONOM XML Zip file based on the current PRONOM version."""
        return self.conf_dir / 'pronom-xml-v{}.zip'.format(self.pronom_version)

    def get_signature_file(self):
        """Obtain location to the current PRONOM signature file."""
        return self.conf_dir / self.pronom_signature

    def write(self):
        """Update versions.xml."""
        # Check that all the fields are defined
        for key, value in self.PROPS_MAPPING.items():
            if self.root.find(value) is None:
                raise ValueError('Field {} has not been defined!'.format(key))
        self.tree.write(self.versions_file, xml_declaration=True, method='xml', encoding='utf-8')


def get_local_versions(config_dir=CONFIG_DIR):
    """Return an instance of LocalVersions loaded with `conf/versions.xml`."""
    return LocalVersions(str(Path(config_dir) / 'versions.xml'))
