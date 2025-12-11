"""
Format Identification for Digital Objects (FIDO).

FIDO is a command-line tool to identify the file formats of digital objects.
It is designed for simple integration into automated work-flows.
"""

import os
import re
import sys
from pathlib import Path

try:
    from time import perf_counter
except ImportError:
    from time import clock as perf_counter

from xml.etree import ElementTree as ET

from fido import __version__, CONFIG_DIR
from fido.config import DEFAULTS
from fido.package import SignatureLoader
from fido.char_handler import escape


class PerfTimer:
    """A simple performance timer utility."""

    def __init__(self):
        """New instance with start time running."""
        self.start_time = perf_counter()

    def start(self):
        """Start new timer."""
        self.start_time = perf_counter()

    def duration(self):
        """Return the duration since instantiation or start() was last called."""
        return perf_counter() - self.start_time


class Fido:
    """Main FIDO application class."""

    def __init__(self, conf_dir=CONFIG_DIR, format_files=None, containersignature_file=None):
        """Initialise a FIDO class instance."""
        self.bufsize = DEFAULTS['bufsize']
        self.container_bufsize = DEFAULTS['container_bufsize']
        self.conf_dir = conf_dir
        format_files = format_files or DEFAULTS['format_files']
        containersignature_file = containersignature_file or DEFAULTS['containersignature_file']

        loader = SignatureLoader(conf_dir, format_files, containersignature_file)
        self.puid_format_map = loader.load_signatures()
        self.formats = loader.formats

        self.zip_signatures = None
        self.ole_signatures = None
        self.load_container_signatures(containersignature_file)
        self.containersignature_file = containersignature_file

        self.current_count = 0  # Count of calls to match_formats
        re._MAXCACHE = DEFAULTS['regexcachesize']
        self.externalsig = ET.XML('<signature><name>External</name></signature>')

    def load_container_signatures(self, containersignature_file):
        """Load container signatures."""
        container_file = Path(self.conf_dir).joinpath(self.containersignature_file)
        self.zip_signatures = self.extract_signatures(container_file, signature_type="ZIP")
        self.ole_signatures = self.extract_signatures(container_file, signature_type="OLE")

    def convert_container_sequence(self, sig):
        """Parse the PRONOM container sequences and convert to regular expressions."""
        # The sequence is regex matching bytes from a file so the sequence must also be bytes
        seq = b'(?s)'
        inq = False # type: ignore
        byt = False
        rng = False
        ror = False
        for i in range(len(sig)):
            if not inq and not rng:
                if sig[i] == "'":
                    inq = True
                    continue
                if sig[i] == " " or sig[i] == "\n":
                    continue
                if sig[i] == "[":
                    seq += b"("
                    rng = True
                    continue
                if not byt:
                    seq += b"\\x" + sig[i].lower().encode('utf8')
                    byt = True
                    continue
                if byt:
                    seq += sig[i].lower().encode('utf8')
                    byt = False
                    continue
            if inq:
                if sig[i] == "'" and not rng:
                    inq = False
                    continue
                seq += escape(sig[i]).encode('utf8')
                continue
            if rng:
                if sig[i] == "]":
                    seq += b")"
                    rng = False
                    continue
                if sig[i] != "-" and sig[i] != "'" and ror:
                    seq += escape(sig[i]).encode('utf8')
                    continue
                if sig[i] != "-" and sig[i] != "'" and sig[i] != " " and sig[i] != ":" and not ror and not byt:
                    seq += b"\\x" + sig[i].lower().encode('utf8')
                    byt = True
                    continue
                if sig[i] != "-" and sig[i] != "'" and sig[i] != " " and not ror and byt:
                    seq += sig[i].lower().encode('utf8')
                    byt = False
                    continue
                if sig[i] == "-" or sig[i] == " ":
                    seq += b"|"
                    continue
                if sig[i] == "'" and not ror:
                    ror = True
                    continue
                if sig[i] == "'" and ror:
                    ror = False
                    continue

        return seq

    def extract_signatures(self, doc, signature_type="ZIP"):
        """
        Given an XML container signature file, returns a dictionary of signatures.

        The format of the dictionary is:

        {
            "path_to_file_inside_zip": {"puid": [signatures]}
        }
        """
        root = ET.parse(doc).getroot()
        format_mappings = root.find("FileFormatMappings")

        def get_puid(doc, element_id):
            return format_mappings.find('FileFormatMapping[@signatureId="{}"]'.format(element_id)).attrib["Puid"]

        def format_signature_attributes(element):
            return {
                "path": element.findtext("Files/File/Path"),
                "id": element.attrib["Id"],
                "signature": self.convert_container_sequence(element.findtext("Files/File/BinarySignatures/InternalSignatureCollection/InternalSignature/ByteSequence/SubSequence/Sequence"))
            }

        elements = root.findall("ContainerSignatures/ContainerSignature[@ContainerType=\"{}\"]".format(signature_type))
        signatures = {}
        for el in elements:
            if el.find("Files/File/BinarySignatures") is None:
                continue

            puid = get_puid(doc, el.attrib["Id"])
            signature = format_signature_attributes(el)
            path = signature["path"]
            if path not in signatures:
                signatures[path] = {}
            if puid not in signatures[path]:
                signatures[path][puid] = []
            signatures[path][puid].append(format_signature_attributes(el))
        return signatures


    def get_puid(self, format_obj):
        """Return the PUID for the format."""
        return format_obj.puid

    def get_extension(self, format):
        """Return the extension for a format."""
        return format.extensions[0] if format.extensions else None

    def identify_file(self, filename):
        """
        Identify the type of @param filename.

        Returns a list of match tuples.
        """
        with open(str(filename), 'rb') as f:
            size = os.fstat(f.fileno()).st_size
            bofbuffer, eofbuffer, _ = self.get_buffers(f, size, seekable=True)
        return self.match_formats(bofbuffer, eofbuffer)

    def identify_stream(self, stream, filename, extension=True):
        """
        Identify the type of @param stream.

        Call self.handle_matches instead of returning a value.
        Does not close stream.
        Returns a list of match tuples.
        """
        bofbuffer, eofbuffer, bytes_read = self.get_buffers(stream, length=None)
        matches = self.match_formats(bofbuffer, eofbuffer)
        if not matches and extension and filename:
            matches = self.match_extensions(filename)

        return matches, bytes_read

    def container_type(self, matches):
        """
        Return true if this is a container type.

        Determine if one of the @param matches is the format of a container
        that we can look inside of (e.g., zip, tar).
        @return False, zip, or tar.
        """
        for (format_, _) in matches:
            container = format_.find('container')
            if container is not None:
                return container.text

            # aside from checking <container> elements,
            # check for fmt/111, which is OLE
            puid = format_.find('puid')
            if puid is not None and puid.text == 'fmt/111':
                return 'ole'
        return False

    def blocking_read(self, file, bytes_to_read):
        """Perform a blocking read and return the buffer."""
        bytes_read = 0
        buffer = b''
        while bytes_read < bytes_to_read:
            readbuffer = file.read(bytes_to_read - bytes_read)
            buffer += readbuffer
            bytes_read = len(buffer)
            # break out if EOF is reached.
            if readbuffer == '':
                break
        return buffer

    def get_buffers(self, stream, length=None, seekable=False):
        """
        Return buffers from the beginning and end of stream.

        Includes number of bytes read if there may be more bytes in the stream.

        If length is None, return the length as found.
        If seekable is False, the steam does not support a seek operation.
        """
        bytes_to_read = self.bufsize if length is None else min(length, self.bufsize)
        bofbuffer = self.blocking_read(stream, bytes_to_read)
        bytes_read = len(bofbuffer)
        if length is None:
            # A stream with unknown length; have to keep two buffers around
            prevbuffer = bofbuffer
            while True:
                buffer = self.blocking_read(stream, self.bufsize)
                bytes_read += len(buffer)
                if len(buffer) == self.bufsize:
                    prevbuffer = buffer
                else:
                    eofbuffer = prevbuffer if len(buffer) == 0 else prevbuffer[-(self.bufsize - len(buffer)):] + buffer
                    break
            return bofbuffer, eofbuffer, bytes_read
        bytes_unread = length - len(bofbuffer)
        if bytes_unread == 0:
            eofbuffer = bofbuffer
        elif bytes_unread < self.bufsize:
            # The buffs overlap
            eofbuffer = bofbuffer[bytes_unread:] + self.blocking_read(stream, bytes_unread)
        elif bytes_unread == self.bufsize:
            eofbuffer = self.blocking_read(stream, self.bufsize)
        elif seekable:  # easy case when we can just seek!
            stream.seek(length - self.bufsize)
            eofbuffer = self.blocking_read(stream, self.bufsize)
        else:
            # We have more to read and know how much.
            # n*bufsize + r = length
            (n, r) = divmod(bytes_unread, self.bufsize)
            # skip n-1*bufsize bytes
            for unused_i in range(1, n):
                self.blocking_read(stream, self.bufsize)
            # skip r bytes
            self.blocking_read(stream, r)
            # and read the remaining bufsize bytes into the eofbuffer
            eofbuffer = self.blocking_read(stream, self.bufsize)
        return bofbuffer, eofbuffer, bytes_to_read

    def as_good_as_any(self, f1, match_list):
        """
        Return True if the proposed format is as good as any in the match_list.

        For example, if there is no format in the match_list that has priority over the proposed one
        """
        if match_list != []:
            for (f2, _) in match_list:
                if f1 == f2:
                    continue
                if self.get_puid(f1) in f2.has_priority_over:
                    return False
        return True

    # This method is not used in the library and seems to be a remnant of a different design.
    def buffered_read(self, file_pos, overlap):
        """Buffered read of data chunks."""
        buf = ""
        if not overlap:
            bufsize = self.container_bufsize
        else:
            bufsize = self.container_bufsize + overlap
        file_end = self.current_filesize
        with open(self.current_file, 'rb') as file_handle:
            file_handle.seek(file_pos)
            if file_end - file_pos < bufsize:
                file_read = file_end - file_pos
            else:
                file_read = self.bufsize
            buf = file_handle.read(file_read)
        return buf

    def match_formats(self, bofbuffer, eofbuffer):
        """
        Apply the patterns for formats to the supplied buffers.

        @return a match list of (format, signature) tuples.
        The list has inferior matches removed.
        """
        self.current_count += 1
        result = []
        for format in self.formats:
            try:
                if self.as_good_as_any(format, result):
                    for sig in format.signatures:
                        success = True
                        for pat in sig.patterns:
                            pos = pat.position
                            regex = pat.regex
                            # print 'trying ', regex
                            if pos == 'BOF':
                                if not re.match(regex, bofbuffer):
                                    success = False
                                    break
                            elif pos == 'EOF':
                                if not re.search(regex, eofbuffer):
                                    success = False
                                    break
                            elif pos == 'VAR':
                                if not re.search(regex, bofbuffer):
                                    success = False
                                    break
                            elif pos == 'IFB':
                                if not re.search(regex, bofbuffer):
                                    success = False
                                    break
                        if success:
                            result.append((format, sig.name))
            except Exception as e:
                sys.stderr.write(str(e) + "\n")
                continue
            # TODO: MdR: needs some <3
            # print "Unexpected error:", sys.exc_info()[0], e
            # sys.stdout.write('***', self.get_puid(format), regex)

        result = [match for match in result if self.as_good_as_any(match[0], result)]
        return result

    def match_extensions(self, filename):
        """Return the list of (format, self.externalsig) for every format whose extension matches the filename."""
        myext = os.path.splitext(filename)[1].lower().lstrip(".")
        result = []
        if not myext:
            return result
        for file_format in self.formats:
            for extension in file_format.extensions:
                if myext == extension:
                    result.append((file_format, self.externalsig.findtext("name")))
                    break
        return result
