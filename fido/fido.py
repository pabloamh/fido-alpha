"""
Format Identification for Digital Objects (FIDO).
 
FIDO is a command-line tool to identify the file formats of digital objects.
It is designed for simple integration into automated work-flows.
"""

from argparse import ArgumentParser, RawTextHelpFormatter
from contextlib import closing, suppress
import os
import zipfile
import re
import sys
import tarfile
from pathlib import Path
import tempfile
try:
    from time import perf_counter
except ImportError:
    from time import clock as perf_counter

from xml.etree import ElementTree as ET


from fido import __version__, CONFIG_DIR
from fido.config import DEFAULTS
from fido.package import OlePackage, ZipPackage, SignatureLoader, get_container_handler
from fido.versions import get_local_versions, sig_file_actions
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

    def match_container(self, signature_type, klass, file):
        """Return the signature matches for a container."""
        signatures = self.zip_signatures if signature_type == "ZIP" else self.ole_signatures
        puids = klass(file, signatures).detect_formats()
        results = []
        for puid in sorted(list(puids)):
            results.append((self.puid_format_map[puid], self.puid_format_map[puid].name))
        return results

    def has_priority_over(self, format, possibly_inferior):
        """Return true if format has priority over possibly inferior."""
        return possibly_inferior.puid in format.has_priority_over

    def get_puid(self, format_obj):
        """Return the PUID for the format."""
        return format_obj.puid

    def get_extension(self, format):
        """Return the extension for a format."""
        return format.extensions[0] if format.extensions else None

    def print_matches(self, fullname, matches, delta_t, matchtype=''):
        """
        The default match handler. Prints out information for each match in the list.

        @param fullname is name of the file being matched
        @param matches is a list of (format, signature)
        @param delta_t is the time taken for the match.
        @param matchtype is the type of match (signature, containersignature, extension, fail)
        """
        class Info:
            pass
        obj = Info()
        obj.count = self.current_count
        obj.group_size = len(matches)
        obj.filename = fullname
        obj.time = int(delta_t * 1000)
        obj.filesize = self.current_filesize
        obj.matchtype = matchtype
        if len(matches) == 0:
            sys.stdout.write(DEFAULTS['printnomatch'].format(info=obj))
        else:
            i = 0
            for (f, sig_name) in matches:
                i += 1
                obj.group_index = i
                obj.puid = f.puid
                obj.formatname = f.name
                obj.signaturename = sig_name
                obj.mimetype = f.mime
                obj.version = f.version
                # These attributes are not in the new model, so we set them to None
                obj.alias = None
                obj.apple_uti = None
                sys.stdout.write(DEFAULTS['printmatch'].format(info=obj))

    def identify_file(self, filename):
        """
        Identify the type of @param filename.

        Returns a list of match tuples.
        """
        with open(str(filename), 'rb') as f:
            size = os.fstat(f.fileno()).st_size
            bofbuffer, eofbuffer, _ = self.get_buffers(f, size, seekable=True)
        return self.match_formats(bofbuffer, eofbuffer)

    def identify_contents(self, filename, fileobj=None, container_type=None, extension=True):
        """
        Identify each item in a container (such as a zip or tar file).
        """
        handler = get_container_handler(self, container_type)
        if handler:
            handler.walk(filename, fileobj, extension)
        elif container_type:
            raise RuntimeError(f"Unknown container type: {container_type!r}")

    def process_stream(self, stream, filename, filesize, extension=True):
        """Helper to process a stream from a container or other source."""
        timer = PerfTimer()
        bofbuffer, eofbuffer, _ = self.get_buffers(stream, filesize)
        matches = self.match_formats(bofbuffer, eofbuffer)
        matchtype = "signature"

        if not matches and extension:
            matches = self.match_extensions(filename)
            matchtype = "extension"
        
        self.current_filesize = filesize
        self.print_matches(filename, matches, timer.duration(), matchtype)

        container_type = self.container_type(matches)
        if self.zip and self.can_recurse_into_container(container_type):
            # To properly recurse, we'd need to get a handle to the stream again
            # which is complex. This shows the structure for future implementation.
            return

    def identify_multi_object_stream(self, stream, extension=True):
        """
        Stream may contain one or more objects each with an HTTP style header
        that must include content-length. The headers consist of keyword:value
        pairs terminated by a newline. There must be a newline following the
        headers.
        Yields match results.
        """
        # This method is complex and seems designed for a very specific use case.
        # Refactoring it to be more generic would be a larger task.
        # For now, I'll leave it as is but note that it's not very OOP.
        # A better design would be to have a separate class for handling
        # such multi-object streams.

        offset = 0
        while True:
            # This is a bit of a hack to make the old printing mechanism work
            # with a generator. A proper refactor would change this.
            matches_list = []
            def handle_matches_capture(filename, matches, delta_t, matchtype=''):
                matches_list.append({'file': filename, 'matches': matches, 'duration': delta_t, 'matchtype': matchtype})

            timer = PerfTimer()
            content_length = -1
            for line in stream:
                offset += len(line)
                if line == '\n':
                    if content_length < 0:
                        raise EnvironmentError("No content-length provided.")
                    else:
                        break
                pair = line.lower().split(':', 2)
                if pair[0] == 'content-length':
                    content_length = int(pair[1])
            if content_length == -1:
                return
            # Consume exactly content-length bytes
            current_file = 'STDIN!(at ' + str(offset) + ' bytes)'
            current_filesize = content_length
            bofbuffer, eofbuffer, _ = self.get_buffers(stream, content_length)
            matches = self.match_formats(bofbuffer, eofbuffer)

            if len(matches) > 0:
                handle_matches_capture(current_file, matches, timer.duration(), "signature")
            elif extension:
                matches = self.match_extensions(current_file)
                handle_matches_capture(current_file, matches, timer.duration(), "extension")
            yield matches_list

    def identify_stream(self, stream, filename, extension=True):
        """
        Identify the type of @param stream.

        Call self.handle_matches instead of returning a value.
        Does not close stream.
        Returns a list of match tuples.
        """
        bofbuffer, eofbuffer, bytes_read = self.get_buffers(stream, length=None)
        matches = self.match_formats(bofbuffer, eofbuffer)
        if not matches and extension:
            if os.name != "nt":
                with suppress(OSError):
                    filename = os.readlink("/proc/self/fd/0")
            if filename:
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

    def can_recurse_into_container(self, container_type):
        """
        Return true if it is possible to recursively process this container.

        Determine if the passed container type can:
        a) be extracted, and
        b) contain individual files which can be identified separately.

        This function is useful for filtering out containers such as OLE,
        which are usually most interesting as compound objects rather than
        for their contents.
        """
        return container_type in ('zip', 'tar')

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
            f1_puid = self.get_puid(f1)
            for (f2, _) in match_list:
                if f1 == f2:
                    continue
                if f1_puid in self.puid_has_priority_over_map[self.get_puid(f2)]:
                    return False
        return True

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
        result = [match for match in result if self.as_good_as_any(match[0], result)]
        return result

    def copy_stream(self, source, target):
        """Copy the stream from source to target."""
        while True:
            buf = source.read(self.bufsize)
            if len(buf) == 0:
                break
            target.write(buf)


def list_files(roots, recurse=False):
    """Return the files one at a time. Roots could be a fileobj or a list."""
    for root_path in roots:
        root = Path(root_path.strip())
        if root.is_file():
            yield str(root)
        else:
            for p in root.rglob("*") if recurse else root.glob("*"):
                if p.is_file():
                    yield str(p)
                if not recurse:
                    break


def set_up_platform():
    """Enable Unicode display when running Python from Windows console."""
    # This function was primarily for Python 2 on Windows.
    # Python 3 handles Unicode in the console much better by default.
    pass


def identify_file(file_path, **kwargs):
    """
    Library function to identify a single file.

    :param file_path: Path to the file to identify.
    :param kwargs: Other FIDO options.
    :return: A list of matches.
    """
    fido = Fido(**kwargs)
    return fido.identify_file(str(file_path))

def print_summary(count, secs, quiet):
    """Print summary information on the number of matches and time taken."""
    if not quiet:
        rate = int(round(count / secs)) if secs != 0 else 9999
        print('FIDO: Processed %6d files in %6.2f msec, %2d files/sec' % (count, secs * 1000, rate), file=sys.stderr)


def main(args=None):
    """Main FIDO method."""
    # set_up_platform() # No longer needed in Python 3
    if not args:
        args = sys.argv[1:]

    parser = ArgumentParser(description=defaults['description'], epilog=defaults['epilog'], fromfile_prefix_chars='@', formatter_class=RawTextHelpFormatter)
    parser.add_argument('-v', default=False, action='store_true', help='show version information')
    parser.add_argument('-q', default=False, action='store_true', help='run (more) quietly')
    parser.add_argument('-recurse', default=False, action='store_true', help='recurse into subdirectories')
    parser.add_argument('-zip', default=False, action='store_true', help='recurse into zip and tar files')
    parser.add_argument('-noextension', default=False, action='store_true', help='disable extension matching, reduces number of matches but may reduce false positives')
    parser.add_argument('-nocontainer', default=False, action='store_true', help='disable deep scan of container documents, increases speed but may reduce accuracy with big files')
    parser.add_argument('-pronom_only', default=False, action='store_true', help='disables loading of format extensions file, only PRONOM signatures are loaded, may reduce accuracy of results')
 
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-input', default=False, help='file containing a list of files to check, one per line. - means stdin')
    group.add_argument('files', nargs='*', default=[], metavar='FILE', help='files to check. If the file is -, then read content from stdin. In this case, python must be invoked with -u or it may convert the line terminators.')

    parser.add_argument('-filename', default=None, help='filename if file contents passed through STDIN')
    parser.add_argument('-useformats', metavar='INCLUDEPUIDS', default=None, help='comma separated string of formats to use in identification')
    parser.add_argument('-nouseformats', metavar='EXCLUDEPUIDS', default=None, help='comma separated string of formats not to use in identification')
    parser.add_argument('-matchprintf', metavar='FORMATSTRING', default=None, help='format string (Python style) to use on match. See nomatchprintf, README.txt.')
    parser.add_argument('-nomatchprintf', metavar='FORMATSTRING', default=None, help='format string (Python style) to use if no match. See README.txt')
    parser.add_argument('-bufsize', type=int, default=None, help='size (in bytes) of the buffer to match against (default=' + str(defaults['bufsize']) + ' bytes)')
    parser.add_argument('-sigs', default=None, metavar='SIG_ACT', help='SIG_ACT "check" for new version\nSIG_ACT "update" to latest\nSIG_ACT "list" available versions\nSIG_ACT "n" use version n.')
    parser.add_argument('-container_bufsize', type=int, default=None, help='size (in bytes) of the buffer to match against (default=' + str(defaults['container_bufsize']) + ' bytes)')
    parser.add_argument('-loadformats', default=None, metavar='XML1,...,XMLn', help='comma separated string of XML format files to add.')
    parser.add_argument('-confdir', default=CONFIG_DIR, help='configuration directory to load_fido_xml, for example, the format specifications from.')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    args = parser.parse_args(args)

    timer = PerfTimer()

    versions = get_local_versions(args.confdir) # type: ignore

    DEFAULTS['xml_pronomSignature'] = versions.pronom_signature
    DEFAULTS['containersignature_file'] = versions.pronom_container_signature 
    DEFAULTS['xml_fidoExtensionSignature'] = versions.fido_extension_signature
    DEFAULTS['format_files'] = [Path(args.confdir) / DEFAULTS['xml_pronomSignature']]

    if args.pronom_only:
        versionHeader = "FIDO v{0} ({1}, {2})\n".format(__version__, DEFAULTS['xml_pronomSignature'], DEFAULTS['containersignature_file'])
    else:
        versionHeader = "FIDO v{0} ({1}, {2}, {3})\n".format(__version__, DEFAULTS['xml_pronomSignature'], DEFAULTS['containersignature_file'], DEFAULTS['xml_fidoExtensionSignature']) 
        DEFAULTS['format_files'].append(DEFAULTS['xml_fidoExtensionSignature'])

    if args.v or args.version:
        sys.stdout.write(versionHeader)
        sys.exit(0)

    if args.sigs:
        sig_file_actions(args.sigs.lower())
        sys.exit(0) 

    if args.matchprintf:
        args.matchprintf = args.matchprintf.replace(r"\n", "\n").replace(r"\t", "\t")
    if args.nomatchprintf:
        args.nomatchprintf = args.nomatchprintf.replace(r"\n", "\n").replace(r"\t", "\t")

    fido_instance = Fido(
        conf_dir=args.confdir,
        format_files=DEFAULTS['format_files'],
        containersignature_file=DEFAULTS['containersignature_file'])

    # TODO: Allow conf options to be dis-included
    if args.loadformats:
        for file in args.loadformats.split(','):
            fido_instance.puid_format_map.update(SignatureLoader(args.confdir, [file], None).load_signatures())

    # TODO: remove from maps
    if args.useformats:
        args.useformats = args.useformats.split(',')
        fido_instance.formats = [f for f in fido_instance.formats if f.puid in args.useformats]
    elif args.nouseformats:
        args.nouseformats = args.nouseformats.split(',')
        fido_instance.formats = [f for f in fido_instance.formats if f.puid not in args.nouseformats]

    fido_instance.handle_matches = handle_matches
    fido_instance.zip = args.zip
    fido_instance.nocontainer = args.nocontainer

    # Set up to use stdin, or open input files:
    if args.input == '-':
        args.files = sys.stdin
    elif args.input:
        args.files = open(args.input, 'r')

    # RUN
    try:
        if not args.q:
            sys.stderr.write(versionHeader)
            sys.stderr.flush()
        if not args.input and len(args.files) == 1 and args.files[0] == '-':
            if args.zip:
                raise RuntimeError("Multiple content read from stdin not yet supported.")
            else:
                matches, size = fido_instance.identify_stream(sys.stdin, args.filename, extension=not args.noextension)
                fido_instance.current_filesize = size
                fido_instance.print_matches(args.filename or 'STDIN', matches, timer.duration(), 'stream')
        else:
            for file in list_files(args.files, args.recurse):
                try:
                    matches = fido_instance.identify_file(file)
                    matchtype = "signature"
                    container_type = fido_instance.container_type(matches)

                    if not args.nocontainer and container_type in ("zip", "ole"):
                        if container_type == "zip":
                            container_matches = fido_instance.match_container("ZIP", ZipPackage, file)
                        else:
                            container_matches = fido_instance.match_container("OLE2", OlePackage, file)
                        if container_matches:
                            handle_matches(file, container_matches, timer.duration(), "container")
                            continue

                    if not matches and not args.noextension:
                        matches = fido_instance.match_extensions(file)
                        matchtype = "extension"

                    fido_instance.print_matches(file, matches, timer.duration(), matchtype)

                    if args.zip and fido_instance.can_recurse_into_container(container_type):
                        fido_instance.identify_contents(file, container_type=container_type, extension=not args.noextension)
                except (IOError, RuntimeError) as e:
                    sys.stderr.write("FIDO: Error processing {}: {}\n".format(file, e))
    except KeyboardInterrupt:
        sys.stdout.flush()
        sys.stderr.flush()
        sys.exit('FIDO: Interrupt while identifying file {0}'.format(fido_instance.current_file))

    if not args.q:
        sys.stdout.flush()
        print_summary(fido_instance.current_count, timer.duration(), args.q)
        sys.stderr.flush()


if __name__ == '__main__':
    main()
