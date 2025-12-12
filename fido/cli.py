"""
FIDO Command-Line Interface

This module contains the command-line entry point for FIDO and all
related user interface functions.
"""
from argparse import ArgumentParser, RawTextHelpFormatter
import asyncio
import sys
from pathlib import Path
import logging

from .fido import Fido
from . import __version__
from .config import DEFAULTS
from .package import ZipPackage, OlePackage, SignatureLoader
from .versions import get_local_versions
from .update_signatures import run as update_signatures
from .reporters import print_matches, print_summary
from .utils import PerfTimer

async def identify_and_print_async(fido_instance, file, timer, noextension):
    """Helper coroutine to identify a single file and print matches."""
    try:
        matches = await fido_instance.identify_file_async(file, extension=not noextension)
        for match in matches:
            print_matches(fido_instance, match['filename'], [match], timer.duration(), match['match_type'])
    except (IOError, RuntimeError) as e:
        sys.stderr.write(f"FIDO: Error processing {file}: {e}\n")

async def process_files_async(fido_instance, files, timer, noextension, recurse):
    """Process a list of files concurrently."""
    tasks = [identify_and_print_async(fido_instance, file, timer, noextension) for file in list_files(files, recurse)]
    await asyncio.gather(*tasks)

def list_files(roots, recurse=False):
    """Return the files one at a time. Roots could be a fileobj or a list."""
    for root_str in roots:
        root = Path(root_str.strip())
        if root.is_file():
            yield root
        else:
            for p in root.rglob("*") if recurse else root.glob("*"):
                if p.is_file():
                    yield p
                if not recurse:
                    break


def main(args=None):
    """Main FIDO method."""
    if not args:
        args = sys.argv[1:]

    parser = ArgumentParser(description=DEFAULTS['description'], epilog=DEFAULTS['epilog'], fromfile_prefix_chars='@', formatter_class=RawTextHelpFormatter)
    parser.add_argument('-v', '--version', default=False, action='store_true', help='show version information')
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
    parser.add_argument('-bufsize', type=int, default=None, help='size (in bytes) of the buffer to match against (default=' + str(DEFAULTS['bufsize']) + ' bytes)')
    parser.add_argument('-sigs', default=None, metavar='SIG_ACT', help='SIG_ACT "check" for new version\nSIG_ACT "update" to latest\nSIG_ACT "list" available versions\nSIG_ACT "n" use version n.')
    parser.add_argument('-container_bufsize', type=int, default=None, help='size (in bytes) of the buffer to match against (default=' + str(DEFAULTS['container_bufsize']) + ' bytes)')
    parser.add_argument('-loadformats', default=None, metavar='XML1,...,XMLn', help='comma separated string of XML format files to add.')
    parser.add_argument('-confdir', default=None, help='configuration directory to load_fido_xml, for example, the format specifications from.')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    args = parser.parse_args(args)

    timer = PerfTimer()

    conf_dir = args.confdir or Path(__file__).parent.joinpath('conf')
    versions = get_local_versions(conf_dir)

    DEFAULTS['xml_pronomSignature'] = versions.pronom_signature
    DEFAULTS['containersignature_file'] = versions.pronom_container_signature
    DEFAULTS['xml_fidoExtensionSignature'] = versions.fido_extension_signature
    DEFAULTS['format_files'] = [Path(conf_dir) / DEFAULTS['xml_pronomSignature']]

    if args.pronom_only:
        versionHeader = "FIDO v{0} ({1}, {2})\n".format(__version__, DEFAULTS['xml_pronomSignature'], DEFAULTS['containersignature_file'])
    else:
        versionHeader = "FIDO v{0} ({1}, {2}, {3})\n".format(__version__, DEFAULTS['xml_pronomSignature'], DEFAULTS['containersignature_file'], DEFAULTS['xml_fidoExtensionSignature'])
        DEFAULTS['format_files'].append(DEFAULTS['xml_fidoExtensionSignature'])

    if args.version:
        sys.stdout.write(versionHeader)
        sys.exit(0)

    if args.sigs:
        logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
        update_signatures()
        sys.exit(1)


    if args.matchprintf:
        DEFAULTS['printmatch'] = args.matchprintf.replace(r"\n", "\n").replace(r"\t", "\t")
    if args.nomatchprintf:
        DEFAULTS['printnomatch'] = args.nomatchprintf.replace(r"\n", "\n").replace(r"\t", "\t")

    fido_instance = Fido(
        conf_dir=conf_dir,
        format_files=DEFAULTS['format_files'],
        containersignature_file=DEFAULTS['containersignature_file'])

    # TODO: Allow conf options to be dis-included
    if args.loadformats:
        for file in args.loadformats.split(','):
            fido_instance.puid_format_map.update(SignatureLoader(conf_dir, [file], None).load_signatures())

    # TODO: remove from maps
    if args.useformats:
        args.useformats = args.useformats.split(',')
        fido_instance.formats = [f for f in fido_instance.formats if f.puid in args.useformats]
    elif args.nouseformats:
        args.nouseformats = args.nouseformats.split(',')
        fido_instance.formats = [f for f in fido_instance.formats if f.puid not in args.nouseformats]

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
                print_matches(fido_instance, args.filename or 'STDIN', matches, timer.duration(), 'stream')
        else:
            asyncio.run(process_files_async(fido_instance, args.files, timer, args.noextension, args.recurse))
    except KeyboardInterrupt:
        sys.stdout.flush()
        sys.stderr.flush()
        sys.exit('FIDO: Interrupt while identifying file {0}'.format(fido_instance.current_file))

    if not args.q:
        sys.stdout.flush()
        print_summary(fido_instance.current_count, timer.duration(), args.q)
        sys.stderr.flush()