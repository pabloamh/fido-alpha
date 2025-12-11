"""
FIDO Command-Line Interface

This module contains the command-line entry point for FIDO and all
related user interface functions.
"""
from argparse import ArgumentParser, RawTextHelpFormatter
import sys
from pathlib import Path
import logging

from .fido import Fido, PerfTimer
from . import __version__
from .config import DEFAULTS
from .package import ZipPackage, OlePackage, SignatureLoader
from .versions import get_local_versions
from .update_signatures import run as update_signatures


def query_yes_no(question, default='yes'):
    """
    Ask a yes/no question via input() and return their answer.

    `question` is a string that is presented to the user. `default` is the
    presumed answer if the user just hits <Enter>. It must be "yes" (the
    default), "no" or None (meaning an answer is required of the user).

    The "answer" return value is True for "yes" or False for "no".
    """
    valid = {'yes': True, 'y': True, 'no': False, 'n': False}
    if default is None:
        prompt = ' [y/n] '
    elif default == 'yes':
        prompt = ' [Y/n] '
    elif default == 'no':
        prompt = ' [y/N] '
    else:
        raise ValueError('Invalid default answer: "%s"' % default)
    while True:
        choice = input(question + prompt).lower()
        if default is not None and choice == '':
            return valid[default]
        if choice in valid:
            return valid[choice]
        print('Please respond with "yes" or "no" (or "y" or "n").')


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


def print_summary(count, secs, quiet):
    """Print summary information on the number of matches and time taken."""
    if not quiet:
        rate = int(round(count / secs)) if secs != 0 else 9999
        print('FIDO: Processed %6d files in %6.2f msec, %2d files/sec' % (count, secs * 1000, rate), file=sys.stderr)


def print_matches(fido_instance, fullname, matches, delta_t, matchtype=''):
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
    obj.count = fido_instance.current_count
    obj.group_size = len(matches)
    obj.filename = fullname
    obj.time = int(delta_t * 1000)
    obj.filesize = fido_instance.current_filesize
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
                            print_matches(fido_instance, file, container_matches, timer.duration(), "container")
                            continue

                    if not matches and not args.noextension:
                        matches = fido_instance.match_extensions(file)
                        matchtype = "extension"

                    print_matches(fido_instance, file, matches, timer.duration(), matchtype)

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