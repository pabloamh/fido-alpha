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

Functions for reporting FIDO's results.
"""
import sys
from typing import List, Dict, Any
from .config import DEFAULTS
from .fido import Fido
from .models import FileFormat


def print_summary(count: int, secs: float, quiet: bool) -> None:
    """Print summary information on the number of matches and time taken."""
    if not quiet:
        rate = int(round(count / secs)) if secs != 0 else 9999
        print('FIDO: Processed %6d files in %6.2f msec, %2d files/sec' % (count, secs * 1000, rate), file=sys.stderr)


def print_matches(fido_instance: Fido, fullname: str, matches: List[Dict[str, Any]], delta_t: float, matchtype: str = '') -> None:
    """
    The default match handler. Prints out information for each match in the list.
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
    if not matches:
        sys.stdout.write(DEFAULTS['printnomatch'].format(info=obj))
    else:
        for i, match_data in enumerate(matches, 1):
            obj.group_index = i
            obj.puid = match_data.get('puid')
            obj.formatname = match_data.get('format_name')
            obj.signaturename = match_data.get('signature_name')
            obj.mimetype = match_data.get('mime')
            obj.version = match_data.get('version')
            sys.stdout.write(DEFAULTS['printmatch'].format(info=obj))