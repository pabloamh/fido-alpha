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

General application utilities.
"""
try:
    from typing import Optional, Dict
    from time import perf_counter
except ImportError:
    from time import clock as perf_counter


class PerfTimer:
    """A simple performance timer utility."""

    def __init__(self) -> None:
        """New instance with start time running."""
        self.start_time = perf_counter()

    def start(self) -> None:
        """Start new timer."""
        self.start_time = perf_counter()

    def duration(self) -> float:
        """Return the duration since instantiation or start() was last called."""
        return perf_counter() - self.start_time


def query_yes_no(question: str, default: Optional[str] = 'yes') -> bool:
    """
    Ask a yes/no question via input() and return their answer.

    `question` is a string that is presented to the user. `default` is the
    presumed answer if the user just hits <Enter>. It must be "yes" (the
    default), "no" or None (meaning an answer is required of the user).

    The "answer" return value is True for "yes" or False for "no".
    """
    valid: Dict[str, bool] = {'yes': True, 'y': True, 'no': False, 'n': False}
    if default is None:
        prompt = ' [y/n] '
    elif default == 'yes':
        prompt = ' [Y/n] '
    elif default == 'no':
        prompt = ' [y/N] '
    else:
        raise ValueError(f'Invalid default answer: "{default}"')
    while True:
        choice = input(question + prompt).lower()
        if default is not None and choice == '':
            return valid[default]
        if choice in valid:
            return valid[choice]
        print('Please respond with "yes" or "no" (or "y" or "n").')