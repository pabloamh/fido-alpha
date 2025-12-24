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
class PronomServiceError(Exception):
    """Exception to wrap any exception thrown by the PRONOM service."""

    def __init__(self, message, original_error=None):
        if original_error:
            message = f"{message} (Caused by: {original_error})"
        super().__init__(message)
        self.original_error = original_error