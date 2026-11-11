# Copyright (c) 2024 The Johns Hopkins University/Applied Physics Laboratory
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import os
import tempfile

# The server engine defaults to a hard-coded /tmp database path. In
# restricted environments /tmp may not be writable, so redirect the default
# location into a per-process temporary file before any engine is built.
os.environ.setdefault(
    'KMIP_SERVER_DB_PATH',
    os.path.join(tempfile.gettempdir(), 'pykmip-test.database')
)
