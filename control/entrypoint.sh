#!/bin/sh
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#
# Makes a shallow checkout of the target repository available to the scanner.
# The checkout is read-only as far as this stack is concerned: remediation
# happens in Devin sessions against the real repository, never here.

set -eu

: "${TARGET_REPOSITORY:=neerajgulia92/superset-ng}"
: "${TARGET_CHECKOUT:=/target}"
: "${TARGET_REF:=master}"
: "${SKIP_CHECKOUT:=false}"

if [ "$SKIP_CHECKOUT" != "true" ]; then
  if [ -d "$TARGET_CHECKOUT/.git" ]; then
    echo "refreshing $TARGET_REPOSITORY in $TARGET_CHECKOUT"
    git -C "$TARGET_CHECKOUT" fetch --depth 1 origin "$TARGET_REF" \
      && git -C "$TARGET_CHECKOUT" checkout -q FETCH_HEAD \
      || echo "refresh failed, using the existing checkout"
  else
    echo "cloning $TARGET_REPOSITORY into $TARGET_CHECKOUT"
    git clone --depth 1 --branch "$TARGET_REF" \
      "https://github.com/$TARGET_REPOSITORY.git" "$TARGET_CHECKOUT" \
      || echo "clone failed; the scan stage will report no manifests"
  fi
fi

exec "$@"
