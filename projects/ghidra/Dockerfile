# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

FROM gcr.io/oss-fuzz-base/base-builder-jvm
RUN apt-get update && \
        apt-get install -y make autoconf automake libtool \
                gradle python3 ca-certificates \
                vim

# Downloading version 11.1.2 for Java 17 compatibility with oss-fuzz base runner
# newer Ghidra builds require Java 21 which the oss-fuzz base containers do not currently support
RUN git clone --depth 1 --single-branch --branch Ghidra_11.1.2_build https://github.com/NationalSecurityAgency/ghidra.git

COPY build.sh $SRC/
COPY ./*Fuzzer.java $SRC/

# get the additional project deps
WORKDIR $SRC/ghidra
