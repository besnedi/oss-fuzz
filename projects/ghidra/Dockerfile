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
		openjdk-17-jdk gradle python3 ca-certificates \
		vim
ENV JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64

# get the src code (only latest commit, not the full history)
RUN git clone --depth 1 https://github.com/NationalSecurityAgency/ghidra.git ghidra

COPY build.sh $SRC/
COPY ./*Fuzzer.java $SRC/

# get the additional project deps
WORKDIR $SRC/ghidra

#RUN $SRC/build.sh
## per ghidra README.md, using ./gradlew instead of gradle
## --no-daemon disables gradle background process
## -x exclude any tests
#RUN ./gradlew --no-daemon -I gradle/support/fetchDependencies.gradle
#RUN ./gradlew --no-daemon buildGhidra -x test

## get the binaries
#RUN unzip build/dist/ghidra_*.zip -d /src/ghidra-dist
#ENV GHIDRA_HOME=/src/ghidra-dist/ghidra_*/
#
#WORKDIR $GHIDRA_HOME
#ENV GHIDRA_JARS=$(find ${GHIDRA_HOME}/Ghidra/ -name "*.jar" -type f)| tr ' ' ':'




## per https://github.com/trailofbits/buttercup/blob/main/guides/CUSTOM_CHALLENGES.md
#RUN apt-get update && apt-get install -y \
#    make pkg-config
    

# Ghidra build deps
#RUN apt-get install -y unzip wget git \
#    openjdk-21-jdk gradle python3 ca-certificates \
#  && rm -rf /var/lib/apt/lists/*
#
#RUN ./gradlew --no-daemon  -I gradle/support/fetchDependencies.gradle init
#RUN gradle --no-daemon build -x test
#
## Unpack the built distribution so we can compile/run fuzz targets against the API jars
#WORKDIR /src
#RUN unzip ghidra/build/dist/ghidra_*_PUBLIC_*.zip -d /src/ghidra-dist
#
### Add fuzz targets & build script
##ADD fuzz/ /src/fuzz/
##ADD build.sh run.sh /src/
#
## Jazzer expects FUZZ_TARGET to be built into /out and classpath set
#ENV GHIDRA_HOME=/src/ghidra-dist/ghidra_*_PUBLIC
#ENV GHIDRA_JARS="$GHIDRA_HOME/Ghidra/Framework/*/lib/*:$GHIDRA_HOME/Ghidra/Features/*/lib/*:$GHIDRA_HOME/Ghidra/Processors/*/lib/*:$GHIDRA_HOME/lib/*"
#ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
#
##RUN /src/build.sh
#
## Default run executes both targets under libFuzzer/Jazzer
#CMD ["/src/run.sh"]

