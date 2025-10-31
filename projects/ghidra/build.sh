#!/bin/bash -eu
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

# Step 1: build Ghidra

# Java17 compatible Ghidra (build 11.1.2 and older) requires get a compatible version of Gradle (8.5+)
# Download and use the compatible Gradle version to generate a wrapper (gradlew equivalent)
GRADLE_VER=8.5
curl -L -o /tmp/gradle.zip https://services.gradle.org/distributions/gradle-${GRADLE_VER}-bin.zip
unzip -q /tmp/gradle.zip -d /tmp

# make the script executable and verify

# build project - per ghidra README.md
# --no-daemon disables gradle background process
# -x exclude any tests
/tmp/gradle-${GRADLE_VER}/bin/gradle --no-daemon -I gradle/support/fetchDependencies.gradle init
/tmp/gradle-${GRADLE_VER}/bin/gradle --no-daemon buildGhidra -x test

# get the jars (https://google.github.io/oss-fuzz/getting-started/new-project-guide/jvm-lang/)
unzip build/dist/ghidra_*.zip -d /src/ghidra-dist
export GHIDRA_SRC_HOME=/src/ghidra/
export GHIDRA_HOME=/src/ghidra-dist/ghidra_*/

find ${GHIDRA_SRC_HOME}/ -name "*.jar" -type f ! -name "*-test.jar" ! -name "*-tests.jar" -exec cp -v {} "${OUT}/" \;
find ${GHIDRA_HOME}/ -name "*.jar" -type f ! -name "*-test.jar" ! -name "*-tests.jar" -exec cp -v {} "${OUT}/" \;
PROJECT_JAR=$(find ${OUT}/ -name "*.jar" -type f)

# Step 2: build the fuzzers

# The classpath at build-time includes the project jars in $OUT as well as the Jazzer API.
BUILD_CLASSPATH=$(echo ${PROJECT_JAR} | tr ' ' ':'):${JAZZER_API_PATH}

# All .jar and .class files lie in the same directory as the fuzzer at runtime.
RUNTIME_CLASSPATH=$(echo ${PROJECT_JARS} | tr ' ' ':')

for fuzzer in $(find $SRC -name '*Fuzzer.java'); do
  fuzzer_basename=$(basename -s .java $fuzzer)
  echo $fuzzer
  javac -cp $BUILD_CLASSPATH $fuzzer
  cp $SRC/$fuzzer_basename.class $OUT/

  # Create an execution wrapper that executes Jazzer with the correct arguments.
  echo "#!/bin/bash
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=\$(dirname \"\$0\")
if [[ \"\$@\" =~ (^| )-runs=[0-9]+($| ) ]]; then
  mem_settings='-Xmx1900m:-Xss900k'
else
  mem_settings='-Xmx2048m:-Xss1024k'
fi
LD_LIBRARY_PATH=\"$JVM_LD_LIBRARY_PATH\":\$this_dir \
\$this_dir/jazzer_driver --agent_path=\$this_dir/jazzer_agent_deploy.jar \
--cp=$RUNTIME_CLASSPATH \
--target_class=$fuzzer_basename \
--jvm_args=\"\$mem_settings:-Djava.awt.headless=true\" \
\$@" > $OUT/$fuzzer_basename
  chmod +x $OUT/$fuzzer_basename

done
