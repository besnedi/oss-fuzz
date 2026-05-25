FROM gcr.io/oss-fuzz-base/base-builder-jvm

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    git zip unzip maven ca-certificates wget \
    && (apt-get install -y --no-install-recommends openjdk-21-jdk-headless || \
        (mkdir -p /opt/jdk21 && \
         wget -O /tmp/jdk21.tar.gz https://api.adoptium.net/v3/binary/latest/21/ga/linux/x64/jdk/hotspot/normal/eclipse && \
         tar -xzf /tmp/jdk21.tar.gz --strip-components=1 -C /opt/jdk21)) \
    && if [ -d /usr/lib/jvm/java-21-openjdk-amd64 ]; then ln -sfn /usr/lib/jvm/java-21-openjdk-amd64 /opt/jdk21; fi \
    && rm -rf /var/lib/apt/lists/* /tmp/jdk21.tar.gz

ENV JAVA_HOME=/opt/jdk21
ENV PATH=$JAVA_HOME/bin:$PATH
RUN git clone https://github.com/apache/nifi $SRC/nifi && \
    cd $SRC/nifi && \
    git checkout fc08aa897197327baca920640393f07a3b5eed5a

COPY build.sh *.java *.dict *.options *_seed_corpus.zip $SRC/
WORKDIR $SRC/nifi
