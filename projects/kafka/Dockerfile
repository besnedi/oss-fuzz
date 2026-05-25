FROM gcr.io/oss-fuzz-base/base-builder-jvm

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    git zip unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/apache/kafka $SRC/kafka

COPY build.sh *.java *.dict *.options *_seed_corpus.zip $SRC/
WORKDIR $SRC/kafka
