ARG OTP_VERSION=alpine
FROM erlang:${OTP_VERSION}-alpine

# Setup environment
ENV LANG=C.UTF-8 TERM=xterm

# Add dependencies
RUN apk upgrade --update musl && \
    apk add --no-cache bash bc build-base clang curl git make openssl rsync unzip && \
    rm -rf /var/cache/apk/*

ENV CC clang
ENV CXX clang++

RUN mkdir /build
WORKDIR /build
