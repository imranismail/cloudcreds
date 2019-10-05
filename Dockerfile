FROM scratch

COPY cloudcreds /

ENTRYPOINT ["/cloudcreds"]