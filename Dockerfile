FROM alpine:3.22

LABEL org.opencontainers.image.title="dns-speedtest" \
      org.opencontainers.image.description="DNS, DoT and DoH speed test" \
      org.opencontainers.image.source="https://github.com/mazixs/dns-speedtest" \
      org.opencontainers.image.licenses="GPL-3.0"

# bash gives a microsecond timer, kdig handles UDP and DoT, curl handles DoH over HTTP/2.
RUN apk add --no-cache bash ca-certificates curl knot-utils openssl

COPY dnstest.sh /usr/local/bin/dnstest.sh

ENTRYPOINT ["sh", "/usr/local/bin/dnstest.sh"]
