# Aiven Runtime2 CTF probe container
# Built for deployment inside Aiven's perimeter once Runtime access lands
# Sweep + PG exfil chain + results reporting
FROM alpine:3.20

RUN apk add --no-cache \
    bash \
    curl \
    nmap \
    netcat-openbsd \
    openssh-client \
    postgresql16-client \
    bind-tools \
    jq \
    coreutils

# probe script is the main payload
COPY probe.sh /probe.sh
RUN chmod +x /probe.sh

# light HTTP server for result retrieval (busybox python replacement)
COPY serve-results.sh /serve-results.sh
RUN chmod +x /serve-results.sh

EXPOSE 8080

CMD ["/probe.sh"]
