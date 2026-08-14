FROM alpine:latest
RUN apk add --no-cache curl netcat-openbsd openssh-client postgresql-client bind-tools busybox-extras
COPY probe.sh /probe.sh
RUN chmod +x /probe.sh
EXPOSE 8080
CMD ["sh", "/probe.sh"]
