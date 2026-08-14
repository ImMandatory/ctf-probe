FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    dnsutils netcat-openbsd curl postgresql-client openssh-client \
    && rm -rf /var/lib/apt/lists/*
COPY probe.sh /app/probe.sh
RUN chmod +x /app/probe.sh
EXPOSE 8080
CMD ["/app/probe.sh"]
