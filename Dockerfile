FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    dnsutils netcat-openbsd curl postgresql-client openssh-client git \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir psycopg2-binary 2>/dev/null || pip install --no-cache-dir psycopg2
COPY probe.sh /app/probe.sh
RUN chmod +x /app/probe.sh
# pghostile clone (the intended PG exploit)
RUN git clone --depth 1 https://github.com/Aiven-Open/pghostile.git /app/pghostile
COPY pghostile_run.py /app/pghostile_run.py
EXPOSE 8080
CMD ["/app/probe.sh"]
