#!/bin/sh
# Aiven Runtime probe container - sweeps the CTF sandbox from INSIDE the Aiven perimeter
echo "=== probe container started $(date -u) ==="
echo "=== env intel ==="
env | grep -iE "hostname|cloud|region|avn|runtime" | head -20
echo "=== outbound IP ==="
curl -s -m 10 https://api.ipify.org 2>/dev/null || echo "no egress to ipify"
echo ""
echo "=== SANDBOX PORT SWEEP: 132.145.191.135 ==="
for p in 22 80 443 5432 5433 22292 22293 22294 22300 8008 8080 8443 16000 9092 9200 54321 28001; do
  if nc -z -w 3 132.145.191.135 $p 2>/dev/null; then
    echo "OPEN: $p"
  else
    echo "closed/filtered: $p"
  fi
done
echo ""
echo "=== SSH banner grab ==="
timeout 8 nc 132.145.191.135 22 2>/dev/null | head -2 || echo "no banner"
echo ""
echo "=== PG reachability ==="
timeout 8 bash -c 'echo | nc -w 4 132.145.191.135 5432' 2>/dev/null | head -1 || echo "pg:5432 no response"
echo ""
echo "=== done $(date -u) ==="
# keep alive for port exposure / results retrieval
python3 -m http.server 8080 --bind 0.0.0.0 &
wait
