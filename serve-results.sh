#!/bin/sh
# Lightweight results server — busybox httpd, no python dependency
cd /results 2>/dev/null || cd /
echo "Serving results on :8080"
httpd -p 8080 -h . -f
