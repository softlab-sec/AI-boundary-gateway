#!/bin/sh
mkdir -p /var/log/boundary /var/lib/boundary
chmod -R 777 /var/log/boundary /var/lib/boundary 2>/dev/null || true
exec "$@"
