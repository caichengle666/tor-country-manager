#!/bin/sh
set -eu

if [ ! -f /data/config.json ]; then
  cp /app/config.default.json /data/config.json
  chmod 0600 /data/config.json
fi

exec /usr/local/bin/tor-country-manager -config /data/config.json

