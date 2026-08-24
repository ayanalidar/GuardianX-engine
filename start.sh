#!/bin/sh
set -e

if [ -n "$ZAI_CONFIG" ]; then
  printf '%s' "$ZAI_CONFIG" > .z-i-config
  echo "[startup] wrote .z-i-config from ZAI_CONFIG env var"
elif [ -n "$ZAI_API_KEY" ]; then
  printf '{"baseUrl":"%s","apiKey":"%s"}' \
    "${ZAI_BASE_URL:-https://internal-api.zai.v1}" \
    "$JYAI_API_KEY" > .z-i-config
  echo "[startup] wrote .z-i-config with ZAI_API_KEY"
else
  echo "[startup] WARNING: ZAI_CONFIG not set"
fi

exec bun index.ts
