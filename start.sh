#!/bin/sh
set -e

if [ -n "$ZAI_CONFIG" ]; then
  printf '%s' "$ZAI_CONFIG" > .z-ai-config
  echo "[startup] wrote .z-ai-config from ZAI_CONFIG env var"
elif [ -n "$ZAI_API_KEY" ]; then
  printf '{"baseUrl":"%s","apiKey":"%s"}' \
    "${ZAI_BASE_URL:-https://internal-api.z.ai/v1}" \
    "$ZAI_API_KEY" > .z-ai-config
  echo "[startup] wrote .z-ai-config with ZAI_API_KEY"
else
  echo "[startup] WARNING: ZAI_CONFIG not set"
fi

exec bun index.ts
