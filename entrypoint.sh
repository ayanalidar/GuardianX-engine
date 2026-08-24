#!/bin/sh
# Write z-ai config from env var at runtime
printf '%s' "$ZAI_CONFIG" > /app/.z-ai-config
echo "[entrypoint] wrote .z-ai-config"
exec bun index.ts
