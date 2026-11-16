#!/bin/sh
# Write the runtime settings the dashboard reads before its bundle loads.
#
# The image is generic: the same trydirect/stackdog-ui serves every
# installation, so the API address cannot be compiled in. It is written here,
# at container start, from the environment.
set -eu

CONFIG_PATH=/usr/share/nginx/html/config.js

API_PORT="${STACKDOG_API_PORT:-5000}"
# Empty means "same host as the dashboard, on the API port", which the bundle
# works out for itself.
API_URL="${STACKDOG_API_URL:-}"
WS_URL="${STACKDOG_WS_URL:-}"

cat > "$CONFIG_PATH" <<EOF
window.__STACKDOG_ENV__ = {
  REACT_APP_API_URL: "${API_URL}",
  REACT_APP_WS_URL: "${WS_URL}",
  REACT_APP_API_PORT: "${API_PORT}"
};
EOF

echo "Dashboard config: API_URL=${API_URL:-<default>} WS_URL=${WS_URL:-<default>} API_PORT=${API_PORT}"

exec "$@"
