#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MCP_ROOT="${REPO_ROOT}/mcp"
NODE_SDK_ROOT="${REPO_ROOT}/packages/npm"
ENV_FILE="${MCP_ROOT}/.env.hosted"
NODE_PATH="$(command -v node)"
NPM_PATH="$(command -v npm)"
SERVICE_NAME="aegir-sdk-mcp"
SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
SERVICE_USER="${SUDO_USER:-$(whoami)}"

if [[ -z "${NODE_PATH}" ]]; then
  echo "node is required on the server."
  exit 1
fi

if [[ -z "${NPM_PATH}" ]]; then
  echo "npm is required on the server."
  exit 1
fi

if [[ ! -f "${ENV_FILE}" ]]; then
  echo "Expected hosted environment file at ${ENV_FILE}."
  exit 1
fi

if [[ ! -f "${NODE_SDK_ROOT}/package.json" ]]; then
  echo "Expected Node SDK package.json at ${NODE_SDK_ROOT}."
  exit 1
fi

cd "${NODE_SDK_ROOT}"
npm install
npm run build

cd "${MCP_ROOT}"
npm install

sudo tee "${SERVICE_PATH}" > /dev/null <<EOF
[Unit]
Description=Aegir SDK Hosted MCP
After=network.target

[Service]
Type=simple
User=${SERVICE_USER}
WorkingDirectory=${MCP_ROOT}
EnvironmentFile=${ENV_FILE}
ExecStart=${NODE_PATH} ${MCP_ROOT}/src/hosted-server.mjs
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable "${SERVICE_NAME}"
sudo systemctl restart "${SERVICE_NAME}"
sudo systemctl status "${SERVICE_NAME}" --no-pager
