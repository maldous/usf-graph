#!/usr/bin/env bash
# Bootstrap the repository chroot for reproducible USF graph/compiler work.
#
# Stardog access is exclusively through the official JavaScript SDK installed
# from compiler/package-lock.json. No Stardog CLI, raw HTTP client, or local
# Stardog server is installed or invoked.
set -euo pipefail

NODE_VERSION="22.23.1"
NODE_SHA256="9749e988f437343b7fa832c69ded82a312e41a03116d766797ac14f6f9eee578"
NODE_DIR="/opt/node-v${NODE_VERSION}-linux-x64"
NODE_ARCHIVE="/opt/node-v${NODE_VERSION}-linux-x64.tar.xz"
NODE_URL="https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz"
VENV_DIR="/usf/.venv"
PY_DEPS=("rdflib==7.6.0" "pyshacl==0.40.0" "pyyaml==6.0.3")
# Agent CLIs, pinned for repeatable installs (same policy as Node/Java above).
# npm verifies registry-signed integrity checksums for exact-version installs.
CLAUDE_CODE_PKG="@anthropic-ai/claude-code@2.1.207"
CODEX_PKG="@openai/codex@0.144.2"

log(){ printf '\n== %s ==\n' "$*"; }
have(){ command -v "$1" >/dev/null 2>&1; }
ensure_dns(){
  if [ ! -s /etc/resolv.conf ] || ! grep -q nameserver /etc/resolv.conf 2>/dev/null; then
    echo "nameserver 1.1.1.1" > /etc/resolv.conf
  fi
}

[ "$(id -u)" -eq 0 ] || { echo "error: run as root inside the chroot" >&2; exit 1; }
[ -d /usf/compiler ] || { echo "error: /usf/compiler is missing" >&2; exit 1; }

log "OS prerequisites"
need=()
have curl || need+=(curl)
have xz || need+=(xz-utils)
[ -e /etc/ssl/certs/ca-certificates.crt ] || need+=(ca-certificates)
have python3 || need+=(python3)
python3 -c 'import venv' 2>/dev/null || need+=(python3-venv)
python3 -c 'import ensurepip' 2>/dev/null || need+=(python3-pip)
if [ "${#need[@]}" -gt 0 ]; then
  ensure_dns
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y --no-install-recommends "${need[@]}"
  update-ca-certificates 2>/dev/null || true
else
  echo "present: curl xz ca-certificates python3 venv pip"
fi

log "Node.js ${NODE_VERSION}"
if [ ! -x "${NODE_DIR}/bin/node" ]; then
  if [ ! -f "${NODE_ARCHIVE}" ]; then
    ensure_dns
    curl -fSL --retry 3 -o "${NODE_ARCHIVE}" "${NODE_URL}"
  fi
  printf '%s  %s\n' "${NODE_SHA256}" "${NODE_ARCHIVE}" | sha256sum -c -
  rm -rf "${NODE_DIR}"
  tar -xJf "${NODE_ARCHIVE}" -C /opt
fi
ln -sf "${NODE_DIR}/bin/node" /usr/local/bin/node
ln -sf "${NODE_DIR}/bin/npm" /usr/local/bin/npm
ln -sf "${NODE_DIR}/bin/npx" /usr/local/bin/npx
cat > /etc/profile.d/node.sh <<EOF
export PATH="${NODE_DIR}/bin:\$PATH"
EOF
export PATH="${NODE_DIR}/bin:$PATH"
node --version
npm --version

log "Pinned Python RDF toolchain"
[ -x "${VENV_DIR}/bin/python" ] || python3 -m venv "${VENV_DIR}"
"${VENV_DIR}/bin/pip" install --quiet --upgrade pip
"${VENV_DIR}/bin/pip" install --quiet "${PY_DEPS[@]}"
"${VENV_DIR}/bin/python" -c 'import rdflib, pyshacl, yaml; print(rdflib.__version__, pyshacl.__version__, yaml.__version__)'

log "Frozen compiler dependencies"
(cd /usf/compiler && npm ci --ignore-scripts)
(cd /usf/compiler && node -e 'import("stardog").then(() => console.log("official Stardog SDK import: OK"))')

log "Pinned agent CLIs (claude, codex)"
want_claude="${CLAUDE_CODE_PKG##*@}"
want_codex="${CODEX_PKG##*@}"
have_cli(){ [ -x "${NODE_DIR}/bin/$1" ] && "${NODE_DIR}/bin/$1" --version 2>/dev/null | grep -qF "$2"; }
if ! have_cli claude "${want_claude}"; then
  ensure_dns
  npm install -g --no-fund --no-audit "${CLAUDE_CODE_PKG}"
fi
if ! have_cli codex "${want_codex}"; then
  ensure_dns
  npm install -g --no-fund --no-audit "${CODEX_PKG}"
fi
ln -sf "${NODE_DIR}/bin/claude" /usr/local/bin/claude
ln -sf "${NODE_DIR}/bin/codex" /usr/local/bin/codex
claude --version
codex --version

log "Agent shell, git and MCP wiring (token-free; credentials live in /usf/.env)"
cat > /root/.bashrc <<'EOF'
# USF chroot shell environment: load token-free profile.d wiring, which sources
# /usf/.env (git-ignored credentials). Makes STARDOG_*, GITHUB_PERSONAL_ACCESS_TOKEN,
# LINEAR_API_KEY and OPENAI_API_KEY available to claude/codex and the MCP servers.
for f in /etc/profile.d/*.sh; do [ -r "$f" ] && . "$f"; done
cd /usf 2>/dev/null || true
EOF
cat > /root/.bash_profile <<'EOF'
[ -r ~/.bashrc ] && . ~/.bashrc
EOF
[ -f /root/.gitconfig ] || cat > /root/.gitconfig <<'EOF'
[user]
	name = Matthew Aldous
	email = matthew.aldous@gmail.com
[safe]
	directory = *
[init]
	defaultBranch = main
[pull]
	rebase = false
[credential "https://github.com"]
	# token-free config: the credential is read from the environment at use
	# time (populated by /root/.bashrc from the git-ignored /usf/.env)
	helper = "!f() { echo username=x-access-token; echo \"password=${GITHUB_PERSONAL_ACCESS_TOKEN}\"; }; f"
EOF
# Pre-trust /usf and its project .mcp.json servers for headless agent launches.
[ -f /root/.claude.json ] || cat > /root/.claude.json <<'EOF'
{
  "hasCompletedOnboarding": true,
  "projects": {
    "/usf": {
      "hasTrustDialogAccepted": true,
      "hasCompletedProjectOnboarding": true,
      "enabledMcpjsonServers": ["usf", "github", "linear"]
    }
  }
}
EOF
echo "shell/git/mcp wiring present"

log "Codex MCP registration and skill wiring (token-free)"
# Codex does not read the project .mcp.json: it discovers MCP servers only via
# $CODEX_HOME/config.toml. Register the same three servers claude gets, field-level
# through the codex CLI (idempotent: re-adding a name rewrites the same table).
# Token-free: usf launches via a wrapper that sources the git-ignored /usf/.env;
# github/linear read their bearer tokens from the environment at connect time.
CODEX_CFG=/root/.codex/config.toml
codex mcp add usf -- bash -c 'set -a; [ -f /usf/.env ] && . /usf/.env; set +a; exec /usr/local/bin/node /usf/compiler/src/mcp.js'
codex mcp add github --url https://api.githubcopilot.com/mcp/ --bearer-token-env-var GITHUB_PERSONAL_ACCESS_TOKEN
codex mcp add linear --url https://mcp.linear.app/mcp --bearer-token-env-var LINEAR_API_KEY
# Tool-approval posture (headless `codex exec` auto-denies prompted calls):
#   usf    -> approve: the gateway is read-only and fail-closed server-side, so
#             approval prompts add no safety.
#   github/linear -> writes: reads run unprompted; mutations still prompt (and
#             are therefore denied in headless runs) per AGENTS.md Linear rules.
set_approval_mode(){ # <server> <mode>
  awk -v s="$1" 'index($0,"[mcp_servers."s"]")==1{f=1;next} /^\[/{f=0} f&&/^default_tools_approval_mode/{ok=1} END{exit !ok}' "$CODEX_CFG" ||
    sed -i "/^\[mcp_servers\.$1\]$/a default_tools_approval_mode = \"$2\"" "$CODEX_CFG"
}
set_approval_mode usf approve
set_approval_mode github writes
set_approval_mode linear writes
# Pre-trust /usf so Codex loads AGENTS.md and the project-level skills
# (/usf/.codex/skills — the tracked symlink to the canonical .claude/skills/usf).
grep -qF '[projects."/usf"]' "$CODEX_CFG" || printf '\n[projects."/usf"]\ntrust_level = "trusted"\n' >> "$CODEX_CFG"
chmod 600 "$CODEX_CFG"
echo "codex mcp/skill wiring present"

log "readiness"
[ -x /usr/local/bin/node ] || { echo "MISSING node" >&2; exit 1; }
[ -x "${VENV_DIR}/bin/python" ] || { echo "MISSING venv" >&2; exit 1; }
[ -d /usf/compiler/node_modules/stardog ] || { echo "MISSING official Stardog SDK" >&2; exit 1; }
[ -x /usr/local/bin/claude ] || { echo "MISSING claude CLI" >&2; exit 1; }
[ -x /usr/local/bin/codex ] || { echo "MISSING codex CLI" >&2; exit 1; }
for s in usf github linear; do
  grep -qF "[mcp_servers.$s]" /root/.codex/config.toml || { echo "MISSING codex $s MCP registration" >&2; exit 1; }
done
[ -f /usf/.codex/skills/usf/SKILL.md ] || { echo "MISSING codex usf skill (broken /usf/.codex/skills/usf link?)" >&2; exit 1; }
echo "USF chroot bootstrap complete"
