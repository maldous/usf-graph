#!/usr/bin/env bash
# Verify the reproducible chroot toolchain without contacting Stardog.
set -euo pipefail
fail=0
note(){ echo "$@" >&2; }

for p in /usf /usf/graph /usf/.venv/bin/python \
  /usr/local/bin/node /usr/local/bin/npm /usf/tools/compiler/node_modules/stardog \
  /usr/local/bin/claude /usr/local/bin/codex /usf/AGENTS.md /usf/CLAUDE.md \
  /usf/CODEX.md /usf/.mcp.json /usf/.claude/skills/usf/SKILL.md \
  /usf/.codex/skills/usf/SKILL.md /root/.codex/config.toml \
  /root/.bashrc /root/.gitconfig /root/.claude.json; do
  if [ -e "$p" ]; then note "ok   $p"; else note "MISS $p"; fail=1; fi
done

if grep -R -E '/usr/local/bin/stardog|stardog-admin|[[:space:]]stardog[[:space:]]+(query|data)([[:space:]]|$)' \
    /usf/tools --exclude=verify-isolation.sh --exclude-dir=node_modules >/dev/null 2>&1; then
  note "FAIL prohibited Stardog CLI reference in active scripts"
  fail=1
else
  note "ok   official-SDK-only active scripts"
fi

/usf/.venv/bin/python -c 'import rdflib, pyshacl, yaml' >/dev/null 2>&1 ||
  { note "FAIL Python RDF imports"; fail=1; }
(cd /usf/tools/compiler && node -e 'import("stardog")') >/dev/null 2>&1 ||
  { note "FAIL official Stardog SDK import"; fail=1; }
# The standalone semantic source is inside /usf; historical parent census and
# host paths must not be reachable from the chroot.
if [ ! -e /usf/graph ] || [ -e /census ] || [ -e /home/user/src/usf ]; then
  note "FAIL standalone graph or isolation boundary"; fail=1
else
  note "ok   standalone graph present; parent and census absent"
fi
(cd /usf/tools/compiler && npm run check >/dev/null) ||
  { note "FAIL standalone graph check"; fail=1; }
(cd /usf/tools/compiler && npm test >/dev/null) ||
  { note "FAIL compiler local validation"; fail=1; }

[ "$fail" -eq 0 ] || { note "verification FAILED"; exit 1; }
echo "USF standalone chroot verified"
