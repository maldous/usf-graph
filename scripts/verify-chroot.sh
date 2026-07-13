#!/usr/bin/env bash
# Verify the reproducible chroot toolchain without contacting Stardog.
set -euo pipefail
fail=0
note(){ echo "$@" >&2; }

for p in /usf /usf/.venv/bin/python \
  /usr/local/bin/node /usr/local/bin/npm /usf/compiler/node_modules/stardog \
  /usr/local/bin/claude /usr/local/bin/codex /usf/AGENTS.md /usf/CLAUDE.md \
  /usf/CODEX.md /usf/.mcp.json /usf/.claude/skills/usf/SKILL.md \
  /usf/.codex/skills/usf/SKILL.md /root/.codex/config.toml \
  /root/.bashrc /root/.gitconfig /root/.claude.json; do
  if [ -e "$p" ]; then note "ok   $p"; else note "MISS $p"; fail=1; fi
done

if grep -R -E '/usr/local/bin/stardog|stardog-admin|[[:space:]]stardog[[:space:]]+(query|data)' \
    /usf/scripts --exclude=verify-chroot.sh >/dev/null 2>&1; then
  note "FAIL prohibited Stardog CLI reference in active scripts"
  fail=1
else
  note "ok   official-SDK-only active scripts"
fi

/usf/.venv/bin/python -c 'import rdflib, pyshacl, yaml' >/dev/null 2>&1 ||
  { note "FAIL Python RDF imports"; fail=1; }
(cd /usf/compiler && node -e 'import("stardog")') >/dev/null 2>&1 ||
  { note "FAIL official Stardog SDK import"; fail=1; }
# graph/ and census/ live in the parent repository and are used host-side only
# (validate-graph.sh, npm run check); the chroot never sees them.
if [ -e /graph ] || [ -e /census ]; then
  note "FAIL graph/census must not exist inside the chroot"; fail=1
else
  note "ok   chroot is graph/census-free"
fi
(cd /usf/compiler && npm test >/dev/null) ||
  { note "FAIL compiler local validation"; fail=1; }

[ "$fail" -eq 0 ] || { note "verification FAILED"; exit 1; }
echo "USF v2 chroot verified"
