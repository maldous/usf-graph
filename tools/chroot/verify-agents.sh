#!/usr/bin/env bash
# Verify agent wiring behaviourally inside the chroot for both supported agent
# products against the required USF gateway: registration, discovery, live
# invocation, mutation rejection and credential hygiene. Optional external-work
# integrations are deliberately outside this gate so they cannot become normal
# programme dependencies. This contacts Stardog and the model backends and fails
# closed when the required runtime environment or agent auth is unavailable.
set -euo pipefail
fail=0
note(){ echo "$@" >&2; }
ok(){ note "ok   $*"; }
bad(){ note "FAIL $*"; fail=1; }

CODEX_HOME_DIR="${CODEX_HOME:-$HOME/.codex}"
CODEX_CFG="$CODEX_HOME_DIR/config.toml"

SMOKE_PROMPT='Do not run shell commands. If a skill named usf is NOT in your skill catalog, print exactly SKILL_MISSING and stop. Otherwise call the usf MCP tool usf_health and print its JSON result verbatim.'

# --- required runtime environment --------------------------------------------
[ -s /usf/.env ] && ok "/usf/.env present" || bad "/usf/.env missing/empty (required environment unavailable)"
for v in STARDOG_SERVER; do
  ( set -a; . /usf/.env 2>/dev/null; set +a; [ -n "${!v:-}" ] ) \
    && ok "env $v projected" || bad "env $v missing from /usf/.env"
done

# --- codex static wiring ------------------------------------------------------
[ -f "$CODEX_CFG" ] && ok "codex config $CODEX_CFG" || bad "codex config missing"
if [ -f "$CODEX_CFG" ]; then
  for s in usf; do
    [ "$(grep -cF "[mcp_servers.$s]" "$CODEX_CFG")" = 1 ] \
      && ok "single [mcp_servers.$s] registration" || bad "$s MCP registration absent or duplicated"
  done
  approval_of(){ awk -v s="$1" 'index($0,"[mcp_servers."s"]")==1{f=1;next} /^\[/{f=0} f&&sub(/^default_tools_approval_mode = /,""){print; exit}' "$CODEX_CFG"; }
  [ "$(approval_of usf)" = '"approve"' ] && ok "usf tools auto-approved" || bad "usf approval mode wrong: $(approval_of usf)"
  grep -qF '[projects."/usf"]' "$CODEX_CFG" && ok "/usf pre-trusted (codex)" || bad "/usf codex project trust missing"
  # Credential hygiene: no secret material may live in the codex config.
  if grep -qE '(token|password|api_key|bearer_token)[[:space:]]*=[[:space:]]*"[^"$]' "$CODEX_CFG"; then
    bad "credential literal found in codex config"
  else
    ok "codex config token-free"
  fi
  [ "$(stat -c %a "$CODEX_CFG")" = "600" ] && ok "codex config mode 600" || bad "codex config permissions too open"
fi
[ -f /usf/.codex/skills/usf/SKILL.md ] && ok "codex usf skill resolves" || bad "codex usf skill missing (/usf/.codex/skills/usf)"
[ -f /usf/.claude/skills/usf/SKILL.md ] && ok "canonical usf skill present" || bad "canonical .claude/skills/usf missing"

# --- claude static wiring -----------------------------------------------------
node -e 'const m=require("/usf/.mcp.json").mcpServers;if(!m.usf)process.exit(1)' 2>/dev/null \
  && ok "claude project .mcp.json declares usf" || bad "claude .mcp.json lacks required usf registration"
# Trust semantics: with hasTrustDialogAccepted, project .mcp.json servers are
# enabled unless explicitly disabled (claude's runtime rewrites this file and
# may drop the bootstrap-seeded enabledMcpjsonServers list).
node -e 'const p=require("/root/.claude.json").projects["/usf"];if(!p||!p.hasTrustDialogAccepted)process.exit(1);const d=p.disabledMcpjsonServers||[];if(d.includes("usf"))process.exit(1)' 2>/dev/null \
  && ok "claude pre-trusts /usf mcp servers" || bad "claude .claude.json trust/enable incomplete"
if grep -qE '(TOKEN|PASSWORD|API_KEY)[^}]*"[A-Za-z0-9_-]{20,}"' /usf/.mcp.json; then
  bad "credential literal found in .mcp.json"
else
  ok "claude .mcp.json token-free"
fi

# --- codex parses the registrations ------------------------------------------
mcp_list="$(codex mcp list 2>/dev/null || true)"
for s in usf; do
  grep -q "^$s[[:space:]]" <<<"$mcp_list" && ok "codex mcp list shows $s" || bad "codex does not list the $s MCP server"
done

# --- MCP protocol: discovery, health, redaction, read-only enforcement ------
# Drive the exact registered usf command (token-free /usf/.env wrapper).
mcp_out="$(printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"verify-agents","version":"0"}}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  '{"jsonrpc":"2.0","id":3,"method":"resources/list"}' \
  '{"jsonrpc":"2.0","id":4,"method":"resources/templates/list"}' \
  '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"usf_health","arguments":{}}}' \
  '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"usf_query","arguments":{"sparql":"INSERT DATA { <urn:usf:probe:a> <urn:usf:probe:b> <urn:usf:probe:c> }"}}}' \
  '{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"usf_evidence_admit","arguments":{"authorityDigest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","semanticResource":"urn:usf:probe:evidence"}}}' \
  | bash -c 'set -a; [ -f /usf/.env ] && . /usf/.env; set +a; exec /usr/local/bin/node /usf/processes/semantic-assurance/semantic-authority-mcp.mjs' 2>&1)" || true
for tool in usf_health usf_query usf_bootstrap usf_layout_context usf_layout_plan \
  usf_layout_validate usf_materialise usf_artifact_describe usf_artifact_verify \
  usf_contract_project usf_work_plan usf_evidence_admit usf_proof_evaluate \
  usf_validation_record; do
  grep -qF "\"name\":\"$tool\"" <<<"$mcp_out" && ok "tool discoverable: $tool" || bad "tool missing: $tool"
done
grep -qF '"resources":[]' <<<"$mcp_out" && ok "resources/list answered" || bad "resources/list not answered"
grep -qF '"resourceTemplates":[]' <<<"$mcp_out" && ok "resources/templates/list answered" || bad "resources/templates/list not answered"
grep -qF '\"ok\": true' <<<"$mcp_out" && ok "usf_health live against Stardog" || bad "usf_health did not return ok:true"
grep -qF 'refused: mutation keyword' <<<"$mcp_out" && ok "mutation rejected read-only" || bad "mutation was not rejected"
grep -qF 'coordinator-only' <<<"$mcp_out" && ok "lifecycle mutation rejected at MCP boundary" || bad "lifecycle mutation was not rejected"
# Redaction: the live token value must never appear in any output.
tok="$(set -a; . /usf/.env 2>/dev/null; set +a; printf '%s' "${STARDOG_TOKEN:-}")"
leak_check(){ # <label> <text>
  if [ -n "$tok" ] && grep -qF "$tok" <<<"$2"; then bad "credential leaked in $1 output"; else ok "$1 output token-free"; fi
}
leak_check "MCP protocol" "$mcp_out"

# --- shared smoke assertions --------------------------------------------------
check_smoke(){ # <agent-label> <output> <prompt-echoed: 0|1>
  local label="$1" out="$2" echoed="$3"
  if [ "$(grep -c 'SKILL_MISSING' <<<"$out")" -gt "$echoed" ]; then
    bad "$label did not discover the usf skill"
  else
    ok "$label discovered the usf skill"
  fi
  grep -qF '"ok": true' <<<"$out" && ok "$label usf MCP live (usf_health)" || bad "$label usf_health did not return ok:true"
  leak_check "$label" "$out"
}

# --- decisive smoke: headless codex through the required gateway --------------
if [ ! -s "$CODEX_HOME_DIR/auth.json" ]; then
  bad "codex auth unavailable — cannot run the headless smoke (required environment unavailable)"
else
  smoke="$(cd /usf && timeout 300 codex exec --sandbox read-only -c approval_policy=never "$SMOKE_PROMPT" </dev/null 2>&1)" || true
  check_smoke "codex" "$smoke" 1  # codex transcripts echo the prompt once
fi

# --- decisive smoke: headless claude through the required gateway -------------
if [ ! -s "$HOME/.claude/.credentials.json" ]; then
  bad "claude auth unavailable — cannot run the headless smoke (required environment unavailable)"
else
  csmoke="$(cd /usf && timeout 300 claude -p "$SMOKE_PROMPT" \
    --allowedTools "Skill,mcp__usf__usf_health" </dev/null 2>&1)" || true
  check_smoke "claude" "$csmoke" 0  # claude -p prints only the response
fi

[ "$fail" -eq 0 ] || { note "agent verification FAILED"; exit 1; }
echo "USF chroot agent wiring verified (codex + claude x usf)"
