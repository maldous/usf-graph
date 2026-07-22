#!/usr/bin/env bash
# Run the mechanically bounded SAFE_ADAPTIVE_EXECUTION envelope.
set -Eeuo pipefail

repo=/root/usf-factory
authorization=${USF_FACTORY_SAFE_AUTHORIZATION:-/root/.config/usf-factory/safe-adaptive-authorization.json}
credential_file=${USF_FACTORY_ENV_FILE:-/root/.config/usf-factory/safe-empty.env}
policy=${USF_FACTORY_SAFE_WORKFORCE_POLICY:-${repo}/config/safe-adaptive-execution.yaml}

command -v jq >/dev/null 2>&1 || {
  printf 'SAFE_ADAPTIVE_EXECUTION prerequisite missing: jq\n' >&2
  exit 2
}
for path in "${authorization}" "${credential_file}" "${policy}"; do
  [[ -f "${path}" && ! -L "${path}" ]] || {
    printf 'SAFE_ADAPTIVE_EXECUTION regular file missing: %s\n' "${path}" >&2
    exit 2
  }
done

auth_mode=$(stat -c '%a' "${authorization}")
credential_mode=$(stat -c '%a' "${credential_file}")
[[ "${auth_mode}" == 600 || "${auth_mode}" == 400 ]] || {
  printf 'RunAuthorization must be owner-only (0600/0400)\n' >&2
  exit 2
}
[[ "${credential_mode}" == 600 || "${credential_mode}" == 400 ]] || {
  printf 'safe credential file must be owner-only (0600/0400)\n' >&2
  exit 2
}

# Fail closed unless this is a zero-side-effect, zero-paid-budget grant. Packet
# and cycle limits are work-volume authorization bounds, not concurrency inputs.
jq -e '
  (.paid_api_budget_usd == 0) and
  (.permitted_actions == []) and
  (.max_branch_pushes == 0) and
  (.max_pr_creations == 0) and
  (.max_pr_merges == 0) and
  (.max_authority_publications == 0) and
  (.raw_source_provider == null) and
  (.allow_subscription_inference == true) and
  (.max_packets_per_wave >= 1) and
  (.max_continuous_cycles >= 1)
' "${authorization}" >/dev/null || {
  printf 'RunAuthorization exceeds SAFE_ADAPTIVE_EXECUTION envelope\n' >&2
  exit 2
}

max_packets=$(jq -er '.max_packets_per_wave' "${authorization}")
max_cycles=$(jq -er '.max_continuous_cycles' "${authorization}")

export USF_FACTORY_ENV_FILE="${credential_file}"
export HOME=/root
export PATH=/root/usf-factory/.venv/bin:/root/.local/bin:/usr/local/bin:/usr/bin:/bin

exec "${repo}/.venv/bin/usf-factory" realize \
  --mode shadow \
  --continuous \
  --authorization-file "${authorization}" \
  --workforce-policy "${policy}" \
  --allow-subscription-inference \
  --max-paid-cost-usd 0 \
  --max-packets-per-wave "${max_packets}" \
  --max-cycles "${max_cycles}"
