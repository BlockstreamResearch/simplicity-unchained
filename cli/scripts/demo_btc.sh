#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Bitcoin policy-v1 demo (experimental; Bitcoin Testnet4 by default)
Usage: ./cli/scripts/demo_btc.sh [address|review|sign|--help]

Required environment:
  POLICY_PROGRAM_BASE64       Reviewed bitcoin-policy-v1 program, not legacy bytes
  BASE_SERVICE_PUBLIC_KEY_HEX Independently known untweaked service key
  USER_PUBLIC_KEY_HEX         Cooperative user public key
  RECOVERY_LEAF_HASH_HEX      Exact raw recovery TapNodeHash
  PSBT_HEX                   Required for review/sign; one input, full parents
  APPROVAL_WITNESS_BASE64     Required for review/sign; set '' if witness-free
  USER_SECRET_KEY_FILE        Required for sign; private file of user key hex

Optional:
  SERVICE_ORIGIN             Default http://127.0.0.1:30431
  NETWORK                    Default testnet4; must exactly match the service
  REDEEM_SCRIPT_HEX          Default empty; exact committed script-data bytes
  ESPLORA_URL                Explicit parent resolver; default strictly offline

address verifies capabilities/tweak before deriving funding data.
review (default) prepares/evaluates only; it never requests a signature.
sign revalidates a pre-reviewed PSBT/witness, co-signs and finalizes locally.
No faucet, broadcast, recovery spend, legacy endpoint or automatic signing retry.
For multi-input spends use the policy CLI directly.
EOF
}

mode="${1:-review}"
case "$mode" in
  -h|--help|help) usage; exit 0 ;;
  address|review|sign) ;;
  *) usage >&2; exit 2 ;;
esac
if [[ $# -gt 1 ]]; then
  usage >&2
  exit 2
fi

command -v cargo >/dev/null
command -v jq >/dev/null
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
su=(cargo run --quiet --locked -p cli -- policy)
service="${SERVICE_ORIGIN:-http://127.0.0.1:30431}"
network="${NETWORK:-testnet4}"
: "${POLICY_PROGRAM_BASE64:?Set a reviewed policy-profile program}"
: "${BASE_SERVICE_PUBLIC_KEY_HEX:?Pin the known untweaked service key}"
: "${USER_PUBLIC_KEY_HEX:?Set the cooperative user key}"
: "${RECOVERY_LEAF_HASH_HEX:?Set the committed raw recovery hash}"

policy_args=(
  --network "$network" --program "$POLICY_PROGRAM_BASE64"
  --redeem-script-hex "${REDEEM_SCRIPT_HEX:-}"
)
binding_args=(
  "${policy_args[@]}"
  --base-public-key "$BASE_SERVICE_PUBLIC_KEY_HEX"
  --user-pubkey "$USER_PUBLIC_KEY_HEX"
  --user-leaf-hash-hex "$RECOVERY_LEAF_HASH_HEX"
)

if [[ "$mode" == address ]]; then
  "${su[@]}" capabilities --network "$network" --service "$service" >&2
  "${su[@]}" tweak "${policy_args[@]}" \
    --base-public-key "$BASE_SERVICE_PUBLIC_KEY_HEX" --service "$service" >&2
  "${su[@]}" address "${binding_args[@]}"
  exit 0
fi

: "${PSBT_HEX:?Supply an already constructed, pre-reviewed policy PSBT}"
if [[ ! ${APPROVAL_WITNESS_BASE64+x} ]]; then
  echo "Set APPROVAL_WITNESS_BASE64 explicitly (empty only for witness-free policies)" >&2
  exit 2
fi
resolver=(--offline)
if [[ -n "${ESPLORA_URL:-}" ]]; then
  resolver=(--esplora-url "$ESPLORA_URL")
fi
tx_args=("${binding_args[@]}" --psbt "$PSBT_HEX" --input-index 0 "${resolver[@]}")
prepared=$("${su[@]}" prepare "${tx_args[@]}" --service "$service")
echo "$prepared" >&2
if [[ "$(jq -er '.context.input_count' <<<"$prepared")" != 1 ]]; then
  echo "Demo requires exactly one input; use the policy CLI for multiple inputs" >&2
  exit 2
fi
"${su[@]}" approval-hash "${tx_args[@]}" >&2
"${su[@]}" evaluate "${tx_args[@]}" --witness "$APPROVAL_WITNESS_BASE64" \
  --service "$service" >&2
if [[ "$mode" == review ]]; then
  echo "$prepared"
  exit 0
fi

: "${USER_SECRET_KEY_FILE:?Provide a private file containing the user secret key hex}"
signed=$("${su[@]}" sign "${tx_args[@]}" --witness "$APPROVAL_WITNESS_BASE64" \
  --service "$service")
psbt=$(jq -er '.psbt_hex' <<<"$signed")
tx_args=("${binding_args[@]}" --psbt "$psbt" --input-index 0 "${resolver[@]}")
user_signed=$("${su[@]}" user-sign "${tx_args[@]}" --secret-key-file "$USER_SECRET_KEY_FILE")
psbt=$(jq -er '.psbt_hex' <<<"$user_signed")
tx_args=("${binding_args[@]}" --psbt "$psbt" --input-index 0 "${resolver[@]}")
"${su[@]}" finalize "${tx_args[@]}"
