#!/bin/bash

set -e

# Funds a P2TR address where Leaf 1 is a CSV recovery script,
# then spends it via the user leaf after the timelock.

PROGRAM="zSQIS29W33fvVt9371bfd+9W33fvVt9371bfd+9W33fvVt93hgGA"
SIMPLICITY_WITNESS=""
NETWORK="liquid_testnet"
CSV_BLOCKS=3

# Wait for transaction to be visible in the mempool.
wait_for_transaction() {
  local TXID=$1
  echo "Waiting for transaction to be visible in the mempool..."
  for i in {1..30}; do
    TX_DATA=$(curl -s "https://blockstream.info/liquidtestnet/api/tx/$TXID" 2>/dev/null)
    if [ -n "$TX_DATA" ] && [ "$TX_DATA" != "Transaction not found" ]; then
      sleep 10
      echo "Transaction found in mempool!"
      return 0
    fi
    sleep 5
  done
  echo "Error: Transaction not found after waiting. Please try again."
  exit 1
}

echo "==== Sanity checks ===="
if ! command -v curl &> /dev/null; then
  echo "ERROR: curl not found in PATH"
  exit 1
fi
echo "OK"
echo

echo "==== Step 0: Get Tweaked Cosigner Pubkey ===="
TWEAK_RESPONSE=$(curl -s -X POST http://localhost:30431/simplicity-unchained/tweak \
  -H "Content-Type: application/json" \
  -d "$(jq -n --arg program "$PROGRAM" '{program: $program, jet_env: "elements"}')")
COSIGNER_PUBKEY=$(echo "$TWEAK_RESPONSE" | jq -r '.tweaked_public_key_hex')
[ -z "$COSIGNER_PUBKEY" ] || [ "$COSIGNER_PUBKEY" = "null" ] && { echo "ERROR: $TWEAK_RESPONSE"; exit 1; }
echo "Cosigner pubkey: $COSIGNER_PUBKEY"
echo

echo "==== Step 1: Generate User Keypair ===="
USER_KEYPAIR=$(cargo run --quiet -- keypair generate)
USER_SECKEY=$(echo "$USER_KEYPAIR" | jq -r '.secret_key')
USER_PUBKEY=$(echo "$USER_KEYPAIR" | jq -r '.public_key')
echo "User pubkey: $USER_PUBKEY"
echo

echo "==== Step 2: Build CSV Recovery Leaf Script ===="
LEAF_DATA=$(cargo run --quiet -- tx build-csv-leaf \
  --user-pubkey "$USER_PUBKEY" \
  --timelock "$CSV_BLOCKS")
USER_LEAF_SCRIPT=$(echo "$LEAF_DATA" | jq -r '.script')
USER_LEAF_HASH=$(echo "$LEAF_DATA" | jq -r '.leaf_hash')
echo "User leaf hash: $USER_LEAF_HASH"
echo

echo "==== Step 3: Create P2TR Address ===="
ADDRESS_DATA=$(cargo run --quiet -- address multisig \
  --pubkey1 "$COSIGNER_PUBKEY" \
  --pubkey2 "$USER_PUBKEY" \
  --user-leaf-hash "$USER_LEAF_HASH" \
  --network "$NETWORK")
ADDRESS=$(echo "$ADDRESS_DATA" | jq -r '.address')
[ -z "$ADDRESS" ] || [ "$ADDRESS" = "null" ] && { echo "ERROR: $ADDRESS_DATA"; exit 1; }
echo "Address: $ADDRESS"
echo

echo "==== Step 4: Fund Address from Faucet ===="
echo "Running curl to connect to Liquid Testnet faucet..."
FAUCET_TRANSACTION=$(curl "https://liquidtestnet.com/faucet?address=$ADDRESS&action=lbtc" 2>/dev/null \
  | sed -n "s/.*with transaction \([0-9a-f]*\)\..*$/\1/p")
echo "Faucet transaction ID: $FAUCET_TRANSACTION"
echo

wait_for_transaction "$FAUCET_TRANSACTION"
echo

echo "==== Step 5: Create PSET (with CSV sequence) ===="
PSET_DATA=$(cargo run --quiet -- tx create \
  -i "$FAUCET_TRANSACTION:0" \
  -o "$ADDRESS:99000" \
  -o "fee:1000" \
  --network "$NETWORK" \
  --sequence "$CSV_BLOCKS")
PSET_HEX=$(echo "$PSET_DATA" | jq -r '.pset')
echo "PSET: $PSET_HEX"
echo

echo "==== Step 6: Wait for CSV timelock ===="
echo "Liquid Testnet produces blocks automatically — waiting for $CSV_BLOCKS blocks..."
echo "Check https://blockstream.info/liquidtestnet/ for block progress."
echo "Sleeping 3 minutes to allow blocks to pass..."
sleep 200 # just to be sure
echo "Done waiting"
echo

echo "==== Step 7: User Signs Leaf 1 (CSV recovery) ===="
PSET_SIGN_DATA=$(cargo run --quiet -- tx spend-user-leaf \
  --psbt "$PSET_HEX" \
  --secret-key "$USER_SECKEY" \
  --user-leaf-script "$USER_LEAF_SCRIPT" \
  --cosigner-pubkey "$COSIGNER_PUBKEY" \
  --input-index 0 \
  --network "$NETWORK")
PSET_SIGNED=$(echo "$PSET_SIGN_DATA" | jq -r '.pset')
echo "Signed"
echo

echo "==== Step 8: Finalize (user leaf) ===="
FINALIZE_DATA=$(cargo run --quiet -- tx finalize-user-leaf --psbt "$PSET_SIGNED")
FINAL_TX_HEX=$(echo "$FINALIZE_DATA" | jq -r '.transaction_hex')
echo "TXID: $(echo "$FINALIZE_DATA" | jq -r '.txid')"
echo

echo "==== Step 9: Broadcast ===="
echo -n "Resulting transaction ID is "
TXID=$(curl -s -X POST "https://blockstream.info/liquidtestnet/api/tx" -d "$FINAL_TX_HEX" 2>/dev/null)
echo "$TXID"
echo
echo "You can view it online at https://blockstream.info/liquidtestnet/tx/$TXID?expand"