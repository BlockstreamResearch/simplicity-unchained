#!/bin/bash

set -e

echo "==== Spend type: P2TR ===="
echo

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

PROGRAM="zSQIS29W33fvVt9371bfd+9W33fvVt9371bfd+9W33fvVt93hgGA"
SIMPLICITY_WITNESS=""
NETWORK="liquid_testnet"
CSV_BLOCKS=10

echo "==== Sanity checks ===="
if ! command -v curl &> /dev/null; then
  echo "ERROR: curl not found in PATH"
  exit 1
fi
echo "OK"
echo

echo "==== Step 0: Get Tweaked Cosigner Public Key ===="
TWEAK_RESPONSE=$(curl -s -X POST http://localhost:30431/simplicity-unchained/tweak \
  -H "Content-Type: application/json" \
  -d "$(jq -n --arg program "$PROGRAM" '{program: $program, jet_env: "elements"}')")

COSIGNER_PUBKEY=$(echo "$TWEAK_RESPONSE" | jq -r '.tweaked_public_key_hex')
if [ -z "$COSIGNER_PUBKEY" ] || [ "$COSIGNER_PUBKEY" = "null" ]; then
  echo "ERROR: Failed to get tweaked public key"
  echo "Response: $TWEAK_RESPONSE"
  exit 1
fi
echo "Cosigner pubkey: $COSIGNER_PUBKEY"
echo

echo "==== Step 1: Generate User Keypair ===="
USER_KEYPAIR=$(cargo run --quiet -- keypair generate)
USER_SECKEY=$(echo "$USER_KEYPAIR" | jq -r '.secret_key')
USER_PUBKEY=$(echo "$USER_KEYPAIR" | jq -r '.public_key')
echo "User public key: $USER_PUBKEY"
echo

echo "==== Step 2: Build User Leaf (CSV recovery) ===="
LEAF_DATA=$(cargo run --quiet -- tx build-csv-leaf \
  --user-pubkey "$USER_PUBKEY" \
  --timelock "$CSV_BLOCKS")
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
if [ -z "$ADDRESS" ] || [ "$ADDRESS" = "null" ]; then
  echo "ERROR: Failed to generate address"
  echo "Response: $ADDRESS_DATA"
  exit 1
fi
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

echo "==== Step 5: Create PSET ===="
PSET_CREATE_DATA=$(cargo run --quiet -- tx create \
  -i "$FAUCET_TRANSACTION:0" \
  -o "$ADDRESS:99000" \
  -o "fee:1000" \
  --network "$NETWORK")
PSET_HEX=$(echo "$PSET_CREATE_DATA" | jq -r '.pset')
echo "Created PSET: $PSET_HEX"
echo

echo "==== Step 6: Cosigner Signature (Service) ===="
SIGN_REQUEST=$(jq -n \
  --arg pset "$PSET_HEX" \
  --arg program "$PROGRAM" \
  --arg witness "$SIMPLICITY_WITNESS" \
  --arg user_pubkey "$USER_PUBKEY" \
  --arg user_leaf_hash "$USER_LEAF_HASH" \
  '{
    pset_hex: $pset,
    input_index: 0,
    program: $program,
    witness: $witness,
    jet_env: "elements",
    user_pubkey: $user_pubkey,
    user_leaf_hash_hex: $user_leaf_hash
  }')

PSET_SIGN1_DATA=$(curl -s -X POST http://localhost:30431/simplicity-unchained/sign/pset \
  -H "Content-Type: application/json" \
  -d "$SIGN_REQUEST")

if echo "$PSET_SIGN1_DATA" | jq -e '.error' > /dev/null 2>&1; then
  echo "ERROR from sign service: $(echo "$PSET_SIGN1_DATA" | jq -r '.error')"
  exit 1
fi

PSET_SIGNED1=$(echo "$PSET_SIGN1_DATA" | jq -r '.pset_hex')
echo "Cosigner signature: $(echo "$PSET_SIGN1_DATA" | jq -r '.signature_hex')"
echo

echo "==== Step 7: User Signature ===="
PSET_SIGN2_DATA=$(cargo run --quiet -- tx sign \
  --pset "$PSET_SIGNED1" \
  --secret-key "$USER_SECKEY" \
  --input-index 0 \
  --cosigner-pubkey "$COSIGNER_PUBKEY" \
  --user-leaf-hash "$USER_LEAF_HASH")

PSET_SIGNED2=$(echo "$PSET_SIGN2_DATA" | jq -r '.pset')
echo "User signature added"
echo

echo "==== Step 8: Finalize ===="
FINALIZE_DATA=$(cargo run --quiet -- tx finalize --pset "$PSET_SIGNED2")
FINAL_TX_HEX=$(echo "$FINALIZE_DATA" | jq -r '.transaction_hex')
echo "TXID: $(echo "$FINALIZE_DATA" | jq -r '.txid')"
echo

echo "==== Step 9: Broadcast ===="
echo -n "Resulting transaction ID is "
TXID=$(curl -s -X POST "https://blockstream.info/liquidtestnet/api/tx" -d "$FINAL_TX_HEX" 2>/dev/null)
echo "$TXID"
echo
echo "You can view it online at https://blockstream.info/liquidtestnet/tx/$TXID?expand"