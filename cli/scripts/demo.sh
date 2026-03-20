#!/bin/bash

set -e

# Usage: ./scripts/demo.sh [p2wsh|p2sh|p2tr]
SPEND_TYPE="${1:-p2wsh}"

case "$SPEND_TYPE" in
  p2wsh|p2sh|p2tr) ;;
  *)
    echo "Error: unsupported spend type '$SPEND_TYPE'"
    echo "Usage: $0 [p2wsh|p2sh|p2tr]"
    exit 1
    ;;
esac

echo "==== Spend type: $SPEND_TYPE ===="
echo

# Wait for user confirmation.
pause() { read -p "Press Enter to continue..."; echo; echo; }

# Wait for transaction to be visible in the mempool.
wait_for_transaction() {
  local TXID=$1
  echo "Waiting for transaction to be visible in the mempool..."
  for i in {1..30}; do
    TX_DATA=$(curl -s "https://blockstream.info/liquidtestnet/api/tx/$TXID" 2>/dev/null)
    if [ -n "$TX_DATA" ] && [ "$TX_DATA" != "Transaction not found" ]; then

      # For some unfathomable reason, the next call can sometimes return 404, like, how is that even possible?
      sleep 10

      echo "Transaction found in mempool!"
      return 0
    fi
    sleep 5
  done

  echo "Error: Transaction not found after waiting. Please try again."
  exit 1
}

# Simple Simplicity program that always returns true
PROGRAM="zSQIS29W33fvVt9371bfd+9W33fvVt9371bfd+9W33fvVt93hgGA"
WITNESS=""

NETWORK="liquid_testnet"
KEYPAIR_FILE=".keypair.json"

echo "==== Step 0: Get Tweaked Public Key for Simplicity Program ===="
TWEAK_REQUEST=$(jq -n --arg program "$PROGRAM" '{program: $program}')

TWEAK_RESPONSE=$(curl -s -X POST http://localhost:30431/simplicity-unchained/tweak \
  -H "Content-Type: application/json" \
  -d "$TWEAK_REQUEST")

COSIGNER_PUBKEY=$(echo "$TWEAK_RESPONSE" | jq -r '.tweaked_public_key_hex')
echo "Tweaked public key (Co-signer): $COSIGNER_PUBKEY"
echo

echo "==== Step 1: Generate User Keypair ===="
USER_KEYPAIR=$(cargo run --quiet keypair generate)
USER_SECKEY=$(echo "$USER_KEYPAIR" | jq -r '.secret_key')
USER_PUBKEY=$(echo "$USER_KEYPAIR" | jq -r '.public_key')

echo "User secret key: $USER_SECKEY"
echo "User public key: $USER_PUBKEY"
echo

echo "==== Step 2: Create Address ===="
case "$SPEND_TYPE" in
  p2wsh)
    ADDRESS_DATA=$(cargo run --quiet -- address multisig \
      --pubkey1 $COSIGNER_PUBKEY \
      --pubkey2 $USER_PUBKEY \
      --network $NETWORK \
      --type p2wsh)
    REDEEM_SCRIPT=$(echo "$ADDRESS_DATA" | jq -r '.redeem_script')
    echo "Redeem script: $REDEEM_SCRIPT"
    ;;
  p2sh)
    ADDRESS_DATA=$(cargo run --quiet -- address multisig \
      --pubkey1 $COSIGNER_PUBKEY \
      --pubkey2 $USER_PUBKEY \
      --network $NETWORK \
      --type p2sh)
    REDEEM_SCRIPT=$(echo "$ADDRESS_DATA" | jq -r '.redeem_script')
    echo "Redeem script: $REDEEM_SCRIPT"
    ;;
  p2tr)
    ADDRESS_DATA=$(cargo run --quiet -- address p2tr \
      --pubkey $COSIGNER_PUBKEY \
      --network $NETWORK)
    REDEEM_SCRIPT=""
    ;;
esac

ADDRESS=$(echo "$ADDRESS_DATA" | jq -r '.address')
echo "Address ($SPEND_TYPE): $ADDRESS"
echo

echo "==== Step 3: Fund Address from Faucet ===="
echo "Running curl to connect to Liquid Testnet faucet..."
FAUCET_TRANSACTION=$(curl "https://liquidtestnet.com/faucet?address=$ADDRESS&action=lbtc" 2>/dev/null | sed -n "s/.*with transaction \([0-9a-f]*\)\..*$/\1/p")

echo "Faucet transaction ID: $FAUCET_TRANSACTION"
echo

wait_for_transaction "$FAUCET_TRANSACTION"
echo

echo "==== Step 4: Create PSET ===="
PSET_CREATE_DATA=$(cargo run --quiet -- tx create \
  -i "$FAUCET_TRANSACTION:0" \
  -o "$ADDRESS:99000" \
  -o "fee:1000" \
  --network $NETWORK)
PSET_HEX=$(echo "$PSET_CREATE_DATA" | jq -r '.pset')

echo "Created PSET (unsigned): $PSET_HEX"
echo

echo "==== Step 5: First Signature (Co-signer) ===="
echo "Calling sign service at http://localhost:30431/simplicity-unchained/sign/pset..."

SIGN_REQUEST=$(jq -n \
  --arg pset "$PSET_HEX" \
  --arg redeem "$REDEEM_SCRIPT" \
  --arg program "$PROGRAM" \
  --arg witness "$WITNESS" \
  '{pset_hex: $pset, redeem_script_hex: $redeem, input_index: 0, program: $program, witness: $witness}')

PSET_SIGN1_DATA=$(curl -s -X POST http://localhost:30431/simplicity-unchained/sign/pset \
  -H "Content-Type: application/json" \
  -d "$SIGN_REQUEST")

PSET_SIGNED1=$(echo "$PSET_SIGN1_DATA" | jq -r '.pset_hex')
COSIGNER_SIG=$(echo "$PSET_SIGN1_DATA" | jq -r '.signature_hex')
COSIGNER_PUBKEY_RETURNED=$(echo "$PSET_SIGN1_DATA" | jq -r '.public_key_hex')

echo "PSET after first signature: $PSET_SIGNED1"
echo "Cosigner signature:         $COSIGNER_SIG"
echo "Cosigner pubkey returned:   $COSIGNER_PUBKEY_RETURNED"
echo

# P2TR key-path spend only needs one signature
if [ "$SPEND_TYPE" = "p2tr" ]; then
  echo "==== Step 6: Skipped (P2TR key-path requires only co-signer signature) ===="
  PSET_SIGNED2=$PSET_SIGNED1
else
  echo "==== Step 6: Second Signature (User) ===="
  PSET_SIGN2_DATA=$(cargo run --quiet -- tx sign \
    --pset "$PSET_SIGNED1" \
    --secret-key "$USER_SECKEY" \
    --input-index 0 \
    --redeem-script "$REDEEM_SCRIPT")
  PSET_SIGNED2=$(echo "$PSET_SIGN2_DATA" | jq -r '.pset')
  echo "PSET after second signature: $PSET_SIGNED2"
  echo
fi

echo "==== Step 7: Finalize PSET ===="
FINALIZE_DATA=$(cargo run --quiet -- tx finalize --pset "$PSET_SIGNED2")
FINAL_TX_HEX=$(echo "$FINALIZE_DATA" | jq -r '.transaction_hex')
TXID=$(echo "$FINALIZE_DATA" | jq -r '.txid')

echo "Finalized transaction hex: $FINAL_TX_HEX"
echo

echo "Submitting raw transaction via Liquid Testnet web API..."
echo -n "Resulting transaction ID is "
TXID=$(curl -X POST "https://blockstream.info/liquidtestnet/api/tx" -d "$FINAL_TX_HEX" 2>/dev/null)
echo "$TXID"
echo
echo "You can view it online at https://blockstream.info/liquidtestnet/tx/$TXID?expand"
echo