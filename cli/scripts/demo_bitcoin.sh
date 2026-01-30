#!/bin/bash

set -e

# Wait for user confirmation.
pause() { read -p "Press Enter to continue..."; echo; echo; }

# Wait for transaction to be visible in the mempool.
wait_for_transaction() {
  local TXID=$1
  echo "Waiting for transaction to be visible in the mempool..."
  for i in {1..30}; do
    TX_DATA=$(curl -s "https://mempool.space/testnet4/api/tx/$TXID" 2>/dev/null)
    if [ -n "$TX_DATA" ] && [ "$TX_DATA" != "Transaction not found" ]; then
      echo "Transaction found in mempool!"
      return 0
    fi
    sleep 5
  done

  echo "Error: Transaction not found after waiting. Please check the transaction ID and try again."
  exit 1
}

# Simple Simplicity program that always returns true
PROGRAM="zSQIS29W33fvVt9371bfd+9W33fvVt9371bfd+9W33fvVt93hgGA"
WITNESS=""

NETWORK="testnet4"

echo "==== Bitcoin Testnet4 2-of-2 Multisig Demo with Simplicity ===="
echo
echo "This demo will guide you through creating and spending from a"
echo "2-of-2 multisig address where one key is tweaked with a Simplicity program."
echo

echo "==== Step 0: Get Tweaked Public Key for Simplicity Program ===="
TWEAK_REQUEST=$(jq -n --arg program "$PROGRAM" '{program: $program}')

TWEAK_RESPONSE=$(curl -s -X POST http://localhost:30431/simplicity-unchained/tweak \
  -H "Content-Type: application/json" \
  -d "$TWEAK_REQUEST")

# Extract the tweaked public key from the response and set it as COSIGNER_PUBKEY
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

echo "==== Step 2: Create 2-of-2 Multisig Address ===="
ADDRESS_DATA=$(cargo run --quiet -- address multisig --pubkey1 $COSIGNER_PUBKEY --pubkey2 $USER_PUBKEY --network $NETWORK)
ADDRESS=$(echo "$ADDRESS_DATA" | jq -r '.address')
REDEEM_SCRIPT=$(echo "$ADDRESS_DATA" | jq -r '.redeem_script')

echo "Multisig P2WSH address: $ADDRESS"
echo "Redeem script: $REDEEM_SCRIPT"
echo

echo "==== Step 3: Fund the Address ===="
echo "Please send Bitcoin testnet4 coins to the following address:"
echo "$ADDRESS"
echo ""
echo "You can get testnet4 coins from: https://mempool.space/testnet4/faucet"
echo
echo -n "After funding, please paste the funding transaction ID and press Enter: "
read FUNDING_TXID

if [ -z "$FUNDING_TXID" ]; then
  echo "Error: No transaction ID provided. Exiting."
  exit 1
fi

echo
echo "Funding transaction ID: $FUNDING_TXID"
echo

wait_for_transaction "$FUNDING_TXID"
echo

echo "==== Step 4: Create PSBT ===="
PSBT_CREATE_DATA=$(cargo run --quiet -- btc-tx create -i "$FUNDING_TXID:1" -o "$ADDRESS:4000" --network $NETWORK)
PSBT_HEX=$(echo "$PSBT_CREATE_DATA" | jq -r '.psbt')

echo "Created PSBT (unsigned): $PSBT_HEX"
echo

echo "==== Step 5: First Signature (Co-signer) ===="
echo "Calling sign service at http://localhost:30431/simplicity-unchained/sign/psbt..."

SIGN_REQUEST=$(jq -n \
  --arg psbt "$PSBT_HEX" \
  --arg redeem "$REDEEM_SCRIPT" \
  --arg program "$PROGRAM" \
  --arg witness "$WITNESS" \
  '{psbt_hex: $psbt, redeem_script_hex: $redeem, input_index: 0, program: $program, witness: $witness}')

PSBT_SIGN1_DATA=$(curl -s -X POST http://localhost:30431/simplicity-unchained/sign/psbt \
  -H "Content-Type: application/json" \
  -d "$SIGN_REQUEST")

PSBT_SIGNED1=$(echo "$PSBT_SIGN1_DATA" | jq -r '.psbt_hex')

echo "PSBT after first signature: $PSBT_SIGNED1"
echo

echo "==== Step 6: Second Signature (User) ===="
PSBT_SIGN2_DATA=$(cargo run --quiet -- btc-tx sign --psbt "$PSBT_SIGNED1" --secret-key "$USER_SECKEY" --input-index 0 --redeem-script "$REDEEM_SCRIPT")
PSBT_SIGNED2=$(echo "$PSBT_SIGN2_DATA" | jq -r '.psbt')

echo "PSBT after second signature: $PSBT_SIGNED2"
echo

echo "==== Step 7: Finalize PSBT ===="
FINALIZE_DATA=$(cargo run --quiet -- btc-tx finalize --psbt "$PSBT_SIGNED2")
FINAL_TX_HEX=$(echo "$FINALIZE_DATA" | jq -r '.transaction_hex')
TXID=$(echo "$FINALIZE_DATA" | jq -r '.txid')

echo "Finalized transaction hex: $FINAL_TX_HEX"
echo

echo "==== Step 8: Broadcast Transaction ===="
echo "Submitting raw transaction via Bitcoin Testnet4 API..."
echo -n "Resulting transaction ID is "
BROADCAST_TXID=$(curl -X POST "https://mempool.space/testnet4/api/tx" -d "$FINAL_TX_HEX" 2>/dev/null)
echo "$BROADCAST_TXID"
echo
echo "You can view it online at https://mempool.space/testnet4/tx/$BROADCAST_TXID"

echo
echo "==== Demo Complete! ===="
echo "Successfully created and spent from a 2-of-2 multisig with Simplicity program!"
echo
