#!/bin/bash

set -e

# Usage: ./scripts/demo_bitcoin.sh [p2wsh|p2sh|p2tr]
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

echo "==== Sanity Check: bitcoin-cli available? ===="
if ! command -v bitcoin-cli &> /dev/null; then
  echo "ERROR: bitcoin-cli not found in PATH"
  exit 1
fi
echo "OK: bitcoin-cli found at $(which bitcoin-cli)"

BTC="bitcoin-cli -regtest"

# Simple Simplicity program that always returns true
PROGRAM="zSQIS29W33fvVt9371bfd+9W33fvVt9371bfd+9W33fvVt93hgGA"
WITNESS=""
NETWORK="regtest"

echo "==== Sanity Check: Bitcoin Core running? ===="
if ! $BTC getblockchaininfo > /dev/null 2>&1; then
  echo "ERROR: Bitcoin Core is not running."
  echo "Start it with: bitcoind -regtest -daemon"
  exit 1
fi
echo "OK"
echo

echo "==== Setup: Ensure wallet has funds ===="
$BTC createwallet "demo" > /dev/null 2>&1 || true
MINER_ADDR=$($BTC getnewaddress)
BAL=$($BTC getbalance)
if (( $(echo "$BAL < 1.0" | bc -l) )); then
  echo "Mining initial coins..."
  $BTC generatetoaddress 101 "$MINER_ADDR" > /dev/null
fi
echo "Wallet balance: $($BTC getbalance) BTC"
echo

echo "==== Step 0: Get Tweaked Public Key ===="
TWEAK_RESPONSE=$(curl -s -X POST http://localhost:30431/simplicity-unchained/tweak \
  -H "Content-Type: application/json" \
  -d "$(jq -n --arg program "$PROGRAM" '{program: $program, jet_env: "bitcoin"}')")

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

echo "==== Step 2: Create Address ===="
case "$SPEND_TYPE" in
  p2tr)
    ADDRESS_DATA=$(cargo run --quiet -- address p2tr \
      --pubkey $COSIGNER_PUBKEY \
      --network $NETWORK)
    REDEEM_SCRIPT=""
    ;;
  *)
    ADDRESS_DATA=$(cargo run --quiet -- address multisig \
      --pubkey1 $COSIGNER_PUBKEY \
      --pubkey2 $USER_PUBKEY \
      --network $NETWORK \
      --type $SPEND_TYPE)
    REDEEM_SCRIPT=$(echo "$ADDRESS_DATA" | jq -r '.redeem_script')
    echo "Redeem script: $REDEEM_SCRIPT"
    ;;
esac

ADDRESS=$(echo "$ADDRESS_DATA" | jq -r '.address')
echo "Address ($SPEND_TYPE): $ADDRESS"
echo

echo "==== Step 3: Fund Address ===="
FUNDING_TXID=$($BTC sendtoaddress "$ADDRESS" 0.001)
echo "Funding txid: $FUNDING_TXID"
$BTC generatetoaddress 1 "$MINER_ADDR" > /dev/null
echo "Confirmed"
echo

VOUT=$($BTC gettransaction "$FUNDING_TXID" | jq '.details[0].vout')
echo "Output index: $VOUT"
echo

echo "==== Step 4: Create PSBT ===="
PSBT_CREATE_DATA=$(cargo run --quiet -- btc-tx create \
  -i "$FUNDING_TXID:$VOUT" \
  -o "$ADDRESS:90000" \
  --network $NETWORK)

PSBT_HEX=$(echo "$PSBT_CREATE_DATA" | jq -r '.psbt')
echo "Created PSBT: $PSBT_HEX"
echo

echo "==== Step 5: First Signature (Co-signer) ===="
case "$SPEND_TYPE" in
  p2tr)
    SIGN_REQUEST=$(jq -n \
      --arg psbt "$PSBT_HEX" \
      --arg program "$PROGRAM" \
      --arg witness "$WITNESS" \
      '{psbt_hex: $psbt, input_index: 0, program: $program, witness: $witness, jet_env: "bitcoin"}')
    ;;
  *)
    SIGN_REQUEST=$(jq -n \
      --arg psbt "$PSBT_HEX" \
      --arg redeem "$REDEEM_SCRIPT" \
      --arg program "$PROGRAM" \
      --arg witness "$WITNESS" \
      '{psbt_hex: $psbt, redeem_script_hex: $redeem, input_index: 0, program: $program, witness: $witness, jet_env: "bitcoin"}')
    ;;
esac

PSBT_SIGN1_DATA=$(curl -s -X POST http://localhost:30431/simplicity-unchained/sign/psbt \
  -H "Content-Type: application/json" \
  -d "$SIGN_REQUEST")

if echo "$PSBT_SIGN1_DATA" | jq -e '.error' > /dev/null 2>&1; then
  echo "ERROR from sign service: $(echo "$PSBT_SIGN1_DATA" | jq -r '.error')"
  exit 1
fi

PSBT_SIGNED1=$(echo "$PSBT_SIGN1_DATA" | jq -r '.psbt_hex')
if [ "$PSBT_SIGNED1" = "null" ] || [ -z "$PSBT_SIGNED1" ]; then
  echo "ERROR: sign service returned null psbt_hex"
  echo "Response: $PSBT_SIGN1_DATA"
  exit 1
fi

echo "Cosigner signature: $(echo "$PSBT_SIGN1_DATA" | jq -r '.signature_hex')"
echo

if [ "$SPEND_TYPE" = "p2tr" ]; then
  echo "==== Step 6: Skipped (P2TR key-path requires only co-signer signature) ===="
  PSBT_SIGNED2=$PSBT_SIGNED1
else
  echo "==== Step 6: Second Signature (User) ===="
  PSBT_SIGN2_DATA=$(cargo run --quiet -- btc-tx sign \
    --psbt "$PSBT_SIGNED1" \
    --secret-key "$USER_SECKEY" \
    --input-index 0 \
    --redeem-script "$REDEEM_SCRIPT")

  PSBT_SIGNED2=$(echo "$PSBT_SIGN2_DATA" | jq -r '.psbt')
  echo "User signature added"
  echo
fi

echo "==== Step 7: Finalize PSBT ===="
FINALIZE_DATA=$(cargo run --quiet -- btc-tx finalize --psbt "$PSBT_SIGNED2")
FINAL_TX_HEX=$(echo "$FINALIZE_DATA" | jq -r '.transaction_hex')
TXID=$(echo "$FINALIZE_DATA" | jq -r '.txid')
echo "Transaction hex: $FINAL_TX_HEX"
echo

echo "==== Step 8: Broadcast ===="
BROADCAST_TXID=$($BTC sendrawtransaction "$FINAL_TX_HEX")
$BTC generatetoaddress 1 "$MINER_ADDR" > /dev/null
echo "Done! TXID: $BROADCAST_TXID"