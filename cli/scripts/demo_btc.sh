#!/bin/bash

set -e

echo "==== Spend type: P2TR ===="
echo

BTC="bitcoin-cli -regtest"
PROGRAM="zSQIS29W33fvVt9371bfd+9W33fvVt9371bfd+9W33fvVt93hgGA"
SIMPLICITY_WITNESS=""
NETWORK="regtest"
CSV_BLOCKS=10

echo "==== Sanity checks ===="
if ! command -v bitcoin-cli &> /dev/null; then
  echo "ERROR: bitcoin-cli not found in PATH"
  exit 1
fi

if ! $BTC getblockchaininfo > /dev/null 2>&1; then
  echo "ERROR: bitcoind is not running or not reachable."
  echo "Start it with:"
  echo "  bitcoind -regtest -fallbackfee=0.0002 -txindex=1 -daemon"
  echo "  bitcoin-cli -regtest loadwallet <wallet>"
  exit 1
fi

echo "OK — bitcoind running"
echo

echo "==== Setup: Ensure wallet has funds ===="
MINER_ADDR=$($BTC getnewaddress)
BAL=$($BTC getbalance)
if (( $(echo "$BAL < 1.0" | bc -l) )); then
  echo "Mining initial coins..."
  $BTC generatetoaddress 101 "$MINER_ADDR" > /dev/null
fi
echo "Wallet balance: $($BTC getbalance) BTC"
echo

echo "==== Step 0: Get Tweaked Cosigner Public Key ===="
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

echo "==== Step 2: Build User Leaf (CSV recovery) ===="
cargo run --quiet -- btc-tx build-csv-leaf --user-pubkey "$USER_PUBKEY" --timelock "$CSV_BLOCKS"
LEAF_DATA=$(cargo run --quiet -- btc-tx build-csv-leaf \
  --user-pubkey "$USER_PUBKEY" \
  --timelock "$CSV_BLOCKS")
USER_LEAF_HASH=$(echo "$LEAF_DATA" | jq -r '.leaf_hash')
echo "User leaf hash:   $USER_LEAF_HASH"
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

echo "==== Step 4: Fund Address ===="
FUNDING_TXID=$($BTC sendtoaddress "$ADDRESS" 0.001)
$BTC generatetoaddress 1 "$MINER_ADDR" > /dev/null
echo "Funding txid: $FUNDING_TXID (confirmed)"
VOUT=$($BTC gettransaction "$FUNDING_TXID" | jq '.details[0].vout')
echo "Output index: $VOUT"
echo

echo "==== Step 5: Create PSBT ===="
PSBT_CREATE_DATA=$(cargo run --quiet -- btc-tx create \
  -i "$FUNDING_TXID:$VOUT" \
  -o "$ADDRESS:90000" \
  --network "$NETWORK")
PSBT_HEX=$(echo "$PSBT_CREATE_DATA" | jq -r '.psbt')
echo "Created PSBT: $PSBT_HEX"
echo

echo "==== Step 6: Cosigner Signature (Service) ===="
SIGN_REQUEST=$(jq -n \
  --arg psbt "$PSBT_HEX" \
  --arg program "$PROGRAM" \
  --arg witness "$SIMPLICITY_WITNESS" \
  --arg user_pubkey "$USER_PUBKEY" \
  --arg user_leaf_hash "$USER_LEAF_HASH" \
  '{
    psbt_hex: $psbt,
    input_index: 0,
    program: $program,
    witness: $witness,
    jet_env: "bitcoin",
    user_pubkey: $user_pubkey,
    user_leaf_hash_hex: $user_leaf_hash
  }')

PSBT_SIGN1_DATA=$(curl -s -X POST http://localhost:30431/simplicity-unchained/sign/psbt \
  -H "Content-Type: application/json" \
  -d "$SIGN_REQUEST")

if echo "$PSBT_SIGN1_DATA" | jq -e '.error' > /dev/null 2>&1; then
  echo "ERROR from sign service: $(echo "$PSBT_SIGN1_DATA" | jq -r '.error')"
  exit 1
fi

PSBT_SIGNED1=$(echo "$PSBT_SIGN1_DATA" | jq -r '.psbt_hex')
echo "Cosigner signature: $(echo "$PSBT_SIGN1_DATA" | jq -r '.signature_hex')"
echo

echo "==== Step 7: User Signature ===="
PSBT_SIGN2_DATA=$(cargo run --quiet -- btc-tx sign \
  --psbt "$PSBT_SIGNED1" \
  --secret-key "$USER_SECKEY" \
  --input-index 0 \
  --cosigner-pubkey "$COSIGNER_PUBKEY" \
  --user-leaf-hash "$USER_LEAF_HASH")

PSBT_SIGNED2=$(echo "$PSBT_SIGN2_DATA" | jq -r '.psbt')
echo "User signature added"
echo

echo "==== Step 8: Finalize ===="
FINALIZE_DATA=$(cargo run --quiet -- btc-tx finalize --psbt "$PSBT_SIGNED2")
FINAL_TX_HEX=$(echo "$FINALIZE_DATA" | jq -r '.transaction_hex')
echo "TXID: $(echo "$FINALIZE_DATA" | jq -r '.txid')"
echo

echo "==== Step 9: Broadcast ===="
BROADCAST_TXID=$($BTC sendrawtransaction "$FINAL_TX_HEX")
$BTC generatetoaddress 1 "$MINER_ADDR" > /dev/null
echo "Done! TXID: $BROADCAST_TXID"