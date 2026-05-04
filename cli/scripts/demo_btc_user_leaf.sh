#!/bin/bash

set -e

# Funds a P2TR address where Leaf 1 is a CSV recovery script,
# then spends it via the user leaf after the timelock.

BTC="bitcoin-cli -regtest"
PROGRAM="zSQIS29W33fvVt9371bfd+9W33fvVt9371bfd+9W33fvVt93hgGA"
SIMPLICITY_WITNESS=""
NETWORK="regtest"
CSV_BLOCKS=10
BLOCK_TO_MINE=10

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

MINER_ADDR=$($BTC getnewaddress)
BAL=$($BTC getbalance)
if (( $(echo "$BAL < 1.0" | bc -l) )); then
  echo "Mining initial coins..."
  $BTC generatetoaddress 101 "$MINER_ADDR" > /dev/null
fi
echo "OK — balance: $($BTC getbalance) BTC"
echo

echo "==== Step 0: Get Tweaked Cosigner Pubkey ===="
TWEAK_RESPONSE=$(curl -s -X POST http://localhost:30431/simplicity-unchained/tweak \
  -H "Content-Type: application/json" \
  -d "$(jq -n --arg program "$PROGRAM" '{program: $program, jet_env: "bitcoin"}')")
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
# <CSV_BLOCKS> OP_CSV OP_DROP <user_xonly> OP_CHECKSIG
# Built by the CLI so the pubkey encoding is correct
echo "==== Step 2: Build CSV Recovery Leaf Script ===="
LEAF_DATA=$(cargo run --quiet -- btc-tx build-csv-leaf \
  --user-pubkey "$USER_PUBKEY" \
  --timelock "$CSV_BLOCKS")
USER_LEAF_SCRIPT=$(echo "$LEAF_DATA" | jq -r '.script')
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
[ -z "$ADDRESS" ] || [ "$ADDRESS" = "null" ] && { echo "ERROR: $ADDRESS_DATA"; exit 1; }
echo "Address: $ADDRESS"
echo

echo "==== Step 4: Fund Address ===="
FUNDING_TXID=$($BTC sendtoaddress "$ADDRESS" 0.001)
$BTC generatetoaddress 1 "$MINER_ADDR" > /dev/null
VOUT=$($BTC gettransaction "$FUNDING_TXID" | jq '.details[0].vout')
echo "Funded: $FUNDING_TXID:$VOUT"
echo

echo "==== Step 5: Create PSBT ===="
PSBT_DATA=$(cargo run --quiet -- btc-tx create \
  -i "$FUNDING_TXID:$VOUT" \
  -o "$ADDRESS:90000" \
  --network "$NETWORK" \
  --sequence "$CSV_BLOCKS")
PSBT_HEX=$(echo "$PSBT_DATA" | jq -r '.psbt')
echo "PSBT: $PSBT_HEX"
echo

echo "==== Step 6: Mine past CSV timelock ===="
$BTC generatetoaddress "$BLOCK_TO_MINE" "$MINER_ADDR" > /dev/null
echo "Mined $BLOCK_TO_MINE blocks"
echo

echo "==== Step 7: User Signs Leaf 1 (CSV recovery) ===="
PSBT_SIGN_DATA=$(cargo run --quiet -- btc-tx spend-user-leaf \
  --psbt "$PSBT_HEX" \
  --secret-key "$USER_SECKEY" \
  --user-leaf-script "$USER_LEAF_SCRIPT" \
  --cosigner-pubkey "$COSIGNER_PUBKEY" \
  --input-index 0 \
  --network "$NETWORK")
PSBT_SIGNED=$(echo "$PSBT_SIGN_DATA" | jq -r '.psbt')
echo "Signed"
echo

echo "==== Step 8: Finalize (user leaf) ===="
FINALIZE_DATA=$(cargo run --quiet -- btc-tx finalize-user-leaf --psbt "$PSBT_SIGNED")
FINAL_TX_HEX=$(echo "$FINALIZE_DATA" | jq -r '.transaction_hex')
echo "TXID: $(echo "$FINALIZE_DATA" | jq -r '.txid')"

echo "==== Step 9: Broadcast ===="
BROADCAST_TXID=$($BTC sendrawtransaction "$FINAL_TX_HEX")
$BTC generatetoaddress 1 "$MINER_ADDR" > /dev/null
echo "Done! TXID: $BROADCAST_TXID"