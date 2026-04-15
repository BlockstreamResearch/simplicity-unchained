use crate::precop::error::PrecopError;
use hal_simplicity::simplicity::bitcoin::psbt::Psbt;

/// Engine for hydrating Simplicity execution environments.
pub struct PrecopEngine;

/// Represents the Bitcoin execution environment.
///
/// Note: In the current version of simplicity-unchained (v0.1.0) and
/// its dependencies (hal-simplicity v0.2.0), the Bitcoin execution
/// environment is represented by `()`. This module enforces the
/// availability of full UTXO context (spent_outputs) to ensure
/// forward compatibility with future secure-derivation upgrades.
pub type BitcoinEnv = ();

impl PrecopEngine {
    /// Hydrates the Bitcoin environment from a PSBT.
    /// Ensures all inputs have full UTXO context (witness_utxo).
    ///
    /// # Arguments
    /// * `psbt` - The PSBT containing transaction and input context.
    ///
    /// # Returns
    /// * `Ok(BitcoinEnv)` if hydration is successful.
    /// * `Err(PrecopError::MissingUtxoContext)` if any input lacks a witness_utxo.
    ///
    /// # Errors
    /// * `PrecopError::MissingUtxoContext` if input context is incomplete.
    pub fn hydrate_env(psbt: &Psbt) -> Result<BitcoinEnv, PrecopError> {
        let mut _spent_outputs = Vec::with_capacity(psbt.inputs.len());

        for (i, input) in psbt.inputs.iter().enumerate() {
            let utxo = input
                .witness_utxo
                .as_ref()
                .ok_or(PrecopError::MissingUtxoContext(i))?;
            _spent_outputs.push(utxo.clone());
        }

        // Simplicity v0.7.0 / hal-simplicity v0.2.0 compatibility:
        // Currently uses () for Bitcoin environment.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hal_simplicity::simplicity::bitcoin::hashes::{Hash, hash160};
    use hal_simplicity::simplicity::bitcoin::psbt::Psbt;
    use hal_simplicity::simplicity::bitcoin::{ScriptBuf, Transaction, TxOut, absolute::LockTime};

    fn mock_psbt(num_inputs: usize) -> Psbt {
        let unsigned_tx = Transaction {
            version: hal_simplicity::simplicity::bitcoin::transaction::Version(2),
            lock_time: LockTime::from_consensus(0),
            input: vec![Default::default(); num_inputs],
            output: vec![],
        };
        Psbt::from_unsigned_tx(unsigned_tx).expect("valid unsigned tx")
    }

    #[test]
    fn test_hydrate_env_fails_on_missing_witness_utxo() {
        let mut psbt = mock_psbt(2);
        // Input 0 has witness_utxo
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: hal_simplicity::simplicity::bitcoin::Amount::from_sat(1000),
            script_pubkey: ScriptBuf::new_p2wpkh(
                &hal_simplicity::simplicity::bitcoin::WPubkeyHash::from_raw_hash(
                    hash160::Hash::from_slice(&[0u8; 20]).expect("valid hash"),
                ),
            ),
        });
        // Input 1 has NONE -> Should fail
        psbt.inputs[1].witness_utxo = None;

        let result = PrecopEngine::hydrate_env(&psbt);
        assert!(matches!(result, Err(PrecopError::MissingUtxoContext(1))));
    }

    #[test]
    fn test_hydrate_env_succeeds_with_full_context() {
        let mut psbt = mock_psbt(1);
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: hal_simplicity::simplicity::bitcoin::Amount::from_sat(1000),
            script_pubkey: ScriptBuf::new_p2wpkh(
                &hal_simplicity::simplicity::bitcoin::WPubkeyHash::from_raw_hash(
                    hash160::Hash::from_slice(&[0u8; 20]).expect("valid hash"),
                ),
            ),
        });

        let result = PrecopEngine::hydrate_env(&psbt);
        assert!(
            result.is_ok(),
            "Should succeed with full context, got {:?}",
            result
        );
    }
}
