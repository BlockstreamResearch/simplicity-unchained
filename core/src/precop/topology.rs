use crate::precop::error::PrecopError;
use hal_simplicity::simplicity::bitcoin::Transaction;

/// Enforcer for strict transaction topology.
pub struct TopologyEnforcer;

impl TopologyEnforcer {
    /// Verifies that the transaction follows the Command-First topology:
    /// [0: OP_RETURN, 1: Target, 2: Change, 3: Fee]
    ///
    /// # Arguments
    /// * `tx` - The transaction to verify.
    ///
    /// # Returns
    /// * `Ok(())` if topology is canonical.
    /// * `Err(PrecopError::TopologyViolation)` otherwise.
    ///
    /// # Errors
    /// * `PrecopError::TopologyViolation` if index 0 is not OP_RETURN or output count is not exactly 4.
    pub fn verify_command_first(tx: &Transaction) -> Result<(), PrecopError> {
        let output_count = tx.output.len();
        if output_count != 4 {
            let msg = if output_count < 4 {
                format!("insufficient outputs: expected 4, got {}", output_count)
            } else {
                format!("excessive outputs: expected 4, got {}", output_count)
            };
            return Err(PrecopError::TopologyViolation(msg));
        }

        if !tx.output[0].script_pubkey.is_op_return() {
            return Err(PrecopError::TopologyViolation(
                "invalid index 0: expected OP_RETURN (Command/Metadata)".into(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hal_simplicity::simplicity::bitcoin::hashes::{Hash, hash160};
    use hal_simplicity::simplicity::bitcoin::{ScriptBuf, TxOut, absolute::LockTime};

    fn mock_tx(outputs: Vec<TxOut>) -> Transaction {
        Transaction {
            version: hal_simplicity::simplicity::bitcoin::transaction::Version(2),
            lock_time: LockTime::from_consensus(0),
            input: vec![],
            output: outputs,
        }
    }

    fn op_return_out() -> TxOut {
        TxOut {
            value: hal_simplicity::simplicity::bitcoin::Amount::ZERO,
            script_pubkey: ScriptBuf::new_op_return([0u8; 32]),
        }
    }

    fn standard_out() -> TxOut {
        TxOut {
            value: hal_simplicity::simplicity::bitcoin::Amount::from_sat(1000),
            script_pubkey: ScriptBuf::new_p2wpkh(
                &hal_simplicity::simplicity::bitcoin::WPubkeyHash::from_raw_hash(
                    hash160::Hash::from_slice(&[0u8; 20]).expect("valid hash"),
                ),
            ),
        }
    }

    #[test]
    fn test_rejects_missing_op_return_at_index_0() {
        // [Target, Change, Fee, OP_RETURN] -> WRONG
        let tx = mock_tx(vec![
            standard_out(),
            standard_out(),
            standard_out(),
            op_return_out(),
        ]);
        let result = TopologyEnforcer::verify_command_first(&tx);
        assert!(
            matches!(result, Err(PrecopError::TopologyViolation(ref m)) if m.contains("index 0"))
        );
    }

    #[test]
    fn test_rejects_insufficient_outputs() {
        // Only 2 outputs -> WRONG
        let tx = mock_tx(vec![op_return_out(), standard_out()]);
        let result = TopologyEnforcer::verify_command_first(&tx);
        assert!(
            matches!(result, Err(PrecopError::TopologyViolation(ref m)) if m.contains("insufficient"))
                || matches!(result, Err(PrecopError::TopologyViolation(ref m)) if m.contains("exact"))
        );
    }

    #[test]
    fn test_rejects_excessive_outputs() {
        // 5 outputs -> WRONG
        let tx = mock_tx(vec![
            op_return_out(),
            standard_out(),
            standard_out(),
            standard_out(),
            standard_out(),
        ]);
        let result = TopologyEnforcer::verify_command_first(&tx);
        assert!(
            matches!(result, Err(PrecopError::TopologyViolation(ref m)) if m.contains("excessive"))
                || matches!(result, Err(PrecopError::TopologyViolation(ref m)) if m.contains("exact"))
        );
    }

    #[test]
    fn test_accepts_canonical_command_first_topology() {
        // [OP_RETURN, Target, Change, Fee] -> CORRECT
        let tx = mock_tx(vec![
            op_return_out(),
            standard_out(),
            standard_out(),
            standard_out(),
        ]);
        let result = TopologyEnforcer::verify_command_first(&tx);
        assert!(
            result.is_ok(),
            "Should accept canonical topology, got {:?}",
            result
        );
    }
}
