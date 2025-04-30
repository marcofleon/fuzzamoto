use crate::{ProgramValidationError, Variable};

use std::{fmt, time::Duration};

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Hash)]
pub enum Operation {
    /// No operation (used for minimization)
    Nop {
        outputs: usize,
        inner_outputs: usize,
    },

    /// `Load*` operations load data from the program's context
    LoadBytes(Vec<u8>),
    LoadMsgType([char; 12]),
    LoadNode(usize),
    LoadConnection(usize),
    LoadConnectionType(String),
    LoadDuration(Duration),
    LoadTime(u64),
    LoadTxo {
        outpoint: ([u8; 32], u32),
        value: u64,
        script_pubkey: Vec<u8>,

        spending_script_sig: Vec<u8>,
        spending_witness: Vec<Vec<u8>>,
    },
    LoadAmount(u64),
    LoadSize(usize),

    LoadTxVersion(u32),
    LoadBlockVersion(i32),
    LoadLockTime(u32),
    LoadSequence(u32),

    LoadHeader {
        prev: [u8; 32],
        merkle_root: [u8; 32],
        nonce: u32,
        bits: u32,
        time: u32,
        version: i32,
        height: u32,
    },

    /// Send a message given a connection, message type and bytes
    SendRawMessage,
    /// Advance a time variable by a given duration
    AdvanceTime,
    /// Set mock time
    SetTime,

    /// Script building operations
    BuildRawScripts,
    BuildPayToWitnessScriptHash,
    BuildPayToScriptHash,
    BuildOpReturnScripts,
    BuildPayToAnchor,

    BeginWitnessStack,
    EndWitnessStack,
    AddWitness,

    /// Transaction building operations
    BeginBuildTx,
    EndBuildTx,
    BeginBuildTxInputs,
    EndBuildTxInputs,
    BeginBuildTxOutputs,
    EndBuildTxOutputs,
    AddTxOutput,
    AddTxInput,
    TakeTxo,

    /// Block building
    BeginBlockTransactions,
    EndBlockTransactions,
    BuildBlock,
    AddTx,

    /// Inventory building
    BeginBuildInventory,
    EndBuildInventory,
    AddTxidInv,            // Tx by txid without witness
    AddTxidWithWitnessInv, // Tx by txid with witness
    AddWtxidInv,           // Tx by wtxid with witness
    AddBlockInv,
    AddBlockWithWitnessInv,
    AddFilteredBlockInv,

    /// Message sending
    SendGetData,
    SendInv,
    SendTx,
    SendTxNoWit,
    SendHeader,
    SendBlock,
    SendBlockNoWit,
}

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Operation::Nop { .. } => write!(f, "Nop"),
            Operation::LoadBytes(bytes) => write!(
                f,
                "LoadBytes(\"{}\")",
                bytes
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>()
            ), // as hex
            Operation::LoadMsgType(msg_type) => write!(
                f,
                "LoadMsgType(\"{}\")",
                msg_type.iter().map(|c| *c as char).collect::<String>()
            ),
            Operation::LoadNode(index) => write!(f, "LoadNode({})", index),
            Operation::LoadConnection(index) => write!(f, "LoadConnection({})", index),
            Operation::LoadConnectionType(connection_type) => {
                write!(f, "LoadConnectionType(\"{}\")", connection_type)
            }
            Operation::LoadDuration(duration) => write!(f, "LoadDuration({})", duration.as_secs()),
            Operation::SendRawMessage => write!(f, "SendRawMessage"),
            Operation::AdvanceTime => write!(f, "AdvanceTime"),
            Operation::LoadTime(time) => write!(f, "LoadTime({})", time),
            Operation::SetTime => write!(f, "SetTime"),
            Operation::BuildRawScripts => write!(f, "BuildRawScripts"),
            Operation::BuildPayToWitnessScriptHash => write!(f, "BuildPayToWitnessScriptHash"),
            Operation::BuildPayToScriptHash => write!(f, "BuildPayToScriptHash"),
            Operation::BuildOpReturnScripts => write!(f, "BuildOpReturnScripts"),
            Operation::BuildPayToAnchor => write!(f, "BuildPayToAnchor"),
            Operation::LoadTxo {
                outpoint,
                value,
                script_pubkey,
                spending_script_sig,
                spending_witness,
            } => write!(
                f,
                "LoadTxo({}:{}, {}, {}, {}, {})",
                hex_string(&outpoint.0),
                outpoint.1,
                value,
                hex_string(&script_pubkey),
                hex_string(&spending_script_sig),
                hex_witness_stack(&spending_witness),
            ),
            Operation::LoadHeader {
                prev,
                merkle_root,
                nonce,
                bits,
                time,
                version,
                height,
            } => write!(
                f,
                "LoadHeader({}, {}, {}, {}, {}, {}, {})",
                hex_string(prev),
                hex_string(merkle_root),
                nonce,
                bits,
                time,
                version,
                height
            ),
            Operation::LoadAmount(amount) => write!(f, "LoadAmount({})", amount),
            Operation::LoadTxVersion(version) => write!(f, "LoadTxVersion({})", version),
            Operation::LoadBlockVersion(version) => write!(f, "LoadBlockVersion({})", version),
            Operation::LoadLockTime(lock_time) => write!(f, "LoadLockTime({})", lock_time),
            Operation::LoadSequence(sequence) => write!(f, "LoadSequence({})", sequence),
            Operation::LoadSize(size) => write!(f, "LoadSize({})", size),
            Operation::BeginBuildTx => write!(f, "BeginBuildTx"),
            Operation::EndBuildTx => write!(f, "EndBuildTx"),
            Operation::BeginBuildTxInputs => write!(f, "BeginBuildTxInputs"),
            Operation::EndBuildTxInputs => write!(f, "EndBuildTxInputs"),
            Operation::BeginBuildTxOutputs => write!(f, "BeginBuildTxOutputs"),
            Operation::EndBuildTxOutputs => write!(f, "EndBuildTxOutputs"),
            Operation::AddTxInput => write!(f, "AddTxInput"),
            Operation::AddTxOutput => write!(f, "AddTxOutput"),
            Operation::TakeTxo => write!(f, "TakeTxo"),
            Operation::BeginWitnessStack => write!(f, "BeginWitnessStack"),
            Operation::EndWitnessStack => write!(f, "EndWitnessStack"),
            Operation::AddWitness => write!(f, "AddWitness"),

            Operation::BeginBuildInventory => write!(f, "BeginBuildInventory"),
            Operation::EndBuildInventory => write!(f, "EndBuildInventory"),
            Operation::AddTxidInv => write!(f, "AddTxidInv"),
            Operation::AddTxidWithWitnessInv => write!(f, "AddTxidWithWitnessInv"),
            Operation::AddWtxidInv => write!(f, "AddWtxidInv"),
            Operation::AddBlockInv => write!(f, "AddBlockInv"),
            Operation::AddBlockWithWitnessInv => write!(f, "AddBlockWithWitnessInv"),
            Operation::AddFilteredBlockInv => write!(f, "AddFilteredBlockInv"),

            Operation::BeginBlockTransactions => write!(f, "BeginBlockTransactions"),
            Operation::EndBlockTransactions => write!(f, "EndBlockTransactions"),
            Operation::BuildBlock => write!(f, "BuildBlock"),
            Operation::AddTx => write!(f, "AddTx"),

            Operation::SendGetData => write!(f, "SendGetData"),
            Operation::SendInv => write!(f, "SendInv"),
            Operation::SendTx => write!(f, "SendTx"),
            Operation::SendTxNoWit => write!(f, "SendTxNoWit"),
            Operation::SendHeader => write!(f, "SendHeader"),
            Operation::SendBlock => write!(f, "SendBlock"),
            Operation::SendBlockNoWit => write!(f, "SendBlockNoWit"),
        }
    }
}

fn hex_string(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
}

fn hex_witness_stack(witness: &[Vec<u8>]) -> String {
    witness.iter().map(|b| hex_string(b)).collect::<String>()
}

impl Operation {
    pub fn mutates_nth_input(&self, index: usize) -> bool {
        match self {
            Operation::AddTxInput if index == 0 => true,
            Operation::AddTxOutput if index == 0 => true,
            Operation::TakeTxo if index == 0 => true,
            Operation::AddWitness if index == 0 => true,
            Operation::AddTxidInv if index == 0 => true,
            Operation::AddTxidWithWitnessInv if index == 0 => true,
            Operation::AddWtxidInv if index == 0 => true,
            Operation::AddTx if index == 0 => true,
            _ => false,
        }
    }

    pub fn is_block_begin(&self) -> bool {
        match self {
            Operation::BeginBuildTx
            | Operation::BeginBuildInventory
            | Operation::BeginBuildTxInputs
            | Operation::BeginBuildTxOutputs
            | Operation::BeginWitnessStack
            | Operation::BeginBlockTransactions => true,
            // Exhaustive match to fail when new ops are added
            Operation::Nop { .. }
            | Operation::LoadBytes(_)
            | Operation::LoadMsgType(_)
            | Operation::LoadNode(_)
            | Operation::LoadConnection(_)
            | Operation::LoadConnectionType(_)
            | Operation::LoadDuration(_)
            | Operation::SendRawMessage
            | Operation::AdvanceTime
            | Operation::LoadTime(_)
            | Operation::LoadSize(_)
            | Operation::SetTime
            | Operation::BuildPayToWitnessScriptHash
            | Operation::BuildRawScripts
            | Operation::BuildPayToScriptHash
            | Operation::BuildOpReturnScripts
            | Operation::BuildPayToAnchor
            | Operation::LoadTxo { .. }
            | Operation::LoadHeader { .. }
            | Operation::LoadAmount(..)
            | Operation::LoadTxVersion(..)
            | Operation::LoadBlockVersion(..)
            | Operation::LoadLockTime(..)
            | Operation::LoadSequence(..)
            | Operation::EndBuildTx
            | Operation::EndBuildTxInputs
            | Operation::EndBuildTxOutputs
            | Operation::EndBuildInventory
            | Operation::AddTxidInv
            | Operation::AddTxidWithWitnessInv
            | Operation::AddWtxidInv
            | Operation::SendGetData
            | Operation::SendInv
            | Operation::AddTxInput
            | Operation::AddTxOutput
            | Operation::TakeTxo
            | Operation::EndWitnessStack
            | Operation::AddWitness
            | Operation::BuildBlock
            | Operation::AddBlockInv
            | Operation::AddBlockWithWitnessInv
            | Operation::AddFilteredBlockInv
            | Operation::AddTx
            | Operation::EndBlockTransactions
            | Operation::SendTx
            | Operation::SendTxNoWit
            | Operation::SendHeader
            | Operation::SendBlock
            | Operation::SendBlockNoWit => false,
        }
    }

    pub fn allow_insertion_in_block(&self) -> bool {
        if self.is_block_begin() {
            return false;
        }
        true
    }

    pub fn is_matching_block_begin(&self, other: &Operation) -> bool {
        match (other, self) {
            (Operation::BeginBuildTx, Operation::EndBuildTx)
            | (Operation::BeginBuildTxInputs, Operation::EndBuildTxInputs)
            | (Operation::BeginBuildTxOutputs, Operation::EndBuildTxOutputs)
            | (Operation::BeginBuildInventory, Operation::EndBuildInventory)
            | (Operation::BeginWitnessStack, Operation::EndWitnessStack)
            | (Operation::BeginBlockTransactions, Operation::EndBlockTransactions) => true,
            _ => false,
        }
    }

    pub fn is_block_end(&self) -> bool {
        match self {
            Operation::EndBuildTx
            | Operation::EndBuildTxInputs
            | Operation::EndBuildTxOutputs
            | Operation::EndBuildInventory
            | Operation::EndWitnessStack
            | Operation::EndBlockTransactions => true,
            // Exhaustive match to fail when new ops are added
            Operation::Nop { .. }
            | Operation::LoadBytes(_)
            | Operation::LoadMsgType(_)
            | Operation::LoadNode(_)
            | Operation::LoadConnection(_)
            | Operation::LoadConnectionType(_)
            | Operation::LoadDuration(_)
            | Operation::SendRawMessage
            | Operation::AdvanceTime
            | Operation::LoadTime(_)
            | Operation::LoadSize(_)
            | Operation::SetTime
            | Operation::BuildPayToWitnessScriptHash
            | Operation::BuildRawScripts
            | Operation::BuildPayToScriptHash
            | Operation::BuildOpReturnScripts
            | Operation::BuildPayToAnchor
            | Operation::LoadTxo { .. }
            | Operation::LoadHeader { .. }
            | Operation::LoadAmount(..)
            | Operation::LoadTxVersion(..)
            | Operation::LoadBlockVersion(..)
            | Operation::LoadLockTime(..)
            | Operation::LoadSequence(..)
            | Operation::BeginBuildTx
            | Operation::BeginBuildTxInputs
            | Operation::BeginBuildTxOutputs
            | Operation::AddTxInput
            | Operation::AddTxOutput
            | Operation::TakeTxo
            | Operation::BeginWitnessStack
            | Operation::AddWitness
            | Operation::BeginBuildInventory
            | Operation::AddTxidInv
            | Operation::AddTxidWithWitnessInv
            | Operation::AddWtxidInv
            | Operation::BuildBlock
            | Operation::AddBlockInv
            | Operation::AddBlockWithWitnessInv
            | Operation::AddFilteredBlockInv
            | Operation::AddTx
            | Operation::BeginBlockTransactions
            | Operation::SendGetData
            | Operation::SendInv
            | Operation::SendTx
            | Operation::SendTxNoWit
            | Operation::SendHeader
            | Operation::SendBlock
            | Operation::SendBlockNoWit => false,
        }
    }

    pub fn num_inner_outputs(&self) -> usize {
        match self {
            Operation::BeginBuildTx
            | Operation::BeginBuildTxInputs
            | Operation::BeginBuildTxOutputs
            | Operation::BeginBuildInventory
            | Operation::BeginWitnessStack
            | Operation::BeginBlockTransactions => 1,
            Operation::Nop {
                outputs: _,
                inner_outputs,
            } => *inner_outputs,
            // Exhaustive match to fail when new ops are added
            Operation::LoadBytes(_)
            | Operation::LoadMsgType(_)
            | Operation::LoadNode(_)
            | Operation::LoadConnection(_)
            | Operation::LoadConnectionType(_)
            | Operation::LoadDuration(_)
            | Operation::SendRawMessage
            | Operation::AdvanceTime
            | Operation::LoadTime(_)
            | Operation::LoadSize(_)
            | Operation::SetTime
            | Operation::BuildPayToWitnessScriptHash
            | Operation::BuildRawScripts
            | Operation::BuildPayToScriptHash
            | Operation::BuildOpReturnScripts
            | Operation::BuildPayToAnchor
            | Operation::LoadTxo { .. }
            | Operation::LoadHeader { .. }
            | Operation::LoadAmount(..)
            | Operation::LoadTxVersion(..)
            | Operation::LoadBlockVersion(..)
            | Operation::LoadLockTime(..)
            | Operation::LoadSequence(..)
            | Operation::EndBuildTx
            | Operation::EndBuildTxInputs
            | Operation::EndBuildTxOutputs
            | Operation::EndBuildInventory
            | Operation::AddTxidInv
            | Operation::AddTxidWithWitnessInv
            | Operation::AddWtxidInv
            | Operation::SendGetData
            | Operation::SendInv
            | Operation::AddTxInput
            | Operation::AddTxOutput
            | Operation::TakeTxo
            | Operation::EndWitnessStack
            | Operation::AddWitness
            | Operation::EndBlockTransactions
            | Operation::BuildBlock
            | Operation::AddBlockInv
            | Operation::AddBlockWithWitnessInv
            | Operation::AddFilteredBlockInv
            | Operation::AddTx
            | Operation::SendTx
            | Operation::SendTxNoWit
            | Operation::SendHeader
            | Operation::SendBlock
            | Operation::SendBlockNoWit => 0,
        }
    }

    pub fn num_outputs(&self) -> usize {
        match self {
            Operation::Nop { outputs, .. } => *outputs,
            Operation::LoadBytes(_) => 1,
            Operation::LoadMsgType(_) => 1,
            Operation::LoadNode(_) => 1,
            Operation::LoadConnection(_) => 1,
            Operation::LoadConnectionType(_) => 1,
            Operation::LoadDuration(_) => 1,
            Operation::SendRawMessage => 0,
            Operation::AdvanceTime => 1,
            Operation::LoadTime(_) => 1,
            Operation::LoadSize(_) => 1,
            Operation::SetTime => 0,
            Operation::BuildPayToWitnessScriptHash => 1,
            Operation::BuildPayToScriptHash => 1,
            Operation::BuildRawScripts => 1,
            Operation::BuildOpReturnScripts => 1,
            Operation::BuildPayToAnchor => 1,
            Operation::LoadTxo { .. } => 1,
            Operation::LoadHeader { .. } => 1,
            Operation::LoadAmount(..) => 1,
            Operation::LoadTxVersion(..) => 1,
            Operation::LoadBlockVersion(..) => 1,
            Operation::LoadLockTime(..) => 1,
            Operation::LoadSequence(..) => 1,
            Operation::BeginBuildTx => 0,
            Operation::EndBuildTx => 1,
            Operation::BeginBuildTxInputs => 0,
            Operation::EndBuildTxInputs => 1,
            Operation::BeginBuildTxOutputs => 0,
            Operation::EndBuildTxOutputs => 1,
            Operation::AddTxInput => 0,
            Operation::AddTxOutput => 0,
            Operation::TakeTxo => 1,
            Operation::AddWitness => 0,
            Operation::BeginWitnessStack => 0,
            Operation::EndWitnessStack => 1,
            Operation::BeginBuildInventory => 0,
            Operation::EndBuildInventory => 1,
            Operation::AddTxidInv => 0,
            Operation::AddTxidWithWitnessInv => 0,
            Operation::AddWtxidInv => 0,
            Operation::AddBlockInv => 0,
            Operation::AddBlockWithWitnessInv => 0,
            Operation::AddFilteredBlockInv => 0,

            Operation::BuildBlock => 2,
            Operation::AddTx => 0,
            Operation::EndBlockTransactions => 1,
            Operation::BeginBlockTransactions => 0,

            Operation::SendGetData => 0,
            Operation::SendInv => 0,
            Operation::SendTx => 0,
            Operation::SendTxNoWit => 0,
            Operation::SendHeader => 0,
            Operation::SendBlock => 0,
            Operation::SendBlockNoWit => 0,
        }
    }

    pub fn num_inputs(&self) -> usize {
        match self {
            Operation::Nop { .. } => 0,
            Operation::LoadBytes(_) => 0,
            Operation::LoadMsgType(_) => 0,
            Operation::LoadNode(_) => 0,
            Operation::LoadConnection(_) => 0,
            Operation::LoadConnectionType(_) => 0,
            Operation::LoadDuration(_) => 0,
            Operation::SendRawMessage => 3,
            Operation::AdvanceTime => 2,
            Operation::LoadTime(_) => 0,
            Operation::LoadSize(_) => 0,
            Operation::SetTime => 1,
            Operation::BuildPayToWitnessScriptHash => 2,
            Operation::BuildRawScripts => 3,
            Operation::BuildPayToScriptHash => 2,
            Operation::BuildOpReturnScripts => 1,
            Operation::BuildPayToAnchor => 0,
            Operation::LoadTxo { .. } => 0,
            Operation::LoadHeader { .. } => 0,
            Operation::LoadAmount(..) => 0,
            Operation::LoadTxVersion(..) => 0,
            Operation::LoadBlockVersion(..) => 0,
            Operation::LoadLockTime(..) => 0,
            Operation::LoadSequence(..) => 0,

            Operation::BeginWitnessStack => 0,
            Operation::EndWitnessStack => 1,
            Operation::AddWitness => 2,

            Operation::BeginBuildTx => 2,
            Operation::EndBuildTx => 3,
            Operation::BeginBuildTxInputs => 0,
            Operation::EndBuildTxInputs => 1,
            Operation::BeginBuildTxOutputs => 1,
            Operation::EndBuildTxOutputs => 1,
            Operation::AddTxInput => 3,
            Operation::AddTxOutput => 3,
            Operation::TakeTxo => 1,

            Operation::BeginBuildInventory => 0,
            Operation::EndBuildInventory => 1,
            Operation::AddTxidInv => 2,
            Operation::AddTxidWithWitnessInv => 2,
            Operation::AddWtxidInv => 2,
            Operation::AddBlockInv => 2,
            Operation::AddBlockWithWitnessInv => 2,
            Operation::AddFilteredBlockInv => 2,

            Operation::BuildBlock => 4,
            Operation::AddTx => 2,
            Operation::EndBlockTransactions => 1,
            Operation::BeginBlockTransactions => 0,

            Operation::SendGetData => 2,
            Operation::SendInv => 2,
            Operation::SendTx => 2,
            Operation::SendTxNoWit => 2,
            Operation::SendHeader => 2,
            Operation::SendBlock => 2,
            Operation::SendBlockNoWit => 2,
        }
    }

    pub fn check_input_types(&self, variables: &[Variable]) -> Result<(), ProgramValidationError> {
        let check_expected =
            |got: &[Variable], expected: &[Variable]| -> Result<(), ProgramValidationError> {
                assert!(self.num_inputs() == got.len());
                if got.len() != expected.len() {
                    return Err(ProgramValidationError::InvalidNumberOfInputs {
                        is: got.len(),
                        expected: expected.len(),
                    });
                }

                for (got, expected) in got.iter().zip(expected.iter()) {
                    if got != expected {
                        return Err(ProgramValidationError::InvalidVariableType {
                            is: Some(got.clone()),
                            expected: expected.clone(),
                        });
                    }
                }
                Ok(())
            };

        match self {
            Operation::SendRawMessage => check_expected(
                variables,
                &[Variable::Connection, Variable::MsgType, Variable::Bytes],
            ),
            Operation::AdvanceTime => {
                check_expected(variables, &[Variable::Time, Variable::Duration])
            }
            Operation::SetTime => check_expected(variables, &[Variable::Time]),
            Operation::BuildPayToWitnessScriptHash => {
                // Script to be wrapped and additional witness stack
                check_expected(variables, &[Variable::Bytes, Variable::ConstWitnessStack])
            }
            Operation::BuildPayToScriptHash => {
                // Script to be wrapped and additional witness stack
                check_expected(variables, &[Variable::Bytes, Variable::ConstWitnessStack])
            }
            Operation::BuildRawScripts => check_expected(
                variables,
                &[
                    Variable::Bytes,
                    Variable::Bytes,
                    Variable::ConstWitnessStack,
                ],
            ),
            Operation::BuildOpReturnScripts => check_expected(variables, &[Variable::Size]),
            Operation::BeginBuildTx => {
                check_expected(variables, &[Variable::TxVersion, Variable::LockTime])
            }
            Operation::EndBuildTx => check_expected(
                variables,
                &[
                    Variable::MutTx,
                    Variable::ConstTxInputs,
                    Variable::ConstTxOutputs,
                ],
            ),
            Operation::EndBuildTxInputs => check_expected(variables, &[Variable::MutTxInputs]),
            Operation::EndBuildTxOutputs => check_expected(variables, &[Variable::MutTxOutputs]),
            Operation::AddTxInput => check_expected(
                variables,
                &[Variable::MutTxInputs, Variable::Txo, Variable::Sequence],
            ),
            Operation::AddTxOutput => check_expected(
                variables,
                &[
                    Variable::MutTxOutputs,
                    Variable::Scripts,
                    Variable::ConstAmount,
                ],
            ),
            Operation::BeginBuildTxOutputs => check_expected(variables, &[Variable::ConstTxInputs]),
            Operation::TakeTxo => check_expected(variables, &[Variable::ConstTx]),
            Operation::AddWitness => {
                check_expected(variables, &[Variable::MutWitnessStack, Variable::Bytes])
            }
            Operation::EndWitnessStack => check_expected(variables, &[Variable::MutWitnessStack]),
            Operation::SendTx | Operation::SendTxNoWit => {
                check_expected(variables, &[Variable::Connection, Variable::ConstTx])
            }
            Operation::EndBuildInventory => check_expected(variables, &[Variable::MutInventory]),

            Operation::AddTxidInv | Operation::AddTxidWithWitnessInv | Operation::AddWtxidInv => {
                check_expected(variables, &[Variable::MutInventory, Variable::ConstTx])
            }
            Operation::AddBlockInv
            | Operation::AddBlockWithWitnessInv
            | Operation::AddFilteredBlockInv => {
                check_expected(variables, &[Variable::MutInventory, Variable::Block])
            }

            Operation::BuildBlock => check_expected(
                variables,
                &[
                    Variable::Header, // prev
                    Variable::Time,
                    Variable::BlockVersion,
                    Variable::ConstBlockTransactions,
                ],
            ),
            Operation::AddTx => check_expected(
                variables,
                &[Variable::MutBlockTransactions, Variable::ConstTx],
            ),
            Operation::EndBlockTransactions => {
                check_expected(variables, &[Variable::MutBlockTransactions])
            }

            Operation::SendGetData | Operation::SendInv => {
                check_expected(variables, &[Variable::Connection, Variable::ConstInventory])
            }
            Operation::SendHeader => {
                check_expected(variables, &[Variable::Connection, Variable::Header])
            }
            Operation::SendBlock | Operation::SendBlockNoWit => {
                check_expected(variables, &[Variable::Connection, Variable::Block])
            }
            // Exhaustive match to fail when new ops are added
            Operation::Nop { .. }
            | Operation::LoadBytes(_)
            | Operation::BuildPayToAnchor
            | Operation::LoadMsgType(_)
            | Operation::LoadNode(_)
            | Operation::LoadConnection(_)
            | Operation::LoadConnectionType(_)
            | Operation::LoadDuration(_)
            | Operation::LoadTime(_)
            | Operation::LoadTxo { .. }
            | Operation::LoadHeader { .. }
            | Operation::LoadAmount(..)
            | Operation::LoadTxVersion(..)
            | Operation::LoadBlockVersion(..)
            | Operation::LoadLockTime(..)
            | Operation::LoadSequence(..)
            | Operation::LoadSize(_)
            | Operation::BeginBuildTxInputs
            | Operation::BeginBuildInventory
            | Operation::BeginBlockTransactions
            | Operation::BeginWitnessStack => Ok(()),
        }
    }

    pub fn get_output_variables(&self) -> Vec<Variable> {
        match self {
            Operation::LoadBytes(_) => vec![Variable::Bytes],
            Operation::LoadMsgType(_) => vec![Variable::MsgType],
            Operation::LoadNode(_) => vec![Variable::Node],
            Operation::LoadConnection(_) => vec![Variable::Connection],
            Operation::LoadConnectionType(_) => vec![Variable::ConnectionType],
            Operation::LoadDuration(_) => vec![Variable::Duration],
            Operation::SendRawMessage => vec![],
            Operation::AdvanceTime => vec![Variable::Time],
            Operation::LoadTime(_) => vec![Variable::Time],
            Operation::SetTime => vec![],
            Operation::Nop { outputs, .. } => vec![Variable::Nop; *outputs],
            Operation::BuildPayToWitnessScriptHash => vec![Variable::Scripts],
            Operation::BuildPayToScriptHash => vec![Variable::Scripts],
            Operation::BuildRawScripts => vec![Variable::Scripts],
            Operation::BuildOpReturnScripts => vec![Variable::Scripts],
            Operation::BuildPayToAnchor => vec![Variable::Scripts],
            Operation::LoadTxo { .. } => vec![Variable::Txo],
            Operation::LoadAmount(..) => vec![Variable::ConstAmount],
            Operation::LoadTxVersion(..) => vec![Variable::TxVersion],
            Operation::LoadBlockVersion(..) => vec![Variable::BlockVersion],
            Operation::LoadLockTime(..) => vec![Variable::LockTime],
            Operation::LoadSequence(..) => vec![Variable::Sequence],
            Operation::LoadSize(..) => vec![Variable::Size],
            Operation::TakeTxo => vec![Variable::Txo],
            Operation::LoadHeader { .. } => vec![Variable::Header],
            Operation::BeginBuildTx => vec![],
            Operation::EndBuildTx => vec![Variable::ConstTx],
            Operation::BeginBuildTxInputs => vec![],
            Operation::EndBuildTxInputs => vec![Variable::ConstTxInputs],
            Operation::BeginBuildTxOutputs => vec![],
            Operation::EndBuildTxOutputs => vec![Variable::ConstTxOutputs],
            Operation::AddTxInput => vec![],
            Operation::AddTxOutput => vec![],

            Operation::BeginBuildInventory => vec![],
            Operation::EndBuildInventory => vec![Variable::ConstInventory],
            Operation::AddTxidInv => vec![],
            Operation::AddTxidWithWitnessInv => vec![],
            Operation::AddWtxidInv => vec![],
            Operation::AddBlockInv => vec![],
            Operation::AddBlockWithWitnessInv => vec![],
            Operation::AddFilteredBlockInv => vec![],

            Operation::BeginWitnessStack => vec![],
            Operation::EndWitnessStack => vec![Variable::ConstWitnessStack],
            Operation::AddWitness => vec![],

            Operation::BuildBlock => vec![Variable::Header, Variable::Block],
            Operation::AddTx => vec![],
            Operation::EndBlockTransactions => vec![Variable::ConstBlockTransactions],
            Operation::BeginBlockTransactions => vec![],

            Operation::SendTx => vec![],
            Operation::SendTxNoWit => vec![],
            Operation::SendGetData => vec![],
            Operation::SendInv => vec![],
            Operation::SendHeader => vec![],
            Operation::SendBlock => vec![],
            Operation::SendBlockNoWit => vec![],
        }
    }

    pub fn get_inner_output_variables(&self) -> Vec<Variable> {
        match self {
            Operation::BeginBuildTx => vec![Variable::MutTx],
            Operation::BeginBuildTxInputs => vec![Variable::MutTxInputs],
            Operation::BeginBuildTxOutputs => vec![Variable::MutTxOutputs],
            Operation::BeginWitnessStack => vec![Variable::MutWitnessStack],
            Operation::BeginBuildInventory => vec![Variable::MutInventory],
            Operation::BeginBlockTransactions => vec![Variable::MutBlockTransactions],
            Operation::Nop {
                outputs: _,
                inner_outputs,
            } => vec![Variable::Nop; *inner_outputs],
            // Exhaustive match to fail when new ops are added
            Operation::LoadBytes(_)
            | Operation::LoadMsgType(_)
            | Operation::LoadNode(_)
            | Operation::LoadConnection(_)
            | Operation::LoadConnectionType(_)
            | Operation::LoadDuration(_)
            | Operation::SendRawMessage
            | Operation::AdvanceTime
            | Operation::LoadTime(_)
            | Operation::SetTime
            | Operation::BuildPayToWitnessScriptHash
            | Operation::BuildRawScripts
            | Operation::BuildPayToScriptHash
            | Operation::BuildOpReturnScripts
            | Operation::BuildPayToAnchor
            | Operation::LoadTxo { .. }
            | Operation::LoadHeader { .. }
            | Operation::LoadAmount(..)
            | Operation::LoadTxVersion(..)
            | Operation::LoadBlockVersion(..)
            | Operation::LoadLockTime(..)
            | Operation::LoadSequence(..)
            | Operation::LoadSize(..)
            | Operation::EndBuildTx
            | Operation::EndBuildTxInputs
            | Operation::EndBuildTxOutputs
            | Operation::AddTxInput
            | Operation::AddTxOutput
            | Operation::TakeTxo
            | Operation::EndWitnessStack
            | Operation::AddWitness
            | Operation::EndBuildInventory
            | Operation::AddTxidInv
            | Operation::AddTxidWithWitnessInv
            | Operation::AddWtxidInv
            | Operation::AddBlockInv
            | Operation::AddBlockWithWitnessInv
            | Operation::AddFilteredBlockInv
            | Operation::BuildBlock
            | Operation::AddTx
            | Operation::EndBlockTransactions
            | Operation::SendGetData
            | Operation::SendInv
            | Operation::SendTx
            | Operation::SendTxNoWit
            | Operation::SendHeader
            | Operation::SendBlock
            | Operation::SendBlockNoWit => vec![],
        }
    }
}
