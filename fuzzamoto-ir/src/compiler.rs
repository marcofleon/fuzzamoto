use std::{any::Any, time::Duration};

use bitcoin::{
    Amount, CompactTarget, OutPoint, Script, ScriptBuf, Sequence, Transaction, TxIn, TxMerkleNode,
    TxOut, Txid, WitnessMerkleNode, Wtxid,
    absolute::LockTime,
    hashes::{Hash, serde_macros::serde_details::SerdeHash, sha256},
    opcodes::{OP_0, OP_TRUE, all::OP_RETURN},
    p2p::message_blockdata::Inventory,
    script::PushBytesBuf,
    transaction,
};

use crate::{Operation, Program, generators::block::Header};

/// `Compiler` is responsible for compiling IR into a sequence of low-level actions to be performed
/// on a node (i.e. mapping `fuzzamoto_ir::Program` -> `CompiledProgram`).
pub struct Compiler;

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub enum CompiledAction {
    /// Create a new connection
    Connect(usize, String),
    /// Send a message on one of the connections
    SendRawMessage(usize, String, Vec<u8>),
    /// Set mock time for all nodes in the test
    SetTime(u64),

    /// Probe state of the nodes under test to enable smarter mutations
    Probe(Probe),
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub enum Probe {
    /// Probe for mempool contents
    Mempool,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct CompiledProgram {
    pub actions: Vec<CompiledAction>,
}

#[derive(Debug)]
pub enum CompilerError {
    MiscError(String),
    IncorrectNumberOfInputs,
    VariableNotFound,
    IncorrectVariableType,
}

impl std::fmt::Display for CompilerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompilerError::MiscError(e) => write!(f, "Misc error: {}", e),
            CompilerError::IncorrectNumberOfInputs => write!(f, "Incorrect number of inputs"),
            CompilerError::VariableNotFound => write!(f, "Variable not found"),
            CompilerError::IncorrectVariableType => write!(f, "Incorrect variable type"),
        }
    }
}

pub type CompilerResult = Result<CompiledProgram, CompilerError>;

struct Node {
    _index: usize,
}

struct Connection {
    index: usize,
}

#[derive(Clone, Debug)]
struct Scripts {
    script_pubkey: Vec<u8>,
    script_sig: Vec<u8>,
    witness: Witness,
}

#[derive(Debug, Clone)]
struct Witness {
    stack: Vec<Vec<u8>>,
}

#[derive(Clone, Debug)]
struct Txo {
    prev_out: ([u8; 32], u32),
    scripts: Scripts,
    value: u64,
}

#[derive(Clone)]
struct TxOutputs {
    outputs: Vec<(Scripts, u64)>,
    fees: u64,
}

#[derive(Clone)]
struct TxInputs {
    inputs: Vec<TxIn>,
    total_value: u64,
}

#[derive(Clone, Debug)]
struct Tx {
    tx: Transaction,
    txos: Vec<Txo>,
    output_selector: usize,
}

struct Nop;

impl Compiler {
    pub fn compile(&self, ir: &Program) -> CompilerResult {
        let mut output = CompiledProgram {
            actions: Vec::new(),
        };

        let mut variables: Vec<Box<dyn Any>> = Vec::new();

        for instruction in &ir.instructions {
            match instruction.operation.clone() {
                Operation::Nop {
                    outputs,
                    inner_outputs,
                } => {
                    for _ in 0..outputs {
                        variables.push(Box::new(Nop));
                    }
                    for _ in 0..inner_outputs {
                        variables.push(Box::new(Nop));
                    }
                }
                Operation::LoadNode(index) => {
                    variables.push(Box::new(Node { _index: index }));
                }
                Operation::LoadConnection(index) => {
                    variables.push(Box::new(Connection { index }));
                }
                Operation::LoadConnectionType(connection_type) => {
                    variables.push(Box::new(connection_type));
                }
                Operation::LoadDuration(duration) => {
                    variables.push(Box::new(duration));
                }
                Operation::LoadAmount(amount) => {
                    variables.push(Box::new(amount));
                }
                Operation::LoadTxVersion(version) => {
                    variables.push(Box::new(version));
                }
                Operation::LoadBlockVersion(version) => {
                    variables.push(Box::new(version));
                }
                Operation::LoadHeader {
                    prev,
                    merkle_root,
                    nonce,
                    bits,
                    time,
                    version,
                    height,
                } => {
                    variables.push(Box::new(Header {
                        prev,
                        merkle_root,
                        nonce,
                        bits,
                        time,
                        version,
                        height,
                    }));
                }
                Operation::LoadLockTime(lock_time) => {
                    variables.push(Box::new(lock_time));
                }
                Operation::LoadSequence(sequence) => {
                    variables.push(Box::new(sequence));
                }
                Operation::LoadTime(time) => {
                    variables.push(Box::new(time));
                }
                Operation::LoadMsgType(message_type) => {
                    variables.push(Box::new(message_type));
                }
                Operation::LoadBytes(bytes) => {
                    variables.push(Box::new(bytes));
                }
                Operation::LoadSize(size) => {
                    variables.push(Box::new(size));
                }
                Operation::LoadTxo {
                    outpoint,
                    value,
                    script_pubkey,
                    spending_script_sig,
                    spending_witness,
                } => {
                    variables.push(Box::new(Txo {
                        prev_out: outpoint,
                        value,
                        scripts: Scripts {
                            script_pubkey,
                            script_sig: spending_script_sig,
                            witness: Witness {
                                stack: spending_witness,
                            },
                        },
                    }));
                }

                Operation::BeginBlockTransactions => {
                    variables.push(Box::new(Vec::<Tx>::new()));
                }

                Operation::AddTx => {
                    let tx_var =
                        get_nth_variable::<Tx>(&variables, &instruction.inputs, 1)?.clone();
                    let block_transactions_var =
                        get_nth_variable_mut::<Vec<Tx>>(&mut variables, &instruction.inputs, 0)?;
                    block_transactions_var.push(tx_var);
                }

                Operation::EndBlockTransactions => {
                    let block_transactions_var =
                        get_nth_variable::<Vec<Tx>>(&variables, &instruction.inputs, 0)?;
                    variables.push(Box::new(block_transactions_var.clone()));
                }

                Operation::BuildBlock => {
                    let header_var =
                        get_nth_variable::<Header>(&variables, &instruction.inputs, 0)?;
                    let time_var = get_nth_variable::<u64>(&variables, &instruction.inputs, 1)?;
                    let block_version_var =
                        get_nth_variable::<i32>(&variables, &instruction.inputs, 2)?;
                    let block_transactions_var =
                        get_nth_variable::<Vec<Tx>>(&variables, &instruction.inputs, 3)?;

                    let mut witness = bitcoin::Witness::new();
                    witness.push([0u8; 32]);
                    let mut txdata = vec![Transaction {
                        version: transaction::Version(1),
                        lock_time: bitcoin::absolute::LockTime::from_height(0).unwrap(),
                        input: vec![TxIn {
                            previous_output: OutPoint::null(),
                            script_sig: ScriptBuf::builder()
                                .push_int((header_var.height + 1) as i64)
                                .push_int(0xFFFFFFFF)
                                .as_script()
                                .into(),
                            sequence: Sequence(0xFFFFFFFF),
                            witness,
                        }],
                        output: vec![
                            TxOut {
                                value: Amount::from_int_btc(25),
                                script_pubkey: vec![].into(), // TODO
                            },
                            fuzzamoto::test_utils::mining::create_witness_commitment_output(
                                WitnessMerkleNode::from_raw_hash(Wtxid::all_zeros().into()),
                            ),
                        ],
                    }];
                    txdata.extend(block_transactions_var.iter().map(|tx| tx.tx.clone()));

                    let mut block = bitcoin::Block {
                        header: bitcoin::block::Header {
                            version: bitcoin::block::Version::from_consensus(*block_version_var),
                            prev_blockhash: header_var.to_bitcoin_header().block_hash(),
                            merkle_root: TxMerkleNode::all_zeros(),
                            bits: CompactTarget::from_consensus(header_var.bits),
                            nonce: header_var.nonce,
                            time: *time_var as u32,
                        },
                        txdata,
                    };
                    fuzzamoto::test_utils::mining::fixup_commitments(&mut block);

                    if cfg!(feature = "reduced_pow") {
                        let mut block_hash = block.header.block_hash();
                        while block_hash.as_raw_hash()[31] & 0x80 != 0 {
                            block.header.nonce += 1;
                            block_hash = block.header.block_hash();
                        }
                        log::info!("{:?} height={}", block_hash, header_var.height);
                    } else {
                        let target = block.header.target();
                        while block.header.validate_pow(target).is_err() {
                            block.header.nonce += 1;
                        }
                    }

                    variables.push(Box::new(Header {
                        prev: *block.header.prev_blockhash.as_byte_array(),
                        merkle_root: *block.header.merkle_root.as_byte_array(),
                        bits: block.header.bits.to_consensus(),
                        time: block.header.time,
                        height: header_var.height + 1,
                        nonce: block.header.nonce,
                        version: block.header.version.to_consensus(),
                    }));
                    variables.push(Box::new(block));
                }

                Operation::BeginBuildInventory => {
                    variables.push(Box::new(Vec::<Inventory>::new()));
                }

                Operation::EndBuildInventory => {
                    let bytes_var =
                        get_nth_variable::<Vec<Inventory>>(&variables, &instruction.inputs, 0)?
                            .clone();
                    variables.push(Box::new(bytes_var.clone()));
                }

                Operation::AddTxidWithWitnessInv => {
                    let tx_var = get_nth_variable::<Tx>(&variables, &instruction.inputs, 1)?;
                    let inv = Inventory::WitnessTransaction(tx_var.tx.compute_txid());
                    let inventory_var = get_nth_variable_mut::<Vec<Inventory>>(
                        &mut variables,
                        &instruction.inputs,
                        0,
                    )?;
                    inventory_var.push(inv);
                }

                Operation::AddWtxidInv => {
                    let tx_var = get_nth_variable::<Tx>(&variables, &instruction.inputs, 1)?;
                    let inv = Inventory::WTx(tx_var.tx.compute_wtxid());
                    let inventory_var = get_nth_variable_mut::<Vec<Inventory>>(
                        &mut variables,
                        &instruction.inputs,
                        0,
                    )?;
                    inventory_var.push(inv);
                }

                Operation::AddTxidInv => {
                    let tx_var = get_nth_variable::<Tx>(&variables, &instruction.inputs, 1)?;
                    let inv = Inventory::Transaction(tx_var.tx.compute_txid());
                    let inventory_var = get_nth_variable_mut::<Vec<Inventory>>(
                        &mut variables,
                        &instruction.inputs,
                        0,
                    )?;
                    inventory_var.push(inv);
                }

                Operation::AddBlockInv => {
                    let block_var =
                        get_nth_variable::<bitcoin::Block>(&variables, &instruction.inputs, 1)?;
                    let inv = Inventory::Block(block_var.header.block_hash());
                    let inventory_var = get_nth_variable_mut::<Vec<Inventory>>(
                        &mut variables,
                        &instruction.inputs,
                        0,
                    )?;
                    inventory_var.push(inv);
                }
                Operation::AddBlockWithWitnessInv => {
                    let block_var =
                        get_nth_variable::<bitcoin::Block>(&variables, &instruction.inputs, 1)?;
                    let inv = Inventory::WitnessBlock(block_var.header.block_hash());
                    let inventory_var = get_nth_variable_mut::<Vec<Inventory>>(
                        &mut variables,
                        &instruction.inputs,
                        0,
                    )?;
                    inventory_var.push(inv);
                }
                Operation::AddFilteredBlockInv => {
                    let block_var =
                        get_nth_variable::<bitcoin::Block>(&variables, &instruction.inputs, 1)?;
                    let inv = Inventory::Unknown {
                        inv_type: 3, // MSG_FILTERED_BLOCK, see Bitcoin Core
                        hash: *block_var.header.block_hash().as_byte_array(),
                    };
                    let inventory_var = get_nth_variable_mut::<Vec<Inventory>>(
                        &mut variables,
                        &instruction.inputs,
                        0,
                    )?;
                    inventory_var.push(inv);
                }

                Operation::BeginWitnessStack => {
                    variables.push(Box::new(Witness { stack: Vec::new() }));
                }
                Operation::AddWitness => {
                    let bytes_var =
                        get_nth_variable::<Vec<u8>>(&variables, &instruction.inputs, 1)?.clone();
                    let witness_var =
                        get_nth_variable_mut::<Witness>(&mut variables, &instruction.inputs, 0)?;

                    witness_var.stack.push(bytes_var);
                }
                Operation::EndWitnessStack => {
                    let witness_var =
                        get_nth_variable::<Witness>(&variables, &instruction.inputs, 0)?;
                    variables.push(Box::new(witness_var.clone()));
                }

                Operation::BuildPayToWitnessScriptHash => {
                    let script = get_nth_variable::<Vec<u8>>(&variables, &instruction.inputs, 0)?;
                    let witness_var =
                        get_nth_variable::<Witness>(&variables, &instruction.inputs, 1)?;

                    let mut witness = witness_var.clone();
                    witness.stack.push(script.clone());

                    // OP_0 0x20 <script hash>
                    let mut script_pubkey = vec![OP_0.to_u8(), 32];
                    let script_hash = sha256::Hash::hash(script.as_slice());
                    script_pubkey.extend(script_hash.as_byte_array().as_slice());

                    variables.push(Box::new(Scripts {
                        script_pubkey,
                        script_sig: vec![],
                        witness,
                    }));
                }
                Operation::BuildPayToScriptHash => {
                    let script = get_nth_variable::<Vec<u8>>(&variables, &instruction.inputs, 0)?;
                    let witness_var =
                        get_nth_variable::<Witness>(&variables, &instruction.inputs, 1)?;

                    let mut witness = witness_var.clone();
                    witness.stack.push(script.clone());

                    let mut script_sig_builder = ScriptBuf::builder().push_opcode(OP_0);
                    for elem in witness.stack.drain(..) {
                        script_sig_builder =
                            script_sig_builder.push_slice(&PushBytesBuf::try_from(elem).unwrap());
                    }

                    let script_hash = ScriptBuf::from(script.clone()).script_hash();
                    let script_pubkey = ScriptBuf::new_p2sh(&script_hash).into_bytes();

                    variables.push(Box::new(Scripts {
                        script_pubkey,
                        script_sig: script_sig_builder.into_bytes(),
                        witness: Witness { stack: Vec::new() },
                    }));
                }
                Operation::BuildPayToAnchor => {
                    variables.push(Box::new(Scripts {
                        script_pubkey: vec![OP_TRUE.to_u8(), 0x2, 0x4e, 0x73], // P2A: https://github.com/bitcoin/bitcoin/pull/30352
                        script_sig: vec![],
                        witness: Witness { stack: Vec::new() },
                    }));
                }

                Operation::BuildRawScripts => {
                    let script_pubkey_var =
                        get_nth_variable::<Vec<u8>>(&variables, &instruction.inputs, 0)?;
                    let script_sig_var =
                        get_nth_variable::<Vec<u8>>(&variables, &instruction.inputs, 1)?;
                    let witness_var =
                        get_nth_variable::<Witness>(&variables, &instruction.inputs, 2)?;

                    let script_pubkey = script_pubkey_var.clone();
                    let script_sig = script_sig_var.clone();
                    let witness = witness_var.clone();

                    variables.push(Box::new(Scripts {
                        script_pubkey,
                        script_sig,
                        witness,
                    }));
                }

                Operation::BuildOpReturnScripts => {
                    let size_var = get_nth_variable::<usize>(&variables, &instruction.inputs, 0)?;

                    let data = vec![0x41u8; *size_var];
                    let script = ScriptBuf::builder()
                        .push_opcode(OP_RETURN)
                        .push_slice(&PushBytesBuf::try_from(data).unwrap());

                    variables.push(Box::new(Scripts {
                        script_pubkey: script.into_bytes(),
                        script_sig: vec![],
                        witness: Witness { stack: Vec::new() },
                    }));
                }

                Operation::BeginBuildTx => {
                    let tx_version_var =
                        get_nth_variable::<u32>(&variables, &instruction.inputs, 0)?;
                    let tx_lock_time_var =
                        get_nth_variable::<u32>(&variables, &instruction.inputs, 1)?;

                    variables.push(Box::new(Tx {
                        tx: Transaction {
                            version: transaction::Version(*tx_version_var as i32),
                            lock_time: LockTime::from_consensus(*tx_lock_time_var),
                            input: Vec::new(),
                            output: Vec::new(),
                        },
                        txos: Vec::new(),
                        output_selector: 0,
                    }));
                }
                Operation::EndBuildTx => {
                    let mut tx_inputs_var =
                        get_nth_variable::<TxInputs>(&variables, &instruction.inputs, 1)?.clone();
                    let tx_outputs_var =
                        get_nth_variable::<TxOutputs>(&variables, &instruction.inputs, 2)?.clone();

                    let mut tx_var =
                        get_nth_variable_mut::<Tx>(&mut variables, &instruction.inputs, 0)?.clone();

                    tx_var.tx.input.extend(tx_inputs_var.inputs.drain(..));
                    tx_var.tx.output.extend(tx_outputs_var.outputs.iter().map(
                        |(scripts, amount)| TxOut {
                            value: Amount::from_sat(*amount),
                            script_pubkey:
                                Script::from_bytes(scripts.script_pubkey.as_slice()).into(),
                        },
                    ));

                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(
                        tx_var
                            .tx
                            .compute_txid()
                            .as_raw_hash()
                            .as_byte_array()
                            .as_slice(),
                    );

                    tx_var.txos = tx_outputs_var
                        .outputs
                        .iter()
                        .enumerate()
                        .map(|(index, (scripts, amount))| Txo {
                            prev_out: (hash, index as u32),
                            scripts: scripts.clone(),
                            value: *amount,
                        })
                        .collect();

                    variables.push(Box::new(tx_var));
                }

                Operation::BeginBuildTxInputs => {
                    variables.push(Box::new(TxInputs {
                        inputs: Vec::new(),
                        total_value: 0,
                    }));
                }
                Operation::EndBuildTxInputs => {
                    let tx_inputs_var =
                        get_nth_variable::<TxInputs>(&variables, &instruction.inputs, 0)?;
                    variables.push(Box::new(tx_inputs_var.clone()));
                }
                Operation::AddTxInput => {
                    let txo_var = get_nth_variable::<Txo>(&variables, &instruction.inputs, 1)?;
                    let sequence_var = get_nth_variable::<u32>(&variables, &instruction.inputs, 2)?;

                    let previous_output = OutPoint::new(
                        Txid::from_slice_delegated(&txo_var.prev_out.0).unwrap(),
                        txo_var.prev_out.1,
                    );
                    let script_sig = Script::from_bytes(&txo_var.scripts.script_sig).into();
                    let witness = bitcoin::Witness::from(txo_var.scripts.witness.stack.as_slice());
                    let value = txo_var.value;
                    let sequence = *sequence_var;

                    let mut_tx_inputs_var =
                        get_nth_variable_mut::<TxInputs>(&mut variables, &instruction.inputs, 0)?;

                    mut_tx_inputs_var.inputs.push(TxIn {
                        previous_output,
                        script_sig,
                        witness,
                        sequence: Sequence(sequence),
                    });
                    mut_tx_inputs_var.total_value += value;
                }

                Operation::BeginBuildTxOutputs => {
                    let tx_inputs_var =
                        get_nth_variable::<TxInputs>(&variables, &instruction.inputs, 0)?;
                    let fees = tx_inputs_var.total_value;
                    variables.push(Box::new(TxOutputs {
                        outputs: Vec::new(),
                        fees,
                    }));
                }
                Operation::EndBuildTxOutputs => {
                    let tx_outputs_var =
                        get_nth_variable_mut::<TxOutputs>(&mut variables, &instruction.inputs, 0)?
                            .clone();
                    variables.push(Box::new(tx_outputs_var));
                }

                Operation::AddTxOutput => {
                    let scripts =
                        get_nth_variable::<Scripts>(&variables, &instruction.inputs, 1)?.clone();
                    let amount =
                        get_nth_variable::<u64>(&variables, &instruction.inputs, 2)?.clone();

                    let mut_tx_outputs_var =
                        get_nth_variable_mut::<TxOutputs>(&mut variables, &instruction.inputs, 0)?;

                    let amount = amount.min(mut_tx_outputs_var.fees);
                    mut_tx_outputs_var.outputs.push((scripts, amount));
                    mut_tx_outputs_var.fees -= amount;
                }

                Operation::AdvanceTime => {
                    let time_var = get_nth_variable::<u64>(&variables, &instruction.inputs, 0)?;
                    let duration_var =
                        get_nth_variable::<Duration>(&variables, &instruction.inputs, 1)?;

                    variables.push(Box::new(*time_var + duration_var.as_secs()));
                }

                Operation::SetTime => {
                    let time_var = get_nth_variable::<u64>(&variables, &instruction.inputs, 0)?;
                    output.actions.push(CompiledAction::SetTime(*time_var));
                }

                Operation::TakeTxo => {
                    let txo = {
                        let tx_var =
                            get_nth_variable_mut::<Tx>(&mut variables, &instruction.inputs, 0)?;
                        tx_var.output_selector += 1;
                        tx_var.txos[tx_var.output_selector - 1].clone()
                    };

                    variables.push(Box::new(txo));
                }

                Operation::SendRawMessage => {
                    let connection_var =
                        get_nth_variable::<Connection>(&variables, &instruction.inputs, 0)?;
                    let message_type_var =
                        get_nth_variable::<[char; 12]>(&variables, &instruction.inputs, 1)?;
                    let bytes_var =
                        get_nth_variable::<Vec<u8>>(&variables, &instruction.inputs, 2)?;

                    output.actions.push(CompiledAction::SendRawMessage(
                        connection_var.index,
                        message_type_var.iter().collect(),
                        bytes_var.clone(),
                    ));
                }

                Operation::SendTx => {
                    let connection_var =
                        get_nth_variable::<Connection>(&variables, &instruction.inputs, 0)?;
                    let tx_var = get_nth_variable::<Tx>(&variables, &instruction.inputs, 1)?;

                    output.actions.push(CompiledAction::SendRawMessage(
                        connection_var.index,
                        "tx".to_string(),
                        bitcoin::consensus::encode::serialize(&tx_var.tx),
                    ));
                }
                Operation::SendTxNoWit => {
                    let connection_var =
                        get_nth_variable::<Connection>(&variables, &instruction.inputs, 0)?;
                    let tx_var = get_nth_variable::<Tx>(&variables, &instruction.inputs, 1)?;

                    let mut tx_var = tx_var.clone();
                    for input in tx_var.tx.input.iter_mut() {
                        input.witness.clear();
                    }

                    output.actions.push(CompiledAction::SendRawMessage(
                        connection_var.index,
                        "tx".to_string(),
                        bitcoin::consensus::encode::serialize(&tx_var.tx),
                    ));
                }
                Operation::SendInv => {
                    let connection_var =
                        get_nth_variable::<Connection>(&variables, &instruction.inputs, 0)?;
                    let inv_var =
                        get_nth_variable::<Vec<Inventory>>(&variables, &instruction.inputs, 1)?;

                    output.actions.push(CompiledAction::SendRawMessage(
                        connection_var.index,
                        "inv".to_string(),
                        bitcoin::consensus::encode::serialize(inv_var),
                    ));
                }
                Operation::SendGetData => {
                    let connection_var =
                        get_nth_variable::<Connection>(&variables, &instruction.inputs, 0)?;
                    let inv_var =
                        get_nth_variable::<Vec<Inventory>>(&variables, &instruction.inputs, 1)?;

                    output.actions.push(CompiledAction::SendRawMessage(
                        connection_var.index,
                        "getdata".to_string(),
                        bitcoin::consensus::encode::serialize(inv_var),
                    ));
                }

                Operation::SendHeader => {
                    let connection_var =
                        get_nth_variable::<Connection>(&variables, &instruction.inputs, 0)?;
                    let header_var =
                        get_nth_variable::<Header>(&variables, &instruction.inputs, 1)?;

                    let mut data = vec![1u8]; // 1 header
                    data.extend(bitcoin::consensus::encode::serialize(
                        &header_var.to_bitcoin_header(),
                    ));
                    data.push(0); // empty txdata

                    output.actions.push(CompiledAction::SendRawMessage(
                        connection_var.index,
                        "headers".to_string(),
                        data,
                    ));
                }
                Operation::SendBlock | Operation::SendBlockNoWit => {
                    let connection_var =
                        get_nth_variable::<Connection>(&variables, &instruction.inputs, 0)?;
                    let block_var =
                        get_nth_variable::<bitcoin::Block>(&variables, &instruction.inputs, 1)?;

                    let mut block_var = block_var.clone();
                    if matches!(instruction.operation, Operation::SendBlockNoWit) {
                        for tx in block_var.txdata.iter_mut() {
                            for input in tx.input.iter_mut() {
                                input.witness.clear();
                            }
                        }
                    }
                    output.actions.push(CompiledAction::SendRawMessage(
                        connection_var.index,
                        "block".to_string(),
                        bitcoin::consensus::encode::serialize(&block_var),
                    ));
                }
            }
        }

        Ok(output)
    }

    pub fn new() -> Self {
        Self {}
    }
}

fn get_nth_variable<'a, T: 'static>(
    variables: &'a Vec<Box<dyn Any>>,
    inputs: &[usize],
    index: usize,
) -> Result<&'a T, CompilerError> {
    let var_index = inputs
        .get(index)
        .ok_or(CompilerError::IncorrectNumberOfInputs)?;
    let var = variables
        .get(*var_index)
        .ok_or(CompilerError::VariableNotFound)?;
    log::debug!("get_nth_variable T={}", std::any::type_name::<T>());
    let var = var
        .downcast_ref::<T>()
        .ok_or(CompilerError::IncorrectVariableType)?;
    Ok(var)
}

fn get_nth_variable_mut<'a, T: 'static>(
    variables: &'a mut Vec<Box<dyn Any>>,
    inputs: &[usize],
    index: usize,
) -> Result<&'a mut T, CompilerError> {
    let var_index = inputs
        .get(index)
        .ok_or(CompilerError::IncorrectNumberOfInputs)?;
    let var = variables
        .get_mut(*var_index)
        .ok_or(CompilerError::VariableNotFound)?;
    let var = var
        .downcast_mut::<T>()
        .ok_or(CompilerError::IncorrectVariableType)?;
    Ok(var)
}
