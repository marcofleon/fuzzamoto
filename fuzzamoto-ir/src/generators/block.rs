use bitcoin::hashes::Hash;
use rand::{Rng, RngCore, seq::SliceRandom};

use crate::{Generator, GeneratorResult, InstructionContext, Operation, ProgramBuilder, Variable};

use super::GeneratorError;

pub struct BlockGenerator;

impl<R: RngCore> Generator<R> for BlockGenerator {
    fn generate(&self, builder: &mut ProgramBuilder, rng: &mut R) -> GeneratorResult {
        let header_var = if rng.gen_bool(0.5) {
            builder.get_random_variable(rng, Variable::Header)
        } else {
            builder.get_nearest_sent_header()
        }
        .ok_or(GeneratorError::MissingVariables)?;

        let time_var = builder
            .get_random_variable(rng, Variable::Time)
            .ok_or(GeneratorError::MissingVariables)?;
        let mut random_tx_vars = builder.get_random_variables(rng, Variable::ConstTx);
        random_tx_vars.sort_by_key(|tx| tx.index);

        let begin_txs_var =
            builder.force_append_expect_output(vec![], Operation::BeginBlockTransactions);

        for tx_var in random_tx_vars {
            builder.force_append(vec![begin_txs_var.index, tx_var.index], Operation::AddTx);
        }

        let end_txs_var = builder
            .force_append_expect_output(vec![begin_txs_var.index], Operation::EndBlockTransactions);

        let block_version_var =
            builder.force_append_expect_output(vec![], Operation::LoadBlockVersion(5));

        let block_and_header_var = builder.force_append(
            vec![
                header_var.index,
                time_var.index,
                block_version_var.index,
                end_txs_var.index,
            ],
            Operation::BuildBlock,
        );

        let conn_var = builder.get_or_create_random_connection(rng);
        builder.force_append(
            vec![conn_var.index, block_and_header_var[0].index],
            Operation::SendHeader,
        );
        builder.force_append(
            vec![conn_var.index, block_and_header_var[1].index],
            Operation::SendBlock,
        );

        Ok(())
    }

    fn name(&self) -> &'static str {
        "BlockGenerator"
    }
}

impl Default for BlockGenerator {
    fn default() -> Self {
        Self {}
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct Header {
    pub prev: [u8; 32],
    pub merkle_root: [u8; 32],
    pub nonce: u32,
    pub bits: u32,
    pub time: u32,
    pub version: i32,
    pub height: u32,
}

impl Header {
    pub fn to_bitcoin_header(&self) -> bitcoin::block::Header {
        bitcoin::block::Header {
            version: bitcoin::block::Version::from_consensus(self.version),
            prev_blockhash: bitcoin::BlockHash::from_slice(&self.prev).unwrap(),
            merkle_root: bitcoin::TxMerkleNode::from_slice(&self.merkle_root).unwrap(),
            bits: bitcoin::CompactTarget::from_consensus(self.bits),
            nonce: self.nonce,
            time: self.time,
        }
    }
}

pub struct HeaderGenerator {
    pub headers: Vec<Header>,
}

impl HeaderGenerator {
    pub fn new(headers: Vec<Header>) -> Self {
        Self { headers }
    }
}

impl<R: RngCore> Generator<R> for HeaderGenerator {
    fn generate(&self, builder: &mut ProgramBuilder, rng: &mut R) -> GeneratorResult {
        let header = self.headers.choose(rng).unwrap().clone();

        builder.force_append(
            vec![],
            Operation::LoadHeader {
                prev: header.prev,
                merkle_root: header.merkle_root,
                nonce: header.nonce,
                bits: header.bits,
                time: header.time,
                version: header.version,
                height: header.height,
            },
        );
        Ok(())
    }

    fn name(&self) -> &'static str {
        "HeaderGenerator"
    }
}

pub struct SendBlockGenerator;

impl<R: RngCore> Generator<R> for SendBlockGenerator {
    fn generate(&self, builder: &mut ProgramBuilder, rng: &mut R) -> GeneratorResult {
        let block_var = builder
            .get_random_variable(rng, Variable::Block)
            .ok_or(GeneratorError::MissingVariables)?;
        let conn_var = builder.get_or_create_random_connection(rng);

        if rng.gen_bool(0.95) {
            builder.force_append(vec![conn_var.index, block_var.index], Operation::SendBlock);
        } else {
            builder.force_append(
                vec![conn_var.index, block_var.index],
                Operation::SendBlockNoWit,
            );
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "SendBlockGenerator"
    }
}

impl Default for SendBlockGenerator {
    fn default() -> Self {
        Self {}
    }
}

pub struct AddTxToBlockGenerator;

impl<R: RngCore> Generator<R> for AddTxToBlockGenerator {
    fn generate(&self, builder: &mut ProgramBuilder, rng: &mut R) -> GeneratorResult {
        let block_var = builder
            .get_nearest_variable(Variable::MutBlockTransactions)
            .ok_or(GeneratorError::MissingVariables)?;
        let mut random_tx_vars = builder.get_random_variables(rng, Variable::ConstTx);
        random_tx_vars.sort_by_key(|tx| tx.index);
        for tx_var in random_tx_vars {
            builder.force_append(vec![block_var.index, tx_var.index], Operation::AddTx);
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "AddTxToBlockGenerator"
    }

    fn requested_context(&self) -> InstructionContext {
        InstructionContext::BlockTransactions
    }
}

impl Default for AddTxToBlockGenerator {
    fn default() -> Self {
        Self {}
    }
}

