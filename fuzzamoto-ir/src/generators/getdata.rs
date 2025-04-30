use rand::{RngCore, seq::SliceRandom};

use crate::{Generator, GeneratorResult, InstructionContext, Operation, ProgramBuilder, Variable};

use super::GeneratorError;

pub struct GetDataGenerator;

impl<R: RngCore> Generator<R> for GetDataGenerator {
    fn generate(&self, builder: &mut ProgramBuilder, rng: &mut R) -> GeneratorResult {
        let inventory_var = builder
            .get_random_variable(rng, Variable::ConstInventory)
            .ok_or(GeneratorError::MissingVariables)?;

        let conn_var = builder.get_or_create_random_connection(rng);

        builder.force_append(
            vec![conn_var.index, inventory_var.index],
            Operation::SendGetData,
        );

        Ok(())
    }

    fn name(&self) -> &'static str {
        "GetDataGenerator"
    }
}

impl Default for GetDataGenerator {
    fn default() -> Self {
        Self {}
    }
}

pub struct InventoryGenerator;

impl<R: RngCore> Generator<R> for InventoryGenerator {
    fn generate(&self, builder: &mut ProgramBuilder, rng: &mut R) -> GeneratorResult {
        let Some(mut_inventory_var) = builder.get_nearest_variable(Variable::MutInventory) else {
            return Err(GeneratorError::MissingVariables);
        };

        let tx_vars = builder.get_random_variables(rng, Variable::ConstTx);
        for tx_var in tx_vars {
            builder.force_append(
                vec![mut_inventory_var.index, tx_var.index],
                [
                    Operation::AddTxidWithWitnessInv,
                    Operation::AddTxidInv,
                    Operation::AddWtxidInv,
                ]
                .choose(rng)
                .unwrap()
                .clone(),
            );
        }

        let block_vars = builder.get_random_variables(rng, Variable::Block);
        for block_var in block_vars {
            builder.force_append(
                vec![mut_inventory_var.index, block_var.index],
                [Operation::AddBlockWithWitnessInv, Operation::AddBlockInv]
                    .choose(rng)
                    .unwrap()
                    .clone(),
            );
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "InventoryGenerator"
    }

    fn requested_context(&self) -> InstructionContext {
        InstructionContext::Inventory
    }
}

impl Default for InventoryGenerator {
    fn default() -> Self {
        Self {}
    }
}
