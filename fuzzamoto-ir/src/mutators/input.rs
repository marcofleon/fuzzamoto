use super::{Mutator, MutatorError, MutatorResult};
use crate::{Program, ProgramBuilder};

use rand::{RngCore, seq::IteratorRandom};

pub struct InputMutator;

impl<R: RngCore> Mutator<R> for InputMutator {
    fn mutate(&mut self, program: &mut Program, rng: &mut R) -> MutatorResult {
        let Some(candidate_instruction) = program
            .instructions
            .iter()
            .enumerate()
            .filter(|(_, instruction)| instruction.is_input_mutable())
            .choose(rng)
        else {
            return Err(MutatorError::NoMutationsAvailable);
        };
        let candidate_instruction = (candidate_instruction.0, candidate_instruction.1.clone());

        let program_upto = Program::unchecked_new(
            program.context.clone(),
            program.instructions[..candidate_instruction.0].to_vec(),
        );

        let builder = ProgramBuilder::from_program(program_upto)
            .expect("Program upto the chosen instruction should always be valid");

        let candidate_input = candidate_instruction
            .1
            .inputs
            .iter()
            .enumerate()
            .choose(rng)
            .expect("Candidates have at least one input");

        let current_variable = builder
            .get_variable(*candidate_input.1)
            .expect("Candiate variable has to exist");

        if let Some(new_var) = builder.get_random_variable(rng, current_variable.var) {
            if new_var.index == current_variable.index {
                return Err(MutatorError::NoMutationsAvailable);
            }

            program.instructions[candidate_instruction.0].inputs[candidate_input.0] = new_var.index;
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "InputMutator"
    }
}

impl InputMutator {
    pub fn new() -> Self {
        Self {}
    }
}
