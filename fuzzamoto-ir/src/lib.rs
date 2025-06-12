pub mod builder;
pub mod compiler;
pub mod errors;
pub mod generators;
pub mod instruction;
pub mod minimizers;
pub mod mutators;
pub mod operation;
pub mod variable;

use crate::errors::*;
pub use builder::*;
pub use generators::*;
pub use instruction::*;
pub use minimizers::*;
pub use mutators::*;
pub use operation::*;

use rand::{RngCore, seq::IteratorRandom};
pub use variable::*;

use std::{collections::HashMap, fmt, hash::Hash};

/// Program represent a sequence of operations to perform on target nodes.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Hash)]
pub struct Program {
    pub instructions: Vec<Instruction>,
    pub context: ProgramContext,
}

/// ProgramContext represents the context in which a program is executed. This mostly describes the
/// snapshot state of the target nodes.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Hash)]
pub struct ProgramContext {
    pub num_nodes: usize,
    pub num_connections: usize,
    pub timestamp: u64,
}

impl Program {
    pub fn unchecked_new(context: ProgramContext, instructions: Vec<Instruction>) -> Self {
        Self {
            instructions,
            context,
        }
    }

    pub fn is_statically_valid(&self) -> bool {
        match ProgramBuilder::from_program(self.clone()) {
            Ok(builder) => builder.finalize().is_ok(),
            Err(_) => false,
        }
    }

    pub fn to_builder(&self) -> Option<ProgramBuilder> {
        match ProgramBuilder::from_program(self.clone()) {
            Ok(prog) => Some(prog),
            Err(_) => None,
        }
    }

    pub fn remove_nops(&mut self) {
        debug_assert!(self.is_statically_valid());

        // Map variable indices from the program with nops to the program without nops
        let mut variable_mapping = HashMap::new();
        let mut variable_count = 0;
        let mut variable_count_with_nops = 0;

        for instr in &mut self.instructions {
            for output in [
                instr.operation.get_output_variables(),
                instr.operation.get_inner_output_variables(),
            ]
            .concat()
            {
                variable_mapping.insert(variable_count_with_nops, variable_count);

                if !matches!(&output, Variable::Nop) {
                    variable_count += 1;
                }
                variable_count_with_nops += 1;
            }

            for input in &mut instr.inputs {
                *input = variable_mapping[input];
            }
        }

        self.instructions = self
            .instructions
            .drain(..)
            .filter(|instr| !matches!(&instr.operation, Operation::Nop { .. }))
            .collect();
        debug_assert!(self.is_statically_valid());
    }

    pub fn get_random_instruction_index<R: RngCore>(
        &self,
        rng: &mut R,
        context: InstructionContext,
    ) -> Option<usize> {
        let mut scope_counter = 0;
        let mut scopes = vec![Scope {
            begin: None,
            id: scope_counter,
            context: InstructionContext::Global,
        }];
        let mut contexts = Vec::new();
        contexts.reserve(self.instructions.len());
        contexts.push(0);

        for (i, instr) in self.instructions.iter().enumerate() {
            if scopes.last().unwrap().context == context {
                contexts.push(i);
            }

            if instr.operation.is_block_end() {
                scopes.pop();
            }

            if instr.operation.is_block_begin() {
                scope_counter += 1;
                scopes.push(Scope {
                    begin: Some(i),
                    id: scope_counter,
                    context: instr.entered_context_after_execution().unwrap(),
                });
            }
        }

        contexts.iter().choose(rng).copied()
    }
}

impl fmt::Display for Program {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "// Context: nodes={} connections={} timestamp={}\n",
            self.context.num_nodes, self.context.num_connections, self.context.timestamp
        )?;
        let mut var_counter = 0;
        let mut indent_counter = 0;

        for instruction in &self.instructions {
            if indent_counter > 0 {
                let offset = if instruction.operation.is_block_end() {
                    1
                } else {
                    0
                };
                write!(f, "{}", "  ".repeat(indent_counter - offset))?;
            }

            if instruction.operation.num_outputs() > 0 {
                for _ in 0..(instruction.operation.num_outputs() - 1) {
                    write!(f, "v{}, ", var_counter)?;
                    var_counter += 1;
                }
                write!(f, "v{}", var_counter)?;
                var_counter += 1;
                write!(f, " <- ")?;
            }
            write!(f, "{}", instruction.operation)?;

            if instruction.operation.num_inputs() > 0 {
                write!(f, "(")?;
                for input in &instruction.inputs[..instruction.operation.num_inputs() - 1] {
                    write!(f, "v{}, ", input)?;
                }
                write!(
                    f,
                    "v{}",
                    instruction.inputs[instruction.operation.num_inputs() - 1]
                )?;
                write!(f, ")")?;
            }

            if instruction.operation.num_inner_outputs() > 0 {
                write!(f, " -> ")?;
                for _ in 0..(instruction.operation.num_inner_outputs() - 1) {
                    write!(f, "v{}, ", var_counter)?;
                    var_counter += 1;
                }
                write!(f, "v{}", var_counter)?;
                var_counter += 1;
            }
            write!(f, "\n")?;

            if instruction.operation.is_block_begin() {
                indent_counter += 1;
            }
            if instruction.operation.is_block_end() {
                indent_counter -= 1;
            }
        }
        Ok(())
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct FullProgramContext {
    pub context: ProgramContext,
    pub txos: Vec<Txo>,
    pub headers: Vec<Header>,
}
