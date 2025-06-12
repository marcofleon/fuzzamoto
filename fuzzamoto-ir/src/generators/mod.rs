pub mod advance_time;
pub mod getdata;
pub mod send_raw_message;
pub mod tx;
pub mod txo;
pub mod witness;
pub mod block;

pub use advance_time::*;
pub use getdata::*;
pub use send_raw_message::*;
pub use tx::*;
pub use txo::*;
pub use witness::*;
pub use block::*;

use crate::{InstructionContext, ProgramBuilder, ProgramContext, ProgramValidationError};
use rand::RngCore;

#[derive(Debug, Clone)]
pub enum GeneratorError {
    GeneratedInvalidProgram(ProgramValidationError),
    InvalidContext(ProgramContext),
    MissingVariables,
}

pub type GeneratorResult = Result<(), GeneratorError>;
pub trait Generator<R: RngCore> {
    /// Generate additional instructions into the program being build by `builder`
    fn generate(&self, builder: &mut ProgramBuilder, rng: &mut R) -> GeneratorResult;

    /// Name of the generator
    fn name(&self) -> &'static str;

    /// `InstructionContext` the generator expects to generate code in
    fn requested_context(&self) -> InstructionContext {
        InstructionContext::Global
    }

    // TODO can we expose requested input variables somehow? currently the generators will fail if
    // inputs variables they expect don't exist
}
