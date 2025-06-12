use std::borrow::Cow;

use fuzzamoto_ir::Program;

use libafl::{
    Error,
    corpus::{Corpus, CorpusId, NopCorpus},
    inputs::BytesInput,
    mutators::{MutationResult, Mutator, StdScheduledMutator, havoc_mutations},
    random_corpus_id,
    state::{HasCorpus, HasRand, StdState},
};
use libafl_bolts::{
    HasLen, Named,
    rands::{Rand, StdRand},
};
use rand::RngCore;

use crate::input::IrInput;

/// Instruction limit for mutated IR programs
const MAX_INSTRUCTIONS: usize = 2048;

pub struct IrMutator<M, R> {
    mutator: M,
    rng: R,
    name: Cow<'static, str>,
}

impl<M, R> IrMutator<M, R>
where
    R: RngCore,
    M: fuzzamoto_ir::Mutator<R>,
{
    pub fn new(mutator: M, rng: R) -> Self {
        let name = mutator.name();
        Self {
            mutator,
            rng,
            name: Cow::from(name),
        }
    }
}

impl<S, M, R> Mutator<IrInput, S> for IrMutator<M, R>
where
    S: HasRand,
    R: RngCore,
    M: fuzzamoto_ir::Mutator<R>,
{
    fn mutate(&mut self, _state: &mut S, input: &mut IrInput) -> Result<MutationResult, Error> {
        Ok(match self.mutator.mutate(input.ir_mut(), &mut self.rng) {
            Ok(_) if input.len() < MAX_INSTRUCTIONS => MutationResult::Mutated,
            _ => MutationResult::Skipped,
        })
    }

    #[inline]
    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl<M, R> Named for IrMutator<M, R> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

pub struct IrSpliceMutator<M, R> {
    mutator: M,
    rng: R,
    name: Cow<'static, str>,
}

impl<M, R> IrSpliceMutator<M, R>
where
    R: RngCore,
    M: fuzzamoto_ir::Mutator<R> + fuzzamoto_ir::Splicer<R>,
{
    pub fn new(mutator: M, rng: R) -> Self {
        let name = mutator.name();
        Self {
            mutator,
            rng,
            name: Cow::from(name),
        }
    }
}

impl<S, M, R> Mutator<IrInput, S> for IrSpliceMutator<M, R>
where
    S: HasRand + HasCorpus<IrInput>,
    R: RngCore,
    M: fuzzamoto_ir::Mutator<R> + fuzzamoto_ir::Splicer<R>,
{
    fn mutate(&mut self, state: &mut S, input: &mut IrInput) -> Result<MutationResult, Error> {
        let id = random_corpus_id!(state.corpus(), state.rand_mut());

        // We don't want to use the testcase we're already using for splicing
        if let Some(cur) = state.corpus().current() {
            if id == *cur {
                return Ok(MutationResult::Skipped);
            }
        }

        let mut other_testcase = state.corpus().get_from_all(id)?.borrow_mut();
        if other_testcase.scheduled_count() == 0 {
            // Don't splice with non-minimized inputs
            return Ok(MutationResult::Skipped);
        }

        let other = other_testcase.load_input(state.corpus())?;

        if let Err(_) = self
            .mutator
            .splice(input.ir_mut(), other.ir(), &mut self.rng)
        {
            return Ok(MutationResult::Skipped);
        }

        if input.len() > MAX_INSTRUCTIONS {
            return Ok(MutationResult::Skipped);
        }

        Ok(MutationResult::Mutated)
    }

    #[inline]
    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl<M, R> Named for IrSpliceMutator<M, R> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

pub struct IrGenerator<G, R> {
    generator: G,
    rng: R,
    name: Cow<'static, str>,
}

impl<G, R> IrGenerator<G, R>
where
    R: RngCore,
    G: fuzzamoto_ir::Generator<R>,
{
    pub fn new(generator: G, rng: R) -> Self {
        let name = generator.name();
        Self {
            generator,
            rng,
            name: Cow::from(name),
        }
    }
}

impl<S, G, R> Mutator<IrInput, S> for IrGenerator<G, R>
where
    S: HasRand,
    R: RngCore,
    G: fuzzamoto_ir::Generator<R>,
{
    fn mutate(&mut self, _state: &mut S, input: &mut IrInput) -> Result<MutationResult, Error> {
        let Some(index) = input
            .ir()
            .get_random_instruction_index(&mut self.rng, self.generator.requested_context())
        else {
            return Ok(MutationResult::Skipped);
        };

        let mut builder = fuzzamoto_ir::ProgramBuilder::new(input.ir().context.clone());

        builder
            .append_all(input.ir().instructions[..index].iter().cloned())
            .expect("Partial append should always succeed if full append succeeded");

        let prev_var_count = builder.variable_count();

        if let Err(_) = self.generator.generate(&mut builder, &mut self.rng) {
            return Ok(MutationResult::Skipped);
        }

        let second_half = Program::unchecked_new(
            input.ir().context.clone(),
            input.ir().instructions[index..].to_vec(),
        );
        let Ok(_) = builder.append_program(
            second_half,
            prev_var_count,
            builder.variable_count() - prev_var_count,
        ) else {
            log::warn!("failed to generate");
            return Ok(MutationResult::Skipped);
        };

        let Ok(new_program) = builder.finalize() else {
            return Ok(MutationResult::Skipped);
        };

        *input.ir_mut() = new_program;

        if input.len() > MAX_INSTRUCTIONS {
            return Ok(MutationResult::Skipped);
        }

        Ok(MutationResult::Mutated)
    }

    #[inline]
    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl<M, R> Named for IrGenerator<M, R> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

pub struct LibAflByteMutator {
    state: StdState<NopCorpus<BytesInput>, BytesInput, StdRand, NopCorpus<BytesInput>>,
}

impl LibAflByteMutator {
    pub fn new() -> Self {
        let state = StdState::new(
            StdRand::new(),
            NopCorpus::<BytesInput>::new(),
            NopCorpus::new(),
            &mut (),
            &mut (),
        )
        .unwrap();

        Self { state }
    }
}

impl fuzzamoto_ir::OperationByteMutator for LibAflByteMutator {
    fn mutate_bytes(&mut self, bytes: &mut Vec<u8>) {
        let mut input = BytesInput::from(bytes.clone());

        let mut mutator = StdScheduledMutator::new(havoc_mutations());
        let _ = mutator.mutate(&mut self.state, &mut input);

        bytes.clear();
        bytes.extend(input.into_inner());
    }
}
