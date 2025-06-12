use std::{borrow::Borrow, marker::PhantomData};

use fuzzamoto_ir::Minimizer;
use libafl::{
    Evaluator, ExecutesInput, HasMetadata,
    events::EventFirer,
    executors::{Executor, HasObservers},
    feedbacks::MapNoveltiesMetadata,
    inputs::Input,
    observers::{CanTrack, MapObserver, ObserversTuple},
    stages::{Restartable, Stage},
    state::{HasCorpus, HasCurrentTestcase},
};
use libafl_bolts::tuples::Handle;

use crate::input::IrInput;

pub struct IrMinimizerStage<M, T, O> {
    trace_handle: Handle<T>,
    consecutive_failures: usize,
    _phantom: PhantomData<(M, O)>,
}

impl<M, T, O> IrMinimizerStage<M, T, O>
where
    O: MapObserver,
    T: AsRef<O> + CanTrack,
    M: Minimizer,
{
    pub fn new(trace_handle: Handle<T>) -> Self {
        Self {
            trace_handle,
            consecutive_failures: 0,
            _phantom: PhantomData::default(),
        }
    }
}

// ?????
impl<M, T, O, S> Restartable<S> for IrMinimizerStage<M, T, O> {
    fn should_restart(&mut self, _state: &mut S) -> Result<bool, libafl::Error> {
        Ok(true)
    }

    fn clear_progress(&mut self, _state: &mut S) -> Result<(), libafl::Error> {
        Ok(())
    }
}

impl<M, E, EM, S, Z, OT, T, O> Stage<E, EM, S, Z> for IrMinimizerStage<M, T, O>
where
    M: Minimizer,
    S: HasCorpus<IrInput> + HasCurrentTestcase<IrInput> + HasMetadata,
    E: Executor<EM, IrInput, S, Z> + HasObservers<Observers = OT>,
    EM: EventFirer<IrInput, S>,
    Z: Evaluator<E, EM, IrInput, S> + ExecutesInput<E, EM, IrInput, S>,
    OT: ObserversTuple<IrInput, S>,
    O: MapObserver,
    T: CanTrack + AsRef<O>,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), libafl::Error> {
        if state.current_testcase()?.scheduled_count() > 0 {
            // Already minimized
            return Ok(());
        }

        let novelties = state
            .current_testcase()?
            .borrow()
            .metadata::<MapNoveltiesMetadata>()?
            .list
            .clone();

        let mut success = false;
        let mut current_ir = state.current_input_cloned()?;

        log::info!(
            "{} reducing ir: {} instrs",
            std::any::type_name::<M>(),
            current_ir.ir().instructions.len()
        );
        let mut minimizer = M::new(current_ir.ir().clone());
        while let Some(prog) = minimizer.next() {
            if self.consecutive_failures > 200 {
                break;
            }

            if !prog.is_statically_valid() {
                log::info!(
                    "{} failure (not statically valid)",
                    std::any::type_name::<M>()
                );
                minimizer.failure();
                self.consecutive_failures += 1;
                continue;
            }

            let attempt = IrInput::new(prog);
            let _ = fuzzer.execute_input(state, executor, manager, &attempt);

            let number_of_retained_novelties = executor.observers()[&self.trace_handle]
                .as_ref()
                .how_many_set(&novelties);
            if number_of_retained_novelties == novelties.len() {
                // Minimization still has all the same novelties
                success = true;
                current_ir = attempt;
                minimizer.success();
                log::info!("{} success", std::any::type_name::<M>());
                self.consecutive_failures = 0;
            } else {
                minimizer.failure();
                log::info!("{} failure", std::any::type_name::<M>());
                self.consecutive_failures += 1;
            }
        }

        log::info!("{} done reducing", std::any::type_name::<M>(),);

        if success {
            current_ir.ir_mut().remove_nops();

            log::info!(
                "{} reduced ir to {} instructions",
                std::any::type_name::<M>(),
                current_ir.ir().instructions.len()
            );

            let mut testcase = state.current_testcase_mut()?;
            testcase.set_input(current_ir);
            let filepath = testcase.file_path().as_ref().unwrap().clone();
            log::info!(
                "{} reduced ir written to: {:?}",
                std::any::type_name::<M>(),
                filepath
            );
            let _ = testcase.input().as_ref().unwrap().to_file(filepath);
        }

        Ok(())
    }
}
