use std::{marker::PhantomData, path::PathBuf, process, time::Duration};

use fuzzamoto_ir::{
    AddTxToBlockGenerator, AdvanceTimeGenerator, BlockGenerator, CombineMutator, ConcatMutator,
    GetDataGenerator, HeaderGenerator, InputMutator, InventoryGenerator, LargeTxGenerator,
    LongChainGenerator, OneParentOneChildGenerator, OperationMutator, SendBlockGenerator,
    SingleTxGenerator, TxoGenerator, WitnessGenerator, cutting::CuttingMinimizer,
    minimizers::block::BlockMinimizer, nopping::NoppingMinimizer,
};

#[cfg(feature = "simplemgr")]
use libafl::events::SimpleEventManager;
use libafl::{
    Error, NopFuzzer,
    corpus::{CachedOnDiskCorpus, Corpus, OnDiskCorpus},
    events::{
        ClientDescription, EventRestarter, LlmpRestartingEventManager, MonitorTypedEventManager,
        NopEventManager,
    },
    executors::Executor,
    feedback_and_fast, feedback_or,
    feedbacks::{ConstFeedback, CrashFeedback, HasObserverHandle, MaxMapFeedback, TimeFeedback},
    fuzzer::{Evaluator, Fuzzer, StdFuzzer},
    monitors::Monitor,
    mutators::{ComposedByMutations, TuneableScheduledMutator},
    observers::{CanTrack, HitcountsMapObserver, StdMapObserver, TimeObserver},
    schedulers::{
        IndexesLenTimeMinimizerScheduler, StdWeightedScheduler, powersched::PowerSchedule,
    },
    stages::{IfStage, StagesTuple, TuneableMutationalStage},
    state::{HasCorpus, HasMaxSize, HasRand, StdState},
};
use libafl_bolts::{
    HasLen, current_nanos,
    rands::{Rand, StdRand},
    shmem::{StdShMem, StdShMemProvider},
    tuples::tuple_list,
};
use libafl_nyx::{executor::NyxExecutor, helper::NyxHelper, settings::NyxSettings};
use rand::{SeedableRng, rngs::SmallRng};
use typed_builder::TypedBuilder;

use crate::{
    input::IrInput,
    mutators::{IrGenerator, IrMutator, IrSpliceMutator, LibAflByteMutator},
    options::FuzzerOptions,
    stages::IrMinimizerStage,
};

pub type ClientState =
    StdState<CachedOnDiskCorpus<IrInput>, IrInput, StdRand, OnDiskCorpus<IrInput>>;

#[cfg(feature = "simplemgr")]
pub type ClientMgr<M> = SimpleEventManager<IrInput, M, ClientState>;
#[cfg(not(feature = "simplemgr"))]
pub type ClientMgr<M> = MonitorTypedEventManager<
    LlmpRestartingEventManager<(), IrInput, ClientState, StdShMem, StdShMemProvider>,
    M,
>;

#[derive(TypedBuilder)]
pub struct Instance<'a, M: Monitor> {
    options: &'a FuzzerOptions,
    /// The harness. We create it before forking, then `take()` it inside the client.
    mgr: ClientMgr<M>,
    client_description: ClientDescription,
    #[builder(default=PhantomData)]
    phantom: PhantomData<M>,
}

impl<M: Monitor> Instance<'_, M> {
    pub fn run(mut self, state: Option<ClientState>) -> Result<(), Error> {
        let parent_cpu_id = self
            .options
            .cores
            .ids
            .first()
            .expect("unable to get first core id");

        let timeout = Duration::from_millis(self.options.timeout as u64);
        let settings = NyxSettings::builder()
            .cpu_id(self.client_description.core_id().0)
            .parent_cpu_id(Some(parent_cpu_id.0))
            .input_buffer_size(self.options.buffer_size)
            .timeout_secs(timeout.as_secs() as u8)
            .timeout_micro_secs(timeout.subsec_micros() as u32)
            .build();

        let helper = NyxHelper::new(self.options.shared_dir(), settings)?;

        let trace_observer = HitcountsMapObserver::new(unsafe {
            StdMapObserver::from_mut_ptr("trace", helper.bitmap_buffer, helper.bitmap_size)
        })
        .track_indices()
        .track_novelties();

        // Create an observation channel to keep track of the execution time
        let time_observer = TimeObserver::new("time");

        let map_feedback = MaxMapFeedback::new(&trace_observer);

        let trace_handle = map_feedback.observer_handle().clone();

        // let stdout_observer = StdOutObserver::new("hprintf_output");

        // Feedback to rate the interestingness of an input
        // This one is composed by two Feedbacks in OR
        let mut feedback = feedback_or!(
            // New maximization map feedback linked to the edges observer and the feedback state
            feedback_and_fast!(
                ConstFeedback::new(!self.options.static_corpus),
                map_feedback
            ),
            // Time feedback, this one does not need a feedback state
            TimeFeedback::new(&time_observer),
            // Append stdout to metadata
            // StdOutToMetadataFeedback::new(&stdout_observer)
        );

        // A feedback to choose if an input is a solution or not
        let mut objective = feedback_and_fast!(
            CrashFeedback::new(),
            // Take it only if trigger new coverage over crashes
            // For deduplication
            MaxMapFeedback::with_name("mapfeedback_metadata_objective", &trace_observer)
        );

        // If not restarting, create a State from scratch
        let mut state = match state {
            Some(x) => x,
            None => {
                StdState::new(
                    // RNG
                    StdRand::with_seed(current_nanos()),
                    // Corpus that will be evolved
                    CachedOnDiskCorpus::new(
                        self.options.queue_dir(self.client_description.core_id()),
                        100,
                    )?,
                    // Corpus in which we store solutions
                    OnDiskCorpus::new(self.options.crashes_dir(self.client_description.core_id()))?,
                    &mut feedback,
                    &mut objective,
                )?
            }
        };

        // A minimization+queue policy to get testcasess from the corpus
        let scheduler = IndexesLenTimeMinimizerScheduler::new(
            &trace_observer,
            StdWeightedScheduler::with_schedule(
                &mut state,
                &trace_observer,
                Some(PowerSchedule::explore()),
            ),
        );
        //let scheduler = StdWeightedScheduler::with_schedule(
        //    &mut state,
        //    &trace_observer,
        //    Some(PowerSchedule::explore()),
        //);

        let observers = tuple_list!(trace_observer, time_observer); // stdout_observer);
        //let scheduler = scheduler.cycling_scheduler();

        state.set_max_size(self.options.buffer_size);

        // A fuzzer with feedbacks and a corpus scheduler
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        if let Some(rerun_input) = &self.options.rerun_input {
            let input = IrInput::unparse(rerun_input);

            let mut executor = NyxExecutor::builder().build(helper, observers);

            let exit_kind = executor
                .run_target(
                    &mut NopFuzzer::new(),
                    &mut state,
                    &mut NopEventManager::new(),
                    &input,
                )
                .expect("Error running target");
            println!("Rerun finished with ExitKind {:?}", exit_kind);
            // We're done :)
            process::exit(0);
        }

        let mut executor = NyxExecutor::builder().build(helper, observers);

        // TODO can we avoid hardcoding this path
        let bytes = std::fs::read(PathBuf::from("/tmp/workdir/dump/ir.context"))
            .expect("Could not read ir context file");
        let full_program_context: fuzzamoto_ir::FullProgramContext =
            postcard::from_bytes(&bytes).expect("could not deser ir context");

        let rng = SmallRng::seed_from_u64(state.rand_mut().next());

        let mutator = TuneableScheduledMutator::new(
            &mut state,
            tuple_list!(
                IrMutator::new(InputMutator::new(), rng.clone()),
                IrMutator::new(OperationMutator::new(LibAflByteMutator::new()), rng.clone()),
                IrSpliceMutator::new(ConcatMutator::new(), rng.clone()),
                IrSpliceMutator::new(CombineMutator::new(), rng.clone()),
                IrGenerator::new(AdvanceTimeGenerator::default(), rng.clone()),
                //IrGenerator::new(SendMessageGenerator::default(), rng.clone()),
                IrGenerator::new(SingleTxGenerator::default(), rng.clone()),
                IrGenerator::new(LongChainGenerator::default(), rng.clone()),
                IrGenerator::new(LargeTxGenerator::default(), rng.clone()),
                IrGenerator::new(OneParentOneChildGenerator::default(), rng.clone()),
                IrGenerator::new(
                    TxoGenerator::new(full_program_context.txos.clone()),
                    rng.clone()
                ),
                IrGenerator::new(WitnessGenerator::new(), rng.clone()),
                IrGenerator::new(InventoryGenerator::default(), rng.clone()),
                IrGenerator::new(GetDataGenerator::default(), rng.clone()),
                IrGenerator::new(BlockGenerator::default(), rng.clone()),
                IrGenerator::new(
                    HeaderGenerator::new(full_program_context.headers.clone()),
                    rng.clone()
                ),
                IrGenerator::new(SendBlockGenerator::default(), rng.clone()),
                IrGenerator::new(AddTxToBlockGenerator::default(), rng.clone()),
            ),
        );

        let weights = &[
            300f32, 300.0, 100.0, 200.0, 30.0, 50.0, 50.0, 50.0, 50.0, 20.0, 20.0, 20.0, 20.0,
            50.0, 50.0, 50.0, 50.0,
        ];
        let sum = weights.iter().sum::<f32>();
        assert_eq!(mutator.mutations().len(), weights.len());

        mutator
            .set_mutation_probabilities(&mut state, weights.iter().map(|w| *w / sum).collect())
            .unwrap();

        let mut stages = tuple_list!(
            IfStage::new(
                |_, _, _, _| Ok(!self.options.static_corpus),
                tuple_list!(
                    IrMinimizerStage::<CuttingMinimizer, _, _>::new(trace_handle.clone()),
                    IrMinimizerStage::<NoppingMinimizer, _, _>::new(trace_handle.clone()),
                    IrMinimizerStage::<BlockMinimizer, _, _>::new(trace_handle.clone()),
                    IrMinimizerStage::<NoppingMinimizer, _, _>::new(trace_handle.clone())
                )
            ),
            TuneableMutationalStage::new(&mut state, mutator)
        );
        self.fuzz(&mut state, &mut fuzzer, &mut executor, &mut stages)
    }

    fn fuzz<Z, E, ST>(
        &mut self,
        state: &mut ClientState,
        fuzzer: &mut Z,
        executor: &mut E,
        stages: &mut ST,
    ) -> Result<(), Error>
    where
        Z: Fuzzer<E, ClientMgr<M>, IrInput, ClientState, ST>
            + Evaluator<E, ClientMgr<M>, IrInput, ClientState>,
        ST: StagesTuple<E, ClientMgr<M>, ClientState, Z>,
    {
        let corpus_dirs = [self.options.input_dir()];

        if state.must_load_initial_inputs() {
            if self.options.static_corpus {
                state
                    .load_initial_inputs_forced(fuzzer, executor, &mut self.mgr, &corpus_dirs)
                    .unwrap_or_else(|_| {
                        println!("Failed to load initial corpus at {corpus_dirs:?}");
                        process::exit(0);
                    });
            } else {
                state
                    .load_initial_inputs(fuzzer, executor, &mut self.mgr, &corpus_dirs)
                    .unwrap_or_else(|_| {
                        println!("Failed to load initial corpus at {corpus_dirs:?}");
                        process::exit(0);
                    });
            }
            println!("We imported {} inputs from disk.", state.corpus().count());
        }

        if let Some(iters) = self.options.iterations {
            fuzzer.fuzz_loop_for(stages, executor, state, &mut self.mgr, iters)?;

            // It's important, that we store the state before restarting!
            // Else, the parent will not respawn a new child and quit.
            self.mgr.on_restart(state)?;
        } else {
            fuzzer.fuzz_loop(stages, executor, state, &mut self.mgr)?;
        }

        Ok(())
    }
}
