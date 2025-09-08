use fuzzamoto::{
    fuzzamoto_main,
    scenarios::{IgnoredCharacterization, Scenario, ScenarioInput, ScenarioResult},
    targets::{BitcoinCoreTarget, Target},
};
use arbitrary::{Arbitrary, Unstructured};
use capnp_rpc::{RpcSystem, twoparty, rpc_twoparty_capnp};
use tokio::net::UnixStream;
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
use futures::FutureExt;

pub mod common_capnp {
    include!(concat!(env!("OUT_DIR"), "/common_capnp.rs"));
}
pub mod echo_capnp {
    include!(concat!(env!("OUT_DIR"), "/echo_capnp.rs"));
}
pub mod init_capnp {
    include!(concat!(env!("OUT_DIR"), "/init_capnp.rs"));
}
pub mod mining_capnp {
    include!(concat!(env!("OUT_DIR"), "/mining_capnp.rs"));
}
pub mod proxy_capnp {
    include!(concat!(env!("OUT_DIR"), "/proxy_capnp.rs"));
}

pub struct BitcoinMiningClient {
    mining: mining_capnp::mining::Client,
    thread: proxy_capnp::thread::Client,
    _rpc_handle: tokio::task::JoinHandle<()>,
}

impl BitcoinMiningClient {
    pub async fn connect(socket_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let stream = UnixStream::connect(socket_path).await?;
        let (reader, writer) = stream.into_split();
        let reader = reader.compat();
        let writer = writer.compat_write();

        let rpc_network = twoparty::VatNetwork::new(
            reader,
            writer,
            rpc_twoparty_capnp::Side::Client,
            Default::default(),
        );

        let mut rpc_system = RpcSystem::new(Box::new(rpc_network), None);
        let init_client: init_capnp::init::Client = rpc_system.bootstrap(rpc_twoparty_capnp::Side::Server);
        let rpc_handle = tokio::task::spawn_local(rpc_system.map(|_| ()));

        let construct_req = init_client.construct_request();
        let construct_response = construct_req.send().promise.await?;
        let thread_map = construct_response.get()?.get_thread_map()?;

        let mut thread_req = thread_map.make_thread_request();
        thread_req.get().set_name("main");
        let thread_response = thread_req.send().promise.await?;
        let thread = thread_response.get()?.get_result()?;

        let mut mining_request = init_client.make_mining_request();
        let mut context = mining_request.get().init_context();
        context.set_thread(thread.clone());
        context.set_callback_thread(thread.clone());
        let mining_response = mining_request.send().promise.await?;
        let mining = mining_response.get()?.get_result()?;

        Ok(Self {
            mining,
            thread,
            _rpc_handle: rpc_handle,
        })
    }

    pub async fn is_test_chain(&self) -> Result<bool, Box<dyn std::error::Error>> {
        let mut request = self.mining.is_test_chain_request();
        let mut context = request.get().init_context();
        context.set_thread(self.thread.clone());
        context.set_callback_thread(self.thread.clone());
        let response = request.send().promise.await?;
        Ok(response.get()?.get_result())
    }

    pub async fn is_initial_block_download(&self) -> Result<bool, Box<dyn std::error::Error>> {
        let mut request = self.mining.is_initial_block_download_request();
        let mut context = request.get().init_context();
        context.set_thread(self.thread.clone());
        context.set_callback_thread(self.thread.clone());
        let response = request.send().promise.await?;
        Ok(response.get()?.get_result())
    }

    pub async fn get_tip(&self) -> Result<Option<(i32, Vec<u8>)>, Box<dyn std::error::Error>> {
        let mut request = self.mining.get_tip_request();
        let mut context = request.get().init_context();
        context.set_thread(self.thread.clone());
        context.set_callback_thread(self.thread.clone());
        let response = request.send().promise.await?;

        if response.get()?.get_has_result() {
            let tip = response.get()?.get_result()?;
            let height = tip.get_height();
            let hash = tip.get_hash()?.to_vec();
            Ok(Some((height, hash)))
        } else {
            Ok(None)
        }
    }

    pub async fn create_new_block(&self, use_mempool: bool, block_reserved_weight: u64) -> Result<BlockTemplateClient, Box<dyn std::error::Error>> {
        let mut request = self.mining.create_new_block_request();
        let mut options = request.get().init_options();
        options.set_use_mempool(use_mempool);
        options.set_block_reserved_weight(block_reserved_weight);
        options.set_coinbase_output_max_additional_sigops(400);

        let response = request.send().promise.await?;
        let template = response.get()?.get_result()?;

        Ok(BlockTemplateClient {
            template,
            thread: self.thread.clone(),
        })
    }

    pub async fn check_block(&self, block_data: &[u8], check_merkle_root: bool, check_pow: bool) -> Result<(bool, String, String), Box<dyn std::error::Error>> {
        let mut request = self.mining.check_block_request();
        request.get().set_block(block_data);

        let mut options = request.get().init_options();
        options.set_check_merkle_root(check_merkle_root);
        options.set_check_pow(check_pow);

        let response = request.send().promise.await?;
        let result = response.get()?;

        let is_valid = result.get_result();
        let reason = result.get_reason()?.to_string().unwrap();
        let debug = result.get_debug()?.to_string().unwrap();

        Ok((is_valid, reason, debug))
    }
}

pub struct BlockTemplateClient {
    template: mining_capnp::block_template::Client,
    thread: proxy_capnp::thread::Client,
}

impl BlockTemplateClient {
    pub async fn get_block_header(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut request = self.template.get_block_header_request();
        let mut context = request.get().init_context();
        context.set_thread(self.thread.clone());
        context.set_callback_thread(self.thread.clone());
        let response = request.send().promise.await?;
        Ok(response.get()?.get_result()?.to_vec())
    }

    pub async fn get_block(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut request = self.template.get_block_request();
        let mut context = request.get().init_context();
        context.set_thread(self.thread.clone());
        context.set_callback_thread(self.thread.clone());
        let response = request.send().promise.await?;
        Ok(response.get()?.get_result()?.to_vec())
    }

    pub async fn get_tx_fees(&self) -> Result<Vec<i64>, Box<dyn std::error::Error>> {
        let mut request = self.template.get_tx_fees_request();
        let mut context = request.get().init_context();
        context.set_thread(self.thread.clone());
        context.set_callback_thread(self.thread.clone());
        let response = request.send().promise.await?;
        let fees_list = response.get()?.get_result()?;
        let mut fees = Vec::new();
        for i in 0..fees_list.len() {
            fees.push(fees_list.get(i));
        }
        Ok(fees)
    }

    pub async fn get_tx_sigops(&self) -> Result<Vec<i64>, Box<dyn std::error::Error>> {
        let mut request = self.template.get_tx_sigops_request();
        let mut context = request.get().init_context();
        context.set_thread(self.thread.clone());
        context.set_callback_thread(self.thread.clone());
        let response = request.send().promise.await?;
        let sigops_list = response.get()?.get_result()?;
        let mut sigops = Vec::new();
        for i in 0..sigops_list.len() {
            sigops.push(sigops_list.get(i));
        }
        Ok(sigops)
    }

    pub async fn get_coinbase_tx(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut request = self.template.get_coinbase_tx_request();
        let mut context = request.get().init_context();
        context.set_thread(self.thread.clone());
        context.set_callback_thread(self.thread.clone());
        let response = request.send().promise.await?;
        Ok(response.get()?.get_result()?.to_vec())
    }

    pub async fn get_coinbase_commitment(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut request = self.template.get_coinbase_commitment_request();
        let mut context = request.get().init_context();
        context.set_thread(self.thread.clone());
        context.set_callback_thread(self.thread.clone());
        let response = request.send().promise.await?;
        Ok(response.get()?.get_result()?.to_vec())
    }

    pub async fn get_witness_commitment_index(&self) -> Result<i32, Box<dyn std::error::Error>> {
        let mut request = self.template.get_witness_commitment_index_request();
        let mut context = request.get().init_context();
        context.set_thread(self.thread.clone());
        context.set_callback_thread(self.thread.clone());
        let response = request.send().promise.await?;
        Ok(response.get()?.get_result())
    }

    pub async fn get_coinbase_merkle_path(&self) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
        let mut request = self.template.get_coinbase_merkle_path_request();
        let mut context = request.get().init_context();
        context.set_thread(self.thread.clone());
        context.set_callback_thread(self.thread.clone());
        let response = request.send().promise.await?;
        let path_list = response.get()?.get_result()?;
        let mut path = Vec::new();
        for i in 0..path_list.len() {
            path.push(path_list.get(i)?.to_vec());
        }
        Ok(path)
    }

    pub async fn submit_solution(&self, version: u32, timestamp: u32, nonce: u32, coinbase: &[u8]) -> Result<bool, Box<dyn std::error::Error>> {
        let mut request = self.template.submit_solution_request();
        let mut context = request.get().init_context();
        context.set_thread(self.thread.clone());
        context.set_callback_thread(self.thread.clone());
        request.get().set_version(version);
        request.get().set_timestamp(timestamp);
        request.get().set_nonce(nonce);
        request.get().set_coinbase(coinbase);
        let response = request.send().promise.await?;
        Ok(response.get()?.get_result())
    }
}

#[derive(Arbitrary, Debug)]
enum ParamSource<T> {
    Fuzzer(T),
    Pool(u16),
}

#[derive(Arbitrary, Debug)]
enum IpcOperation {
    IsTestChain,
    IsInitialBlockDownload,
    GetTip,
    CreateNewBlock {
        use_mempool: ParamSource<bool>,
        block_reserved_weight: ParamSource<u64>
    },
    CheckBlock {
        block_data: ParamSource<Vec<u8>>,
        check_merkle_root: ParamSource<bool>,
        check_pow: ParamSource<bool>,
    },
    GetBlockHeader,
    GetBlock,
    GetTxFees,
    GetTxSigops,
    GetCoinbaseTx,
    GetCoinbaseCommitment,
    GetWitnessCommitmentIndex,
    GetCoinbaseMerklePath,
    SubmitSolution {
        version: ParamSource<u32>,
        timestamp: ParamSource<u32>,
        nonce: ParamSource<u32>,
        coinbase: ParamSource<Vec<u8>>,
    },
}

#[derive(Arbitrary)]
struct TestCase {
    operations: Vec<IpcOperation>,
}

impl ScenarioInput<'_> for TestCase {
    fn decode(bytes: &[u8]) -> Result<Self, String> {
        let mut unstructured = Unstructured::new(bytes);
        let operations = Vec::arbitrary(&mut unstructured).map_err(|e| e.to_string())?;
        Ok(Self { operations })
    }
}

struct IpcParamPool {
    bools: Vec<bool>,
    u32s: Vec<u32>,
    u64s: Vec<u64>,
    i32s: Vec<i32>,
    i64s: Vec<i64>,
    bytes: Vec<Vec<u8>>,
    hashes: Vec<Vec<u8>>,
}

impl IpcParamPool {
    fn new() -> Self {
        Self {
            bools: Vec::new(),
            u32s: Vec::new(),
            u64s: Vec::new(),
            i32s: Vec::new(),
            i64s: Vec::new(),
            bytes: Vec::new(),
            hashes: Vec::new(),
        }
    }

    fn add_bool(&mut self, value: bool) { self.bools.push(value); }
    fn add_u32(&mut self, value: u32) { self.u32s.push(value); }
    fn add_u64(&mut self, value: u64) { self.u64s.push(value); }
    fn add_i32(&mut self, value: i32) { self.i32s.push(value); }
    fn add_i64(&mut self, value: i64) { self.i64s.push(value); }
    fn add_hash(&mut self, hash: Vec<u8>) { self.hashes.push(hash); }
    fn add_bytes(&mut self, bytes: Vec<u8>) { self.bytes.push(bytes); }
    fn add_fee_list(&mut self, fees: Vec<i64>) { self.i64s.extend(fees); }
    fn add_sigop_list(&mut self, sigops: Vec<i64>) { self.i64s.extend(sigops); }

    fn get_bool(&self, index: u16) -> bool {
        if self.bools.is_empty() { return false; }
        self.bools[index as usize % self.bools.len()]
    }

    fn get_u32(&self, index: u16) -> u32 {
        if self.u32s.is_empty() { return 0; }
        self.u32s[index as usize % self.u32s.len()]
    }

    fn get_u64(&self, index: u16) -> u64 {
        if self.u64s.is_empty() { return 0; }
        self.u64s[index as usize % self.u64s.len()]
    }

    fn get_bytes(&self, index: u16) -> Vec<u8> {
        if self.bytes.is_empty() { return vec![0; 32]; }
        self.bytes[index as usize % self.bytes.len()].clone()
    }

    fn resolve_bool(&self, param: &ParamSource<bool>) -> bool {
        match param {
            ParamSource::Fuzzer(value) => *value,
            ParamSource::Pool(index) => self.get_bool(*index),
        }
    }

    fn resolve_u32(&self, param: &ParamSource<u32>) -> u32 {
        match param {
            ParamSource::Fuzzer(value) => *value,
            ParamSource::Pool(index) => self.get_u32(*index),
        }
    }

    fn resolve_u64(&self, param: &ParamSource<u64>) -> u64 {
        match param {
            ParamSource::Fuzzer(value) => *value,
            ParamSource::Pool(index) => self.get_u64(*index),
        }
    }

    fn resolve_bytes(&self, param: &ParamSource<Vec<u8>>) -> Vec<u8> {
        match param {
            ParamSource::Fuzzer(value) => value.clone(),
            ParamSource::Pool(index) => self.get_bytes(*index),
        }
    }
}

struct IpcMiningScenario {
    target: BitcoinCoreTarget,
    param_pool: IpcParamPool,
    rt: tokio::runtime::Runtime,
    client: BitcoinMiningClient,
}

impl<'a> Scenario<'a, TestCase, IgnoredCharacterization> for IpcMiningScenario {
    fn new(args: &[String]) -> Result<Self, String> {
        let target = BitcoinCoreTarget::from_path(&args[1])?;
        let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
        let socket_path = target.node.workdir().join("regtest").join("node.sock");

        let client = rt.block_on(async {
            let local = tokio::task::LocalSet::new();
            local.run_until(async {
                for _ in 0..50 {
                    if socket_path.exists() {
                        if let Ok(client) = BitcoinMiningClient::connect(socket_path.to_str().unwrap()).await {
                            return Ok(client);
                        }
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
                BitcoinMiningClient::connect(socket_path.to_str().unwrap()).await
            }).await
        }).map_err(|e| format!("Failed to connect to IPC socket: {}", e))?;

        Ok(Self {
            target,
            param_pool: IpcParamPool::new(),
            rt,
            client,
        })
    }

    fn run(&mut self, input: TestCase) -> ScenarioResult<IgnoredCharacterization> {
        self.rt.block_on(async {
            let local = tokio::task::LocalSet::new();
            local.run_until(async {
                let client = &self.client;
                let mut active_template: Option<BlockTemplateClient> = None;

                for operation in input.operations {
                    log::info!("Executing IPC operation: {:?}", operation);

                    match operation {
                        IpcOperation::IsTestChain => {
                            if let Ok(result) = client.is_test_chain().await {
                                self.param_pool.add_bool(result);
                            }
                        }
                        IpcOperation::IsInitialBlockDownload => {
                            if let Ok(result) = client.is_initial_block_download().await {
                                self.param_pool.add_bool(result);
                            }
                        }
                        IpcOperation::GetTip => {
                            if let Ok(Some((height, hash))) = client.get_tip().await {
                                self.param_pool.add_u64(height as u64);
                                self.param_pool.add_hash(hash);
                            }
                        }
                        IpcOperation::CreateNewBlock { use_mempool, block_reserved_weight } => {
                            let use_mempool = self.param_pool.resolve_bool(&use_mempool);
                            let weight = self.param_pool.resolve_u64(&block_reserved_weight);
                            if let Ok(template) = client.create_new_block(use_mempool, weight).await {
                                active_template = Some(template);
                            }
                        }
                        IpcOperation::CheckBlock { block_data, check_merkle_root, check_pow } => {
                            let block_data = self.param_pool.resolve_bytes(&block_data);
                            let check_merkle = self.param_pool.resolve_bool(&check_merkle_root);
                            let check_pow = self.param_pool.resolve_bool(&check_pow);
                            if let Ok((is_valid, reason, debug)) = client.check_block(&block_data, check_merkle, check_pow).await {
                                log::info!("Block check: valid={}, reason={}, debug={}", is_valid, reason, debug);
                                self.param_pool.add_bool(is_valid);
                            }
                        }
                        IpcOperation::GetBlockHeader => {
                            if let Some(ref template) = active_template {
                                if let Ok(header) = template.get_block_header().await {
                                    self.param_pool.add_bytes(header);
                                }
                            }
                        }
                        IpcOperation::GetBlock => {
                            if let Some(ref template) = active_template {
                                if let Ok(block) = template.get_block().await {
                                    self.param_pool.add_bytes(block);
                                }
                            }
                        }
                        IpcOperation::GetTxFees => {
                            if let Some(ref template) = active_template {
                                if let Ok(fees) = template.get_tx_fees().await {
                                    self.param_pool.add_fee_list(fees);
                                }
                            }
                        }
                        IpcOperation::GetTxSigops => {
                            if let Some(ref template) = active_template {
                                if let Ok(sigops) = template.get_tx_sigops().await {
                                    self.param_pool.add_sigop_list(sigops);
                                }
                            }
                        }
                        IpcOperation::GetCoinbaseTx => {
                            if let Some(ref template) = active_template {
                                if let Ok(coinbase) = template.get_coinbase_tx().await {
                                    self.param_pool.add_bytes(coinbase);
                                }
                            }
                        }
                        IpcOperation::GetCoinbaseCommitment => {
                            if let Some(ref template) = active_template {
                                if let Ok(commitment) = template.get_coinbase_commitment().await {
                                    self.param_pool.add_bytes(commitment);
                                }
                            }
                        }
                        IpcOperation::GetWitnessCommitmentIndex => {
                            if let Some(ref template) = active_template {
                                if let Ok(index) = template.get_witness_commitment_index().await {
                                    self.param_pool.add_i32(index);
                                }
                            }
                        }
                        IpcOperation::GetCoinbaseMerklePath => {
                            if let Some(ref template) = active_template {
                                if let Ok(path) = template.get_coinbase_merkle_path().await {
                                    for hash in path {
                                        self.param_pool.add_bytes(hash);
                                    }
                                }
                            }
                        }
                        IpcOperation::SubmitSolution { version, timestamp, nonce, coinbase } => {
                            if let Some(ref template) = active_template {
                                let version = self.param_pool.resolve_u32(&version);
                                let timestamp = self.param_pool.resolve_u32(&timestamp);
                                let nonce = self.param_pool.resolve_u32(&nonce);
                                let coinbase = self.param_pool.resolve_bytes(&coinbase);
                                if let Ok(result) = template.submit_solution(version, timestamp, nonce, &coinbase).await {
                                    self.param_pool.add_bool(result);
                                }
                            }
                        }
                    }
                }
            }).await
        });

        if let Err(e) = self.target.is_alive() {
            return ScenarioResult::Fail(format!("Target died: {}", e));
        }

        ScenarioResult::Ok(IgnoredCharacterization)
    }
}

fuzzamoto_main!(IpcMiningScenario, TestCase);
