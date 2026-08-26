use std::time::Duration;

use rand::{Rng, RngCore, seq::SliceRandom};

use crate::{
    Generator, GeneratorResult, IndexedVariable, Instruction, Operation, PerTestcaseMetadata,
    ProgramBuilder, Variable,
};

use super::GeneratorError;

/// `ReconMessageGenerator` generates programs that send Erlay (BIP-330) transaction
/// reconciliation messages with structured, protocol-plausible payloads.
///
/// Unlike `SendMessageGenerator` (random 64-byte payloads), the payloads here are
/// encoded the way `net_processing` expects, so they reach the reconciliation
/// handlers instead of failing deserialization:
///
/// - `reqtxrcncl`: `u16 set_size` + `u16 q` (q biased towards the valid range,
///   since q > `Q_PRECISION` is an instant protocol violation)
/// - `sketch`: compactsize-prefixed sketch bytes, length mostly a multiple of the
///   4-byte field element size and capped well below `MAX_SKETCH_CAPACITY`
///   (decoding is quadratic in capacity)
/// - `reconcildiff`: `bool` + compactsize-prefixed vec of `u32` short ids
/// - `reqsketchext`: empty payload
///
/// Reconciliation roles are fixed per connection: the node *responds* on inbound
/// peers and *initiates* on `outbound-full-recon` peers, and it disconnects peers
/// that speak from the wrong role. The program context records which of the
/// snapshot's connections play which role, and the generator targets them
/// accordingly:
///
/// - Responder connections: the harness runs initiator rounds (`reqtxrcncl`
///   [-> `reqsketchext`] -> `reconcildiff`), including a variant that first
///   relays a transaction and then requests it back by its real short id.
/// - Initiator connections: the harness advances mock time past
///   `RECON_REQUEST_INTERVAL` so the node sends `reqtxrcncl`, then answers with
///   a sketch, which is the only way to reach the node's sketch decoding.
///
/// A small share of messages still goes to random connections, to keep the
/// wrong-role / not-registered disconnect paths covered.
#[derive(Default)]
pub struct ReconMessageGenerator;

/// BIP-330 q-coefficient wire precision: q is transmitted as `ceil(q * Q_PRECISION)`.
const Q_PRECISION: u16 = (2 << 14) - 1;
/// The q value Bitcoin Core currently sends (`ceil(0.25 * Q_PRECISION)`).
const REALISTIC_Q: u16 = 8192;
/// Maximum sketch capacity (in elements) accepted for initial sketches.
const MAX_SKETCH_CAPACITY: usize = 2 << 12;
/// Largest sketch the generator emits for decoding. Decoding cost is quadratic
/// in capacity (~4s at `MAX_SKETCH_CAPACITY`, and extensions decode at twice the
/// capacity), so stay far below the protocol limit to keep testcases fast.
const MAX_GENERATED_SKETCH_CAPACITY: usize = 1024;
/// Serialized bytes per sketch element (32-bit field).
const BYTES_PER_SKETCH_ELEMENT: usize = 4;
/// Interval at which the node initiates reconciliation with its outbound
/// reconciliation peers (`RECON_REQUEST_INTERVAL`).
const RECON_REQUEST_INTERVAL_SECS: u64 = 30;

fn compact_size(len: usize) -> Vec<u8> {
    if len < 253 {
        vec![u8::try_from(len).unwrap()]
    } else if len <= 0xFFFF {
        let mut v = vec![0xFD];
        v.extend_from_slice(&u16::try_from(len).unwrap().to_le_bytes());
        v
    } else {
        let mut v = vec![0xFE];
        v.extend_from_slice(&u32::try_from(len).unwrap().to_le_bytes());
        v
    }
}

fn reqtxrcncl_payload<R: RngCore>(rng: &mut R) -> Vec<u8> {
    let set_size: u16 = match rng.gen_range(0..10) {
        // Never 0: the node answers a zero set size with an empty sketch, which
        // ends the round before it exercises anything interesting
        0..=6 => rng.gen_range(1..=64),
        7..=8 => rng.gen_range(0..=3000),
        // Beyond MAX_RECONSET_SIZE; clamped by the node, never a violation
        _ => rng.r#gen(),
    };
    let q: u16 = match rng.gen_range(0..10) {
        0..=6 => REALISTIC_Q,
        7..=8 => rng.gen_range(0..=Q_PRECISION),
        // Out of range: exercises the protocol violation path
        _ => rng.gen_range(Q_PRECISION + 1..=u16::MAX),
    };

    let mut payload = Vec::with_capacity(4);
    payload.extend_from_slice(&set_size.to_le_bytes());
    payload.extend_from_slice(&q.to_le_bytes());
    payload
}

fn sketch_payload<R: RngCore>(rng: &mut R) -> Vec<u8> {
    // Keep capacities small most of the time: sketch decoding is quadratic in
    // capacity, so near-maximum sketches would dominate testcase runtime.
    let capacity = match rng.gen_range(0..20) {
        // Empty sketch: triggers the early termination path
        0 => 0,
        1..=13 => rng.gen_range(1..=32),
        14..=18 => rng.gen_range(33..=MAX_GENERATED_SKETCH_CAPACITY),
        // Over the limit: rejected before decoding
        _ => rng.gen_range(MAX_SKETCH_CAPACITY + 1..=MAX_SKETCH_CAPACITY + 64),
    };

    let mut sketch = vec![0u8; capacity * BYTES_PER_SKETCH_ELEMENT];
    rng.fill_bytes(&mut sketch);

    // Occasionally corrupt the length so it is not a multiple of the element
    // size, which the node rejects as a malformed sketch
    if !sketch.is_empty() && rng.gen_bool(0.1) {
        sketch.truncate(sketch.len() - rng.gen_range(1..BYTES_PER_SKETCH_ELEMENT));
    }

    let mut payload = compact_size(sketch.len());
    payload.extend_from_slice(&sketch);
    payload
}

fn reconcildiff_payload<R: RngCore>(rng: &mut R) -> Vec<u8> {
    let recon_result = rng.gen_bool(0.5);
    // The node disconnects peers asking for more short ids than the sketch it
    // sent could have yielded, so stay small most of the time
    let num_shortids = match rng.gen_range(0..10) {
        0..=6 => rng.gen_range(0..=8usize),
        7..=8 => rng.gen_range(9..=64),
        _ => rng.gen_range(8192..=8200),
    };

    let mut payload = vec![u8::from(recon_result)];
    payload.extend_from_slice(&compact_size(num_shortids));
    for _ in 0..num_shortids {
        payload.extend_from_slice(&rng.r#gen::<u32>().to_le_bytes());
    }
    payload
}

fn type_as_bytes(t: &str) -> [char; 12] {
    let mut bytes = ['\0'; 12];
    for (i, &b) in t.as_bytes().iter().enumerate() {
        bytes[i] = b as char;
    }
    bytes
}

fn append_send(builder: &mut ProgramBuilder, conn_index: usize, msg_type: &str, payload: Vec<u8>) {
    let msg_type_var = builder
        .append(Instruction {
            inputs: vec![],
            operation: Operation::LoadMsgType(type_as_bytes(msg_type)),
        })
        .expect("Inserting LoadMsgType should always succeed")
        .pop()
        .expect("LoadMsgType should always produce a var");

    let bytes_var = builder
        .append(Instruction {
            inputs: vec![],
            operation: Operation::LoadBytes(payload),
        })
        .expect("Inserting LoadBytes should always succeed")
        .pop()
        .expect("LoadBytes should always produce a var");

    builder
        .append(Instruction {
            inputs: vec![conn_index, msg_type_var.index, bytes_var.index],
            operation: Operation::SendRawMessage,
        })
        .expect("Inserting SendRawMessage should always succeed");
}

/// Load one of the given pre-existing connections (by index) as a variable.
fn load_connection_from<R: RngCore>(
    builder: &mut ProgramBuilder,
    rng: &mut R,
    candidates: &[usize],
) -> IndexedVariable {
    let index = *candidates
        .choose(rng)
        .expect("candidates must not be empty");
    builder
        .append(Instruction {
            inputs: vec![],
            operation: Operation::LoadConnection(index),
        })
        .expect("Inserting LoadConnection should always succeed")
        .pop()
        .expect("LoadConnection should always produce a var")
}

/// Advance the node's mock time by `secs`, so that time-driven behaviour (tx
/// announcement / reconciliation-set population, reconciliation initiation)
/// happens before the next message is processed.
fn append_advance_time(builder: &mut ProgramBuilder, secs: u64) {
    let time_var = match builder.get_nearest_variable(&Variable::Time) {
        Some(v) => v,
        None => builder
            .append(Instruction {
                inputs: vec![],
                operation: Operation::LoadTime(builder.context().timestamp),
            })
            .expect("Inserting LoadTime should always succeed")
            .pop()
            .expect("LoadTime should always produce a var"),
    };
    let duration_var = builder
        .append(Instruction {
            inputs: vec![],
            operation: Operation::LoadDuration(Duration::from_secs(secs)),
        })
        .expect("Inserting LoadDuration should always succeed")
        .pop()
        .expect("LoadDuration should always produce a var");
    let new_time = builder
        .append(Instruction {
            inputs: vec![time_var.index, duration_var.index],
            operation: Operation::AdvanceTime,
        })
        .expect("Inserting AdvanceTime should always succeed")
        .pop()
        .expect("AdvanceTime should always produce a var");
    builder
        .append(Instruction {
            inputs: vec![new_time.index],
            operation: Operation::SetTime,
        })
        .expect("Inserting SetTime should always succeed");
}

/// Send a harmless `ping` on `conn_index`. Setting mock time is a bare RPC call,
/// so this forces the message roundtrip that lets the node's `SendMessages` act
/// on the new time (announce transactions, initiate reconciliation) before the
/// next reconciliation message is processed.
fn append_sync<R: RngCore>(builder: &mut ProgramBuilder, rng: &mut R, conn_index: usize) {
    append_send(
        builder,
        conn_index,
        "ping",
        rng.r#gen::<u64>().to_le_bytes().to_vec(),
    );
}

impl<R: RngCore> Generator<R> for ReconMessageGenerator {
    fn generate(
        &self,
        builder: &mut ProgramBuilder,
        rng: &mut R,
        _meta: Option<&PerTestcaseMetadata>,
    ) -> GeneratorResult {
        let context = builder.context().clone();
        if context.num_connections == 0 {
            return Err(GeneratorError::InvalidContext(context));
        }
        let responders = &context.recon_responder_connections;
        let initiators = &context.recon_initiator_connections;

        // Node-initiated round: push mock time past the request interval so the
        // node sends us `reqtxrcncl` on its next SendMessages pass, then answer
        // with a sketch. Random sketches fail to decode, which makes the node ask
        // for an extension; sometimes answer that too.
        if !initiators.is_empty() && rng.gen_bool(0.25) {
            let conn = load_connection_from(builder, rng, initiators);
            append_advance_time(
                builder,
                RECON_REQUEST_INTERVAL_SECS + rng.gen_range(1..=30),
            );
            append_sync(builder, rng, conn.index);
            append_send(builder, conn.index, "sketch", sketch_payload(rng));
            if rng.gen_bool(0.5) {
                append_send(builder, conn.index, "sketch", sketch_payload(rng));
            }
            return Ok(());
        }

        // Harness-initiated rounds go to a responder connection most of the time;
        // the rest goes to a random connection to cover the wrong-role and
        // not-registered disconnect paths.
        let recon_conn_idx = if !responders.is_empty() && rng.gen_bool(0.8) {
            *responders.choose(rng).unwrap()
        } else {
            rng.gen_range(0..context.num_connections)
        };
        let recon_conn = builder
            .append(Instruction {
                inputs: vec![],
                operation: Operation::LoadConnection(recon_conn_idx),
            })
            .expect("Inserting LoadConnection should always succeed")
            .pop()
            .expect("LoadConnection should always produce a var");

        // Reconcile a known transaction: relay it on a *different* connection (the
        // node never adds a transaction to the reconciliation set of the peer it
        // learned it from), let the node's inv timer add it to the reconciliation
        // set of the recon peer, then request it back by its real short id.
        if context.num_connections >= 2
            && rng.gen_bool(0.3)
            && let Some(tx_var) = builder.get_random_variable(rng, &Variable::ConstTx)
        {
            let mut tx_conn_idx = rng.gen_range(0..context.num_connections - 1);
            if tx_conn_idx >= recon_conn_idx {
                tx_conn_idx += 1;
            }
            let tx_conn = builder
                .append(Instruction {
                    inputs: vec![],
                    operation: Operation::LoadConnection(tx_conn_idx),
                })
                .expect("Inserting LoadConnection should always succeed")
                .pop()
                .expect("LoadConnection should always produce a var");

            builder
                .append(Instruction {
                    inputs: vec![tx_conn.index, tx_var.index],
                    operation: Operation::SendTx,
                })
                .expect("Inserting SendTx should always succeed");

            // Transactions are announced (and added to reconciliation sets) on a
            // Poisson timer of a few seconds; jump well past it.
            append_advance_time(builder, rng.gen_range(10..=120));
            append_sync(builder, rng, recon_conn.index);

            append_send(
                builder,
                recon_conn.index,
                "reqtxrcncl",
                reqtxrcncl_payload(rng),
            );
            builder
                .append(Instruction {
                    inputs: vec![recon_conn.index, tx_var.index],
                    operation: Operation::SendReconDiff {
                        success: rng.gen_bool(0.8),
                    },
                })
                .expect("Inserting SendReconDiff should always succeed");

            return Ok(());
        }

        let conn_var = recon_conn;

        if rng.gen_bool(0.4) {
            // Full initiator round on one connection: request a reconciliation,
            // optionally ask for a sketch extension, then finalize. The node
            // advances its responder phase between messages (SendMessages runs
            // on the ping/pong roundtrips between sends).
            append_send(builder, conn_var.index, "reqtxrcncl", reqtxrcncl_payload(rng));
            if rng.gen_bool(0.5) {
                append_send(builder, conn_var.index, "reqsketchext", vec![]);
            }
            append_send(
                builder,
                conn_var.index,
                "reconcildiff",
                reconcildiff_payload(rng),
            );
        } else {
            // A lone sketch on a responder connection is a wrong-role violation;
            // keep a little of that, the real sketch coverage comes from the
            // node-initiated flow above.
            let (msg_type, payload) = match rng.gen_range(0..10) {
                0..=3 => ("reqtxrcncl", reqtxrcncl_payload(rng)),
                4 => ("sketch", sketch_payload(rng)),
                5..=7 => ("reconcildiff", reconcildiff_payload(rng)),
                _ => ("reqsketchext", vec![]),
            };
            append_send(builder, conn_var.index, msg_type, payload);
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "ReconMessageGenerator"
    }
}
