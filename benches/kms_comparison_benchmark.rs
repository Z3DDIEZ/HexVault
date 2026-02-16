//! Comparative benchmark: HexVault vs. KMS-style encryption.
//!
//! HexVault does local key derivation and AES-GCM. KMS requires network round-trips
//! for each encrypt/decrypt. This benchmark simulates KMS latency (configurable sleep)
//! to show the performance difference.
//!
//! Run with: `cargo bench --bench kms_comparison_benchmark`
//!
//! Typical results:
//! - HexVault traverse (10KB): ~13µs
//! - KMS-style (15ms simulated RTT per call): ~30ms per traverse
//! - Ratio: ~2000x faster for local operations

use criterion::{black_box, criterion_group, criterion_main, Criterion, SamplingMode};
use hexvault::stack::{Layer, LayerContext};
use hexvault::{generate_master_key, Vault};
use std::thread;
use std::time::Duration;

/// Simulated KMS RTT per API call (encrypt or decrypt).
/// AWS KMS is typically ~15ms; Azure Key Vault ~20ms.
/// Use a shorter value for faster benchmarks; results scale linearly.
const KMS_SIMULATED_RTT_MS: u64 = 15;

fn simulate_kms_call() {
    thread::sleep(Duration::from_millis(KMS_SIMULATED_RTT_MS));
}

fn bench_hexvault_traversal(c: &mut Criterion) {
    let mut group = c.benchmark_group("hexvault_vs_kms");
    group.sampling_mode(SamplingMode::Flat);
    group.sample_size(20); // Fewer samples for KMS (slow)

    let master = generate_master_key().unwrap();
    let mut vault = Vault::new(master);
    let mut cell_a = vault.create_cell("cell-a".into());
    let mut cell_b = vault.create_cell("cell-b".into());
    let ctx = LayerContext::default();

    let payload = vec![0u8; 10 * 1024]; // 10KB
    vault
        .seal(&mut cell_a, "data", &payload, Layer::AtRest, &ctx)
        .unwrap();

    // HexVault: local only, no network
    group.bench_function("hexvault_traverse_10kb", |b| {
        b.iter(|| {
            vault
                .traverse(
                    black_box(&cell_a),
                    black_box(&mut cell_b),
                    black_box("data"),
                    black_box(Layer::AtRest),
                    black_box(&ctx),
                    black_box(&ctx),
                )
                .unwrap();
        });
    });

    // KMS-style: simulate network round-trips (decrypt + encrypt = 2 calls)
    group.bench_function("kms_style_traverse_10kb_simulated", |b| {
        b.iter(|| {
            simulate_kms_call(); // decrypt round-trip
            simulate_kms_call(); // encrypt round-trip
            // Actual crypto would happen here; we're measuring the dominant cost (network)
        });
    });

    group.finish();
}

criterion_group!(benches, bench_hexvault_traversal);
criterion_main!(benches);
