use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use hexvault::stack::{Layer, LayerContext};
use hexvault::{generate_master_key, Vault};

fn benchmark_traversal(c: &mut Criterion) {
    let mut group = c.benchmark_group("traversal");

    // Setup vault once
    let master = generate_master_key().unwrap();
    let mut vault = Vault::new(master);

    // Setup cells
    let cell_a_id = "bench-source";
    let cell_b_id = "bench-dest";
    let mut cell_a = vault.create_cell(cell_a_id.into());
    let mut cell_b = vault.create_cell(cell_b_id.into());

    let ctx = LayerContext::default();

    // Pre-calculate payloads of different sizes
    let sizes = [("100B", 100), ("1KB", 1024), ("10KB", 10 * 1024)];

    for (name, size) in sizes {
        let payload = vec![0u8; size];
        let key = format!("data-{}", name);

        // Store initial data
        vault
            .seal(&mut cell_a, &key, &payload, Layer::AtRest, &ctx)
            .unwrap();

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            criterion::BenchmarkId::from_parameter(name),
            &size,
            |b, &_size| {
                b.iter(|| {
                    // We traverse A -> B
                    // Note: In a real benchmark we might want to reset state, but
                    // overwriting the same key in B is a valid throughput test
                    // for the traverse operation itself.
                    vault
                        .traverse(
                            black_box(&cell_a),
                            black_box(&mut cell_b),
                            black_box(&key),
                            black_box(Layer::AtRest),
                            black_box(&ctx),
                            black_box(&ctx),
                        )
                        .unwrap();
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, benchmark_traversal);
criterion_main!(benches);
