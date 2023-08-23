use criterion::{criterion_group, criterion_main, Criterion};

fn bench_aes(c: &mut Criterion) {
    c.bench_function("aes", |b| {
        let message = [0u8; 16];
        let key = [0u8; 16];
        b.iter(|| {
            tinybear::aes::aes128_trace(message, key);
        });
    });
}

criterion_group! {
    name=aes_benches;
    config=Criterion::default();
    targets=
            bench_aes,
}
criterion_main!(aes_benches);
