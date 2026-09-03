//! SHA-256: portable baseline against established implementations.
//!
//! Competitors: RustCrypto `sha2`, ring, aws-lc-rs. All of them are
//! dev-dependencies of this crate only.
//!
//! Two groups:
//! * `oneshot` - hash a complete message, the common case for
//!   transcripts and certificates;
//! * `streaming` - absorb a 64 KiB message in 1 KiB updates, the shape
//!   TLS uses while a handshake transcript grows.

mod common;

use std::hint::black_box;

use criterion::{BenchmarkId, criterion_group, criterion_main};

use fastcrypto::Sha256;

fn oneshot(c: &mut criterion::Criterion) {
    let mut group = c.benchmark_group("sha256/oneshot");
    for &len in common::sizes() {
        group.throughput(common::throughput(len));
        let data = common::message(len);
        let id = common::label(len);

        group.bench_with_input(BenchmarkId::new("fastcrypto", &id), &data, |b, data| {
            b.iter(|| black_box(fastcrypto::sha256(black_box(data))));
        });

        group.bench_with_input(
            BenchmarkId::new("rustcrypto-sha2", &id),
            &data,
            |b, data| {
                use sha2::Digest;
                b.iter(|| black_box(sha2::Sha256::digest(black_box(data))));
            },
        );

        group.bench_with_input(BenchmarkId::new("ring", &id), &data, |b, data| {
            b.iter(|| black_box(ring::digest::digest(&ring::digest::SHA256, black_box(data))));
        });

        group.bench_with_input(BenchmarkId::new("aws-lc-rs", &id), &data, |b, data| {
            b.iter(|| {
                black_box(aws_lc_rs::digest::digest(
                    &aws_lc_rs::digest::SHA256,
                    black_box(data),
                ))
            });
        });
    }
    group.finish();
}

fn streaming(c: &mut criterion::Criterion) {
    use sha2::Digest;

    let total = 65536usize;
    let chunk = 1024usize;
    let data = common::message(total);
    let mut group = c.benchmark_group("sha256/streaming");
    group.throughput(common::throughput(total));

    group.bench_function("fastcrypto", |b| {
        b.iter(|| {
            let mut h = Sha256::new();
            for part in data.chunks(chunk) {
                h.update(black_box(part));
            }
            black_box(h.finalize())
        });
    });

    group.bench_function("rustcrypto-sha2", |b| {
        b.iter(|| {
            let mut h = sha2::Sha256::new();
            for part in data.chunks(chunk) {
                h.update(black_box(part));
            }
            black_box(h.finalize())
        });
    });

    group.bench_function("ring", |b| {
        b.iter(|| {
            let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
            for part in data.chunks(chunk) {
                ctx.update(black_box(part));
            }
            black_box(ctx.finish())
        });
    });

    group.bench_function("aws-lc-rs", |b| {
        b.iter(|| {
            let mut ctx = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
            for part in data.chunks(chunk) {
                ctx.update(black_box(part));
            }
            black_box(ctx.finish())
        });
    });

    group.finish();
}

fn init_cost(c: &mut criterion::Criterion) {
    // Initialization cost matters for TLS: handshake hash contexts are created
    // per handshake, and small-record work is dominated by fixed overhead.
    let mut group = c.benchmark_group("sha256/init");
    group.bench_function("fastcrypto", |b| b.iter(|| black_box(Sha256::new())));
    group.bench_function("rustcrypto-sha2", |b| {
        use sha2::Digest;
        b.iter(|| black_box(sha2::Sha256::new()));
    });
    group.finish();
}

criterion_group! {
    name = benches;
    config = common::criterion();
    targets = oneshot, streaming, init_cost
}
criterion_main!(benches);
