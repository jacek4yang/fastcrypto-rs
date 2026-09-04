//! SHA-256: portable baseline against established implementations.
//!
//! Competitors: RustCrypto `sha2`, ring, aws-lc-rs. All of them are
//! dev-dependencies of this crate only.
//!
//! Groups:
//! * `oneshot` - hash a complete message, the common case for
//!   transcripts and certificates;
//! * `padding-boundaries` - the lengths where the padding path changes shape;
//! * `streaming` - absorb a 64 KiB message in 1 KiB updates;
//! * `init` - context construction, which dominates small-record work;
//! * `tls13-transcript` - **the shape that decides a migration**: six
//!   incremental messages with four clone-and-finalize snapshots, at the two
//!   totals rust-reality actually produces.

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

/// Padding-boundary sizes: the lengths around the 55/56/64 and 119/120/128
/// byte edges where the padding path changes shape. These are the sizes a TLS
/// implementation actually hits for small handshake structures and labels.
fn padding_boundaries(c: &mut criterion::Criterion) {
    const BOUNDARIES: &[usize] = &[
        55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 129, 191, 192, 193,
    ];
    let mut group = c.benchmark_group("sha256/padding-boundaries");
    for &len in BOUNDARIES {
        group.throughput(common::throughput(len));
        let data = common::message(len);
        let id = common::label(len);

        group.bench_with_input(BenchmarkId::new("fastcrypto", &id), &data, |b, data| {
            b.iter(|| black_box(fastcrypto::sha256(black_box(data))));
        });
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
        group.bench_with_input(
            BenchmarkId::new("rustcrypto-sha2", &id),
            &data,
            |b, data| {
                use sha2::Digest;
                b.iter(|| black_box(sha2::Sha256::digest(black_box(data))));
            },
        );
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

/// The TLS 1.3 handshake transcript, exactly as rust-reality drives it.
///
/// `TranscriptHasher` absorbs the handshake messages incrementally and takes a
/// **snapshot** at four milestones — `ClientHello`, `ServerHello`, the server
/// flight, and the client Finished — each of which clones the running hasher
/// and finalizes the copy without disturbing it. Neither `oneshot` nor
/// `streaming` measures that: one hashes a complete message, the other never
/// clones. Whether an implementation is a good fit for this codebase is
/// decided here, because this is the shape that runs once per session.
///
/// Two totals, both from rust-reality's own inventory: ~944 B for the
/// classical X25519 handshake and ~3.2 KiB when the hybrid X25519MLKEM768 key
/// share inflates the `ClientHello`.
fn tls13_transcript(c: &mut criterion::Criterion) {
    use sha2::Digest;

    // Six messages, four snapshots, in the order the server takes them.
    // `snapshot_after` marks the message indices a snapshot follows.
    fn flight(total: usize) -> (Vec<Vec<u8>>, [bool; 6]) {
        // The ClientHello carries the bulk; the rest are the fixed server flight.
        let fixed = [128usize, 24, 640, 80, 52];
        let client_hello = total.saturating_sub(fixed.iter().sum::<usize>()).max(1);
        let mut messages = vec![common::message(client_hello)];
        for len in fixed {
            messages.push(common::message(len));
        }
        (messages, [true, true, false, false, true, true])
    }

    for (name, total) in [("classical-944B", 944usize), ("hybrid-3.2KiB", 3277usize)] {
        let (messages, snapshot_after) = flight(total);
        let mut group = c.benchmark_group(format!("sha256/tls13-transcript/{name}"));
        group.throughput(common::throughput(total));

        group.bench_function("fastcrypto", |b| {
            b.iter(|| {
                let mut state = Sha256::new();
                let mut last = [0u8; 32];
                for (index, message) in messages.iter().enumerate() {
                    state.update(black_box(message));
                    if snapshot_after[index] {
                        last = state.clone().finalize();
                    }
                }
                black_box(last)
            });
        });

        group.bench_function("rustcrypto-sha2", |b| {
            b.iter(|| {
                let mut state = sha2::Sha256::new();
                let mut last = [0u8; 32];
                for (index, message) in messages.iter().enumerate() {
                    state.update(black_box(message));
                    if snapshot_after[index] {
                        last.copy_from_slice(&state.clone().finalize());
                    }
                }
                black_box(last)
            });
        });

        // ring and aws-lc-rs contexts are `Clone`, so the same shape is
        // expressible and the incumbent set stays complete.
        group.bench_function("ring", |b| {
            b.iter(|| {
                let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
                let mut last = [0u8; 32];
                for (index, message) in messages.iter().enumerate() {
                    ctx.update(black_box(message));
                    if snapshot_after[index] {
                        last.copy_from_slice(ctx.clone().finish().as_ref());
                    }
                }
                black_box(last)
            });
        });

        group.bench_function("aws-lc-rs", |b| {
            b.iter(|| {
                let mut ctx = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
                let mut last = [0u8; 32];
                for (index, message) in messages.iter().enumerate() {
                    ctx.update(black_box(message));
                    if snapshot_after[index] {
                        last.copy_from_slice(ctx.clone().finish().as_ref());
                    }
                }
                black_box(last)
            });
        });

        group.finish();
    }
}

/// The same transcript under `AES-256-GCM-SHA384`, where the digest has no
/// hardware backend on either side and the comparison is portable code
/// against portable code.
fn tls13_transcript_sha384(c: &mut criterion::Criterion) {
    use sha2::Digest;

    let messages: Vec<Vec<u8>> = [816usize, 128, 24, 640, 80, 52]
        .iter()
        .map(|len| common::message(*len))
        .collect();
    let snapshot_after = [true, true, false, false, true, true];

    let mut group = c.benchmark_group("sha384/tls13-transcript");
    group.throughput(common::throughput(messages.iter().map(Vec::len).sum()));

    group.bench_function("fastcrypto", |b| {
        b.iter(|| {
            let mut state = fastcrypto::Sha384::new();
            let mut last = [0u8; 48];
            for (index, message) in messages.iter().enumerate() {
                state.update(black_box(message));
                if snapshot_after[index] {
                    last = state.clone().finalize();
                }
            }
            black_box(last)
        });
    });

    group.bench_function("rustcrypto-sha2", |b| {
        b.iter(|| {
            let mut state = sha2::Sha384::new();
            let mut last = [0u8; 48];
            for (index, message) in messages.iter().enumerate() {
                state.update(black_box(message));
                if snapshot_after[index] {
                    last.copy_from_slice(&state.clone().finalize());
                }
            }
            black_box(last)
        });
    });

    group.bench_function("ring", |b| {
        b.iter(|| {
            let mut ctx = ring::digest::Context::new(&ring::digest::SHA384);
            let mut last = [0u8; 48];
            for (index, message) in messages.iter().enumerate() {
                ctx.update(black_box(message));
                if snapshot_after[index] {
                    last.copy_from_slice(ctx.clone().finish().as_ref());
                }
            }
            black_box(last)
        });
    });

    group.finish();
}

criterion_group! {
    name = benches;
    config = common::criterion();
    targets = oneshot, padding_boundaries, streaming, init_cost, tls13_transcript, tls13_transcript_sha384
}
criterion_main!(benches);
