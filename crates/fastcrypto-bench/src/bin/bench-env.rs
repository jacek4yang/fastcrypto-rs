//! Prints the benchmark environment report.
//!
//! Run with cargo run --bin bench-env before recording results; the output goes
//! at the top of every file in `benchmarks/results/`.

fn main() {
    print!("{}", fastcrypto_bench::environment_report());
}
