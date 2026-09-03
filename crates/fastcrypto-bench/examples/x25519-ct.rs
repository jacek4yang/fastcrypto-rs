//! One X25519 operation per process, for constant-time analysis.
//!
//! Deliberately minimal, because everything this program does that is *not* the
//! curve operation has to cost the same for every input. In particular it does
//! not print the result: formatting a value derived from the secret is
//! input-dependent work, and the first version of this harness reported a
//! ~240-instruction spread that turned out to be exactly that — the hex
//! formatter, not the curve.
//!
//! Usage: `x25519-ct <agree|base> <variant> <scalar-hex> [point-hex]`, where
//! `variant` is `dispatch`, or a named compiled variant so that a machine can
//! review the path it would not otherwise take.
//!
//! Driven by `scripts/constant-time-x25519.sh`.

use std::env;
use std::hint::black_box;
use std::process::ExitCode;

fn unhex(text: &str) -> [u8; 32] {
    assert_eq!(text.len(), 64, "expected 32 hex-encoded bytes");
    let mut out = [0_u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).expect("hex digit");
    }
    out
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn run(operation: &str, variant: &str, scalar: &[u8; 32], point: &[u8; 32]) {
    use fastcrypto_x86::x25519;

    let mut out = [0_u8; 32];
    match (operation, variant) {
        ("agree", "dispatch") => x25519::x25519(&mut out, black_box(scalar), black_box(point)),
        ("agree", "baseline") => {
            x25519::x25519_baseline(&mut out, black_box(scalar), black_box(point));
        }
        ("agree", "adx") => {
            // SAFETY: the driver only asks for this variant on a machine whose
            // CPUID reported BMI2 and ADX.
            unsafe { x25519::x25519_adx(&mut out, black_box(scalar), black_box(point)) }
        }
        ("base", "dispatch") => x25519::x25519_base(&mut out, black_box(scalar)),
        ("base", "baseline") => x25519::x25519_base_baseline(&mut out, black_box(scalar)),
        // SAFETY: as above.
        ("base", "adx") => unsafe { x25519::x25519_base_adx(&mut out, black_box(scalar)) },
        _ => panic!("usage: x25519-ct <agree|base> <dispatch|baseline|adx> <scalar> [point]"),
    }
    black_box(&out);
}

#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
fn run(operation: &str, variant: &str, scalar: &[u8; 32], point: &[u8; 32]) {
    use fastcrypto_aarch64::x25519;

    let mut out = [0_u8; 32];
    match (operation, variant) {
        ("agree", "dispatch") => x25519::x25519(&mut out, black_box(scalar), black_box(point)),
        ("agree", "standard") => {
            x25519::x25519_standard(&mut out, black_box(scalar), black_box(point));
        }
        ("agree", "wide-multiplier") => {
            x25519::x25519_wide_multiplier(&mut out, black_box(scalar), black_box(point));
        }
        ("base", "dispatch") => x25519::x25519_base(&mut out, black_box(scalar)),
        ("base", "standard") => x25519::x25519_base_standard(&mut out, black_box(scalar)),
        ("base", "wide-multiplier") => {
            x25519::x25519_base_wide_multiplier(&mut out, black_box(scalar));
        }
        _ => panic!(
            "usage: x25519-ct <agree|base> <dispatch|standard|wide-multiplier> <scalar> [point]"
        ),
    }
    black_box(&out);
}

#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
fn run(_operation: &str, _variant: &str, _scalar: &[u8; 32], _point: &[u8; 32]) {
    panic!("X25519 is only implemented for x86_64 and AArch64 Linux");
}

fn main() -> ExitCode {
    let arguments: Vec<String> = env::args().collect();
    if arguments.len() < 4 {
        eprintln!("usage: x25519-ct <agree|base> <variant> <scalar-hex> [point-hex]");
        return ExitCode::FAILURE;
    }
    let scalar = unhex(&arguments[3]);
    let point = arguments.get(4).map_or([0_u8; 32], |text| unhex(text));
    run(&arguments[1], &arguments[2], &scalar, &point);
    ExitCode::SUCCESS
}
