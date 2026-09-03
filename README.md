# fastcrypto-rs

Cryptographic research and staging for
**[rust-reality](https://github.com/jacek4yang/rust-reality)**.

> **This is not a cryptography library you should use.**
>
> It is a temporary staging repository. Its purpose is to research, implement,
> benchmark and harden the cryptographic primitives that rust-reality actually
> performs, outside the production tree where experiments are cheap — and then
> to have the successful parts **absorbed into rust-reality**, at which point
> this repository is archived.
>
> Not audited. Not constant-time verified. Not a general-purpose library, not
> a competitor to `ring`, `aws-lc-rs` or RustCrypto, and not something to
> depend on. rust-reality's production build does not depend on it and is not
> intended to.

## What it is for

rust-reality is a VLESS + REALITY + Vision proxy whose cost is dominated by
**session establishment on 1–2 vCPU virtualized Linux hosts**. Its crypto is
not a generic TLS stack: it is a specific, measured set of operations at
specific sizes, several of which run once per session and none of which look
like a megabyte-throughput benchmark.

This repository exists to answer one question per primitive:

> Can rust-reality own this implementation, and is doing so better than the
> mature provider it uses today?

"Better" means measured on rust-reality's shapes, on representative hardware,
against the **incumbent** — not against a convenient baseline. The incumbents
are strong and were selected on evidence:

| primitive | rust-reality's current provider | why it is there |
| --- | --- | --- |
| X25519 (per session, ×3) | `aws-lc-rs` | measured **−12.3% server CPU per session**; 2.41x on variable-base agreement |
| AES-128/256-GCM, ChaCha20-Poly1305 | `ring` | faster than `aws-lc-rs` at every measured record size |
| SHA-256/384, HMAC, HKDF | RustCrypto (`sha2`/`hmac`/`hkdf`) | on SHA-NI hardware `ring` is **9.8% slower per session**; RustCrypto wins |
| Ed25519 | `ed25519-dalek` | the only `no_std`-clean option; `ring` is 23–40% slower |
| ML-KEM-768 | `ml-kem` | out of scope; no measured headroom |

A replacement has to beat *those*. A primitive that loses stays delegated, and
that is a successful outcome of the research, not a failure of it.

## Where the work actually stands

Honest, and it matters more than the layering diagram:

| primitive | implemented here | vs rust-reality's incumbent |
| --- | --- | --- |
| SHA-256 (portable + x86 SHA-NI) | yes | portable round function now **−187 cycles at 517 B** and **−149 at 1400 B** against RustCrypto `sha2`; +38 to +97 cycles at 0–32 B, which is ~0.03% of a session and is where this work stops |
| HMAC-SHA256, HKDF-SHA256 | yes | not re-measured since the SHA-256 fix; the recorded HKDF deficit is stale rather than refuted |
| SHA-384 / SHA-512, HMAC-SHA384/512, HKDF-SHA384 | yes | rust-reality performs all of them per session; SHA-NI does not accelerate this family |
| X25519 (x86_64 Linux) | yes — s2n-bignum's assembly, imported | **k = 0.99–1.00** against `aws-lc-rs` at both production shapes; parity, with ~2.6 MB of C libcrypto replaced by ~164 KB and no build script |
| AES-GCM, ChaCha20-Poly1305, Ed25519, ML-KEM | benchmark harness only | — |

The recorded numbers under `benchmarks/results/` were taken in a **shared
cloud container**, which is not a measurement host. They are directional only.
X25519 is the one integration candidate; everything else is still research.

## Architecture, and what it is optimised for

Layering is strict, because the layering is the part most likely to survive
into rust-reality:

```
safe public API        ->  fastcrypto
                             |
                       dispatch (backend selection)
                             |
             +---------------+---------------+
             |                               |
    portable backend                architecture backends
    fastcrypto-core             fastcrypto-x86 / fastcrypto-aarch64
    (forbids unsafe_code)       (unsafe allowed, gated, documented)
```

It is deliberately **not** optimised for external consumers. There is no
plugin registry, no runtime provider selection, no SemVer promise and no
stability guarantee — those would be abstraction tax for users who do not
exist. It is optimised for: rigorous testing, honest benchmarking, security
analysis, and clean extraction into rust-reality later.

rust-reality enforces a `no_std + alloc` protocol core
([ADR 0016](https://github.com/jacek4yang/rust-reality/blob/main/docs/adr/0016-protocol-core-is-no-std-ready-but-stays-in-place.md)),
so `fastcrypto-core` is `no_std` and allocation-free, and anything `std`-only
stays behind an adapter. That boundary is not decoration: it is what decided
rust-reality's Ed25519 and SHA provider questions.

## Layout

```
crates/fastcrypto/         safe public API + backend dispatch
crates/fastcrypto-core/    portable, no_std, allocation-free, no unsafe
crates/fastcrypto-x86/     x86_64: CPUID detection, SHA-NI backend
crates/fastcrypto-aarch64/ AArch64: feature probe
crates/fastcrypto-bench/   Criterion + differential tests vs ring/aws-lc-rs/RustCrypto
benchmarks/results/        recorded measurements, with their environment
docs/                      architecture, benchmarking, security model, roadmap
fuzz/                      cargo-fuzz differential targets
```

## Adapting mature implementations

This repository is allowed to port and adapt mature implementations rather than
deriving optimised field arithmetic and assembly from specifications alone.
That permission comes with a rule: every line of adapted code must be traceable
to an identified upstream, exact revision and compatible license *before* it is
written down, and formal verification does not survive modification.

[`docs/PROVENANCE.md`](docs/PROVENANCE.md) is both the policy and the register.

## Working rules

1. **Correctness first.** Standardised constructions only, published
   known-answer vectors, and differential tests against established
   implementations. No invented constructions, ever.
2. **Measure before optimising**, and measure the shape rust-reality uses —
   handshake-sized inputs, not megabyte throughput.
3. **Compare against the incumbent.** Beating a slow baseline proves nothing.
4. **Claims are specific.** "fastcrypto SHA-256 is X% faster at Y bytes on Z
   CPU", never "fastcrypto is faster than ring".
5. **Delegating is a valid result.** The goal is the best rust-reality, not
   the most code written here.

## Quick start

```sh
./scripts/check.sh                         # the gates CI runs
cargo run --release --bin bench-env        # environment report for any result
cargo bench -p fastcrypto-bench --bench sha256
```

## Status and history

Per-primitive readiness lives in [`PROJECT_STATUS.md`](PROJECT_STATUS.md).
Research state, decisions and rejected hypotheses live in this repository's
GitHub issues. `docs/` holds the architecture, benchmarking method, security
model and the provenance register for adapted implementations.

This repository was developed on CNB and migrated to GitHub with its full
history at commit `5129598`; GitHub is now the only authoritative host.

## Retirement

This repository is finished when its production-relevant work has been
migrated into rust-reality or deliberately delegated to mature providers,
rust-reality no longer needs it to build, and the correctness, security and
benchmark coverage that matters lives in rust-reality's own tree. At that
point it is archived read-only — not deleted, because the rejected experiments
are part of the evidence.

## License

Apache-2.0. See `LICENSE`.
