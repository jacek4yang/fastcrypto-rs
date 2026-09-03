# Security Policy

## Status: experimental research code

This repository is an independent research project. It is **not audited**, it is
**not constant-time verified**, and it is **not production ready**. The
implementations here are being written and measured, not hardened.

Do not use this code to protect real data.

## Reporting

If you find a correctness bug, a side channel, or an unsound `unsafe` block,
please open an issue with:

1. what you ran (crate, version, target, CPU, `rustc` version, features),
2. the smallest input that reproduces it,
3. the observed and expected output,
4. for a suspected side channel: the measurement method and the numbers.

A failing known-answer or differential test is the most useful bug report this
project can receive, because the test harness is designed so that such a report
can be turned into a regression test in one step.

## What is in scope

* Divergence from a published test vector.
* Divergence from ring / aws-lc-rs / RustCrypto for the same primitive.
* Unsound or undocumented `unsafe`.
* Secret-dependent branches or memory indexing in generated code.
* Missing zeroization of secret material.
* Panics on adversary-controlled input.

## What is out of scope

* "This library is slow" without a benchmark run and an environment report.
* Reports against a build modified with non-default `RUSTFLAGS` that the
  report does not disclose.
* Anything requiring access to third-party private systems.

## Supported versions

None. There are no releases and no security patches; the repository is a
moving research baseline. If that changes, this file will be replaced with a
real supported-versions table.

