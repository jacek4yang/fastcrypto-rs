//! Benchmark environment reporting.
//!
//! A benchmark number without the machine that produced it is noise. Every
//! result file in `benchmarks/results/` must be accompanied by the output of this
//! module, which is also printed by the bench-env binary.

use std::process::Command;

use fastcrypto::backend::Backend;

/// Collects everything needed to reproduce or interpret a measurement.
///
/// Every field is best effort: on an unknown platform the value is reported as
/// "unknown" rather than causing a failure, because a missing label must not
/// block a benchmark run.
#[must_use]
pub fn report() -> String {
    let mut out = String::new();
    macro_rules! line {
        ($k:expr, $v:expr) => {
            out.push_str(&format!(
                "{:>18}: {}
",
                $k, $v
            ));
        };
    }

    line!(
        "project",
        concat!("fastcrypto-rs ", env!("CARGO_PKG_VERSION"))
    );
    line!("backend", Backend::for_sha256());
    line!(
        "hw accel",
        format!("sha256-accelerated={}", Backend::sha256_hardware_support())
    );
    line!("arch", std::env::consts::ARCH);
    line!("os", format!("{} {}", std::env::consts::OS, os_release()));
    line!("cpu", cpu_model().unwrap_or_else(|| "unknown".into()));
    line!("cpu cores", cores());
    line!(
        "scaling gov",
        scaling_governor().unwrap_or_else(|| "unknown".into())
    );
    line!("rustc", rustc_version().unwrap_or_else(|| "unknown".into()));
    line!("llvm", llvm_version().unwrap_or_else(|| "unknown".into()));
    line!("profile", build_profile());
    line!(
        "target features",
        target_features().unwrap_or_else(|| "unknown".into())
    );
    line!(
        "rustflags",
        std::env::var("RUSTFLAGS").unwrap_or_else(|_| "<unset>".into())
    );
    line!(
        "target cpu",
        std::env::var("TARGET_CPU").unwrap_or_else(|_| "<unset>".into())
    );
    line!("estimated mhz", clock_estimate());
    line!("criterion", "0.8 (wall clock, warmup + statistics)");
    out
}

fn target_features() -> Option<String> {
    let out = Command::new("rustc")
        .arg("--print")
        .arg("cfg")
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let feats: Vec<String> = text
        .lines()
        .filter(|l| l.starts_with("target_feature="))
        .filter_map(|l| l.strip_prefix("target_feature="))
        .map(|l| l.trim_matches('"').to_string())
        .collect();
    Some(feats.join(" "))
}

/// Rough clock estimate from a dependent 64-bit add chain.
///
/// The container exposes no `cpu MHz` and no `cpufreq` sysfs, so cycles/byte
/// cannot be derived from the hardware. A dependent add has a latency of
/// one cycle on every CPU we target, so N iterations take about N cycles.
/// Good enough to turn throughput into cycles/byte, not a substitute for a
/// dedicated machine with a fixed frequency.
fn clock_estimate() -> String {
    const N: u64 = 500_000_000;
    let mut x: u64 = 0x1234_5678_9abc_def0;
    let start = std::time::Instant::now();
    for _ in 0..N {
        // black_box keeps the compiler from collapsing the chain into a
        // closed form; without it the loop disappears and the estimate
        // becomes meaningless.
        x = std::hint::black_box(x).wrapping_add(0x9e37_79b9_7f4a_7c15);
    }
    let elapsed = start.elapsed().as_secs_f64();
    std::hint::black_box(x);
    if elapsed <= 0.0 {
        return "unknown".into();
    }
    let mhz = (N as f64) / elapsed / 1_000_000.0;
    format!("{mhz:.0} (dependent-add estimate)")
}

fn os_release() -> String {
    run("uname", &["-sr"]).unwrap_or_else(|| "unknown".into())
}

fn cpu_model() -> Option<String> {
    let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").ok()?;
    for line in cpuinfo.lines() {
        if let Some(rest) = line.strip_prefix("model name")
            && let Some(value) = rest.split_once(':').map(|x| x.1)
        {
            return Some(value.trim().to_string());
        }
    }
    None
}

fn cores() -> String {
    match std::thread::available_parallelism() {
        Ok(n) => n.get().to_string(),
        Err(_) => "unknown".into(),
    }
}

fn scaling_governor() -> Option<String> {
    let path = "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor";
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}

fn rustc_version() -> Option<String> {
    let out = Command::new("rustc").arg("-vV").output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    text.lines().next().map(|l| l.trim().to_string())
}

fn llvm_version() -> Option<String> {
    let out = Command::new("rustc").arg("-vV").output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    text.lines()
        .find(|l| l.starts_with("LLVM version"))
        .map(|l| l.trim().to_string())
}

fn build_profile() -> &'static str {
    if cfg!(debug_assertions) {
        "debug (debug_assertions on)"
    } else {
        "release (debug_assertions off)"
    }
}

fn run(program: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(program).args(args).output().ok()?;
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::report;

    #[test]
    fn report_contains_all_required_fields() {
        let r = report();
        for field in [
            "project",
            "backend",
            "arch",
            "os",
            "cpu",
            "cpu cores",
            "rustc",
            "llvm",
            "rustflags",
        ] {
            assert!(r.contains(field), "missing {field} in report: {r}");
        }
    }
}
