#!/usr/bin/env bash
# Constant-time evidence for the imported X25519 assembly.
#
# The property under test: the work the routines do must not depend on the
# secret scalar, nor on the peer encoding an attacker chooses. Valgrind counts
# instructions and simulated data accesses deterministically, so "the same
# count for every input" is a repeatable claim rather than a timing impression
# on a noisy machine.
#
# What this does NOT show is stated in docs/SECURITY_MODEL.md and matters:
# identical *counts* are not identical *addresses*, and nothing here measures
# the real CPU.
#
# Needs valgrind. Takes a few minutes; it is not part of ./scripts/check.sh.
set -euo pipefail

cd "$(dirname "$0")/.."

command -v valgrind >/dev/null || {
    printf 'valgrind is required\n' >&2
    exit 1
}

cargo build --release -p fastcrypto-bench --example x25519-ct
readonly harness=target/release/examples/x25519-ct

# Variants to review. The dispatched path is what production runs; the others
# are compiled in and would run on other hardware, so reviewing only the
# dispatched one would leave a shipped path unexamined.
case "$(uname -m)" in
    x86_64) variants=(dispatch baseline adx) ;;
    aarch64) variants=(dispatch standard wide-multiplier) ;;
    *)
        printf 'unsupported architecture: %s\n' "$(uname -m)" >&2
        exit 1
        ;;
esac

# On x86_64 the ADX routines are only executable where CPUID says so.
if [[ "$(uname -m)" == x86_64 ]] && ! grep -qw adx /proc/cpuinfo; then
    variants=(dispatch baseline)
    printf 'note: no ADX on this CPU; reviewing the baseline routines only\n'
fi

scalars() {
    local index
    for index in $(seq 0 23); do
        printf '%s' "$index" | sha256sum | cut -d' ' -f1
    done
}

# Sixteen arbitrary peer encodings, then every input a peer can actually choose
# to be awkward: the canonical low-order points, the non-canonical encodings of
# them, and all-ones.
peers() {
    local index
    for index in $(seq 0 15); do
        printf 'peer%s' "$index" | sha256sum | cut -d' ' -f1
    done
    cat <<'POINTS'
0000000000000000000000000000000000000000000000000000000000000000
0100000000000000000000000000000000000000000000000000000000000000
e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800
5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157
ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f
edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f
eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f
ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
POINTS
}

readonly fixed_point=de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f
readonly fixed_scalar=77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a

instructions() {
    valgrind --tool=callgrind --callgrind-out-file=/dev/null "$@" 2>&1 >/dev/null |
        grep -i 'refs' | sed 's/.*refs: *//' | tr -d ,
}

accesses() {
    # One line per invocation. `tr` alone would strip the trailing newline and
    # concatenate every run into a single line, at which point `sort -u` sees
    # one value and the check passes whatever it measured — a check that cannot
    # fail is worse than no check.
    valgrind --tool=cachegrind --cache-sim=yes --cachegrind-out-file=/dev/null "$@" 2>&1 >/dev/null |
        grep -E 'D +refs|D1 +misses|LLd +misses' |
        sed 's/==[0-9]*== *//; s/  */ /g' | tr '\n' '|'
}

failures=0
readonly scratch="$(mktemp -d)"
trap 'rm -rf -- "$scratch"' EXIT

# Asserts that a collected file holds one distinct measurement. Each line is
# "<input> <measurement>", so a failure names the inputs that disagreed rather
# than only the numbers — without that, a rare disagreement is undiagnosable.
#
# Not a pipeline: a counter incremented in a subshell would be discarded and the
# script would report success on a real failure.
#
# Only measurements from the *same* run are compared. Absolute counts shift by a
# handful with the process environment, because that moves the initial stack and
# therefore cache-set alignment, so numbers from different runs are not
# comparable and nothing here compares them.
expect_one_value() {
    local label="$1" file="$2" distinct count
    distinct="$(cut -d' ' -f2- "$file" | sort -u)"
    count="$(printf '%s\n' "$distinct" | wc -l)"
    if [[ "$count" -eq 1 ]]; then
        printf '  PASS %-46s %s\n' "$label" "$distinct"
    else
        printf '  FAIL %-46s %s distinct measurements:\n' "$label" "$count"
        sort -k2 "$file" | sed 's/^/       /'
        failures=$((failures + 1))
    fi
}

for variant in "${variants[@]}"; do
    printf '\n== %s ==\n' "$variant"

    : > "$scratch/out"
    while read -r scalar; do
        printf '%s %s\n' "${scalar:0:16}" \
            "$(instructions "$harness" agree "$variant" "$scalar" "$fixed_point")" >> "$scratch/out"
    done < <(scalars)
    expect_one_value "agree: instructions over 24 secret scalars" "$scratch/out"

    : > "$scratch/out"
    while read -r peer; do
        printf '%s %s\n' "${peer:0:16}" \
            "$(instructions "$harness" agree "$variant" "$fixed_scalar" "$peer")" >> "$scratch/out"
    done < <(peers)
    expect_one_value "agree: instructions over 24 peer encodings" "$scratch/out"

    : > "$scratch/out"
    while read -r scalar; do
        printf '%s %s\n' "${scalar:0:16}" \
            "$(instructions "$harness" base "$variant" "$scalar")" >> "$scratch/out"
    done < <(scalars)
    expect_one_value "base: instructions over 24 secret scalars" "$scratch/out"

    : > "$scratch/out"
    while read -r scalar; do
        printf '%s %s\n' "${scalar:0:16}" \
            "$(accesses "$harness" agree "$variant" "$scalar" "$fixed_point")" >> "$scratch/out"
    done < <(scalars | head -12)
    expect_one_value "agree: data accesses over 12 secret scalars" "$scratch/out"

    : > "$scratch/out"
    while read -r scalar; do
        printf '%s %s\n' "${scalar:0:16}" \
            "$(accesses "$harness" base "$variant" "$scalar")" >> "$scratch/out"
    done < <(scalars | head -12)
    expect_one_value "base: data accesses over 12 secret scalars" "$scratch/out"
done

printf '\n'
if [[ "$failures" -eq 0 ]]; then
    printf 'no input-dependent instruction or data-access count was observed\n'
else
    printf '%d measurement(s) varied with the input\n' "$failures" >&2
    exit 1
fi
