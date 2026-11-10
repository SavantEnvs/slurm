#!/usr/bin/env bash
#
# mayhem/test.sh — RUN slurm's own `check`-based unit tests (built by mayhem/build.sh with normal
# flags). Counts come from each binary's own "Checks: N, Failures: F, Errors: E" summary, so a binary
# that exits early without running its checks counts as a failure.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

UT="$SRC/mayhem/build-test/testsuite/slurm_unit/common"
TESTS="
hostlist/hostlist_create-test
hostlist/hostlist_nth-test
hostlist/hostlist_iterator-test
bitstring/bitstring-test
bitstring/bit_unfmt_hexmask-test
xstring-test
parse_time-test
data-test
pack-test
buf-test
xbase64-test
xhash-test
reverse_tree-test
"

passed=0
failed=0
for t in $TESTS; do
  bin="$UT/$t"
  if [ ! -x "$bin" ]; then
    echo "missing test binary $bin (mayhem/build.sh should have built it)" >&2
    failed=$((failed + 1))
    continue
  fi
  out="$(cd "$(dirname "$bin")" && timeout 600 "./$(basename "$bin")" 2>&1)"
  rc=$?
  echo "$out" | tail -n 3
  line="$(echo "$out" | grep -E '^[0-9]+%: Checks: [0-9]+, Failures: [0-9]+, Errors: [0-9]+' | tail -n 1)"
  if [ -z "$line" ]; then
    echo "$t: no check summary (rc=$rc)" >&2
    failed=$((failed + 1))
    continue
  fi
  n="$(echo "$line" | sed -E 's/.*Checks: ([0-9]+),.*/\1/')"
  f="$(echo "$line" | sed -E 's/.*Failures: ([0-9]+),.*/\1/')"
  e="$(echo "$line" | sed -E 's/.*Errors: ([0-9]+).*/\1/')"
  bad=$((f + e))
  passed=$((passed + n - bad))
  failed=$((failed + bad))
  [ "$rc" -eq 0 ] || [ "$bad" -gt 0 ] || failed=$((failed + 1))
done

emit_ctrf "slurm-check" "$passed" "$failed" 0
