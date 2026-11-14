#!/usr/bin/env bash
# Android ABI gate: build every NDK ABI, execute each of them under qemu-user,
# check that they are fully static and seccomp-safe, then run the full
# byte-faithful round-trip gate through the arm64 binary.
#
# Termux/Android background: a glibc static binary dies at startup with
# SIGSYS (signal 31) because glibc calls rseq(2) and the Android app seccomp
# allowlist does not contain it.  This gate fails if the NDK builds pick that
# syscall up again.
#
# SPDX-License-Identifier: MIT
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=${WORK:-/tmp/dbin_android_abi}
rm -rf "$WORK"; mkdir -p "$WORK"

PASS=0; FAIL=0; SKIP=0
note() { printf '%-28s %-6s %s\n' "$1" "$2" "$3"; }
ok()   { PASS=$((PASS+1)); note "$1" PASS "$2"; }
bad()  { FAIL=$((FAIL+1)); note "$1" FAIL "$2"; }
skip() { SKIP=$((SKIP+1)); note "$1" SKIP "$2"; }

echo "building the Android ABIs"
if ! make -C "$ROOT" android >"$WORK/build.log" 2>&1; then
  bad build "make android failed, see $WORK/build.log"
  tail -20 "$WORK/build.log"
  echo; echo "PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
  exit 1
fi
ok build "arm64-v8a, armeabi-v7a, x86_64"

check_abi() {
  local name=$1 bin=$2 emu=$3
  local path="$ROOT/$bin"
  if [ ! -f "$path" ]; then bad "$name" "missing $bin"; return; fi
  if command -v readelf >/dev/null 2>&1; then
    if readelf -d "$path" 2>/dev/null | grep -q '(NEEDED)'; then
      bad "$name" "not static: $bin has NEEDED entries"; return
    fi
  fi
  if ! command -v "$emu" >/dev/null 2>&1; then
    skip "$name" "$emu not installed, cannot execute"
    return
  fi
  local out="$WORK/$name.json"
  if ! "$emu" "$path" --json --outdir "$WORK/$name" "$path" >"$out" 2>"$WORK/$name.err"; then
    bad "$name" "execution failed: $(head -c 120 "$WORK/$name.err" | tr '\n' ' ')"
    return
  fi
  if ! grep -q '"ok": true' "$out"; then
    bad "$name" "unexpected output: $(head -c 120 "$out" | tr '\n' ' ')"
    return
  fi
  # The startup syscall trace must not contain a syscall Android's app seccomp
  # policy traps (rseq and clone3 are the two glibc uses).
  if ! "$emu" -strace "$path" --json --outdir "$WORK/$name-trace" "$path" \
        >/dev/null 2>"$WORK/$name.trace"; then
    bad "$name" "strace run failed"
    return
  fi
  if grep -Eq '(^|[^a-z_])rseq\(|clone3\(' "$WORK/$name.trace"; then
    bad "$name" "uses a seccomp-trapped syscall: $(grep -Eo 'rseq\(|clone3\(' "$WORK/$name.trace" | sort -u | tr '\n' ' ')"
    return
  fi
  ok "$name" "$emu: runs, static, no rseq/clone3"
}

check_abi arm64-v8a   dbin-android-aarch64  qemu-aarch64
check_abi armeabi-v7a dbin-android-armv7a  qemu-arm
check_abi x86_64      dbin-android-x86_64  qemu-x86_64

# Full round-trip gate through the arm64 build, emulated on this host.
if command -v qemu-aarch64 >/dev/null 2>&1; then
  wrap="$WORK/qemu-dbin"
  printf '#!/bin/sh\nexec qemu-aarch64 "%s" "$@"\n' "$ROOT/dbin-android-aarch64" > "$wrap"
  chmod +x "$wrap"
  if WORK="$WORK/gate" DBIN="$wrap" bash "$ROOT/tests/roundtrip.sh" >"$WORK/gate.log" 2>&1; then
    ok roundtrip-aarch64 "$(grep -E '^PASS=' "$WORK/gate.log" | tail -1)"
  else
    bad roundtrip-aarch64 "see $WORK/gate.log"
    tail -20 "$WORK/gate.log"
  fi
else
  skip roundtrip-aarch64 "qemu-aarch64 not installed"
fi

echo
echo "PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
[ "$FAIL" = 0 ]
