#!/usr/bin/env bash
# dbin round-trip gate: disassemble corpus inputs, reassemble, compare bytes.
# A row only "passes" when the byte comparison actually ran and matched.
# SPDX-License-Identifier: MIT
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
# DBIN may point at a wrapper (qemu-aarch64 ./dbin-android-aarch64) so the
# Android ABI builds can run through the same gate as the host build.
DBIN="${DBIN:-$ROOT/dbin}"
WORK=${WORK:-/tmp/dbin_gate}
rm -rf "$WORK"; mkdir -p "$WORK"
CORPUS="$WORK/corpus"; mkdir -p "$CORPUS"
OUT="$WORK/out"; mkdir -p "$OUT"
PASS=0; FAIL=0
declare -a ROWS

add_row() {
  ROWS+=("$1|status=$2|detail=$3|time=$4")
  if [ "$2" = PASS ]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); fi
}

# corpus ------------------------------------------------------------------
cat > "$CORPUS/t.c" <<'EOF'
int add(int a, int b) { return a + b; }
int mul_add(int a, int b, int c) { return a * b + c; }
static int g = 42;
int getg(void) { return g; }
int branchy(int x) {
    switch (x & 7) {
    case 0: return 1; case 1: return 22; case 2: return 333;
    case 3: return 4444; case 4: return 55555; default: return -1;
    }
}
extern int printf(const char*, ...);
int hello(void) { printf("hi %d\n", g); return 0; }
EOF
cat > "$CORPUS/empty.s" <<'EOF'
.section .empty_sec,"a"
.text
.globl nul_fn
.type nul_fn,%function
nul_fn:
ret
EOF
gcc -O2 -c "$CORPUS/t.c" -o "$CORPUS/x86_64.o" || { echo "corpus build failed"; exit 1; }
gcc -c "$CORPUS/empty.s" -o "$CORPUS/empty.o"
clang -m32 -O2 -c "$CORPUS/t.c" -o "$CORPUS/i386.o"
clang --target=aarch64-linux-gnu -O2 -c "$CORPUS/t.c" -o "$CORPUS/aarch64.o"
clang --target=armv7a-linux-gnueabihf -mthumb -O2 -c "$CORPUS/t.c" -o "$CORPUS/armv7.o"
ar rcs "$CORPUS/libtest.a" "$CORPUS/x86_64.o" "$CORPUS/aarch64.o" "$CORPUS/armv7.o" "$CORPUS/i386.o"
gcc -O2 -o "$CORPUS/dyn_hello" -x c - <<'EOF'
#include <stdio.h>
int main(void){ printf("x\n"); return 0; }
EOF
gcc -O2 -static -o "$CORPUS/static_hello" -x c - <<'EOF'
#include <stdio.h>
int main(void){ printf("x\n"); return 0; }
EOF
cp "$CORPUS/static_hello" "$CORPUS/stripped_nosym"
strip --strip-all "$CORPUS/stripped_nosym"
dd if=/dev/zero of="$CORPUS/bigblob.bin" bs=1M count=110 status=none
objcopy --add-section .bigblob="$CORPUS/bigblob.bin" --set-section-flags .bigblob=alloc,contents "$CORPUS/static_hello" "$CORPUS/huge_100mb" 2>/dev/null
LIBC=/lib/x86_64-linux-gnu/libc.so.6
[ -f "$LIBC" ] || LIBC=$(ls /usr/lib/*/libc.so.6 2>/dev/null | head -1)

# verify one object (elf) against its emitted .s ----------------------------
# assembler chosen from the "architecture:" comment dbin writes into each .s
asm_for() { # .s file -> command array prefix
  local arch
  arch=$(grep -m1 'architecture:' "$1" | sed 's/.*architecture: //; s/,.*//')
  case "$arch" in
    x86-64) echo "HOSTAS" ;;
    i386) echo "AS32" ;;
    aarch64) echo "CLANG64" ;;
    arm) echo "CLANGARM" ;;
    *) echo "UNKNOWN" ;;
  esac
}

compare_object() { # objfile rtobjfile -> sets G_OK/G_DETAIL
  local obj="$1" rt="$2" sname stype sflags sbase osz rsz
  G_OK=1; G_DETAIL=""; G_NSEC=0
  while IFS= read -r sline; do
    sname=$(echo "$sline" | awk '{print $1}')
    stype=$(echo "$sline" | awk '{print $2}' | tr 'a-z' 'A-Z')
    sflags=$(echo "$sline" | awk '{print $7}')
    case "$sname" in ''|NULL) continue;; esac
    case "$stype" in PROGBITS|NOBITS) ;; *) continue;; esac
    case "$sflags" in *A*) ;; *) continue;; esac
    G_NSEC=$((G_NSEC+1))
    sbase="$WORK/sec"
    "$DBIN" --dump "$obj" "$sname" "$sbase.orig" 2>/dev/null
    "$DBIN" --dump "$rt" "$sname" "$sbase.rt" 2>/dev/null
    osz=$(stat -c %s "$sbase.orig" 2>/dev/null || echo -1)
    rsz=$(stat -c %s "$sbase.rt" 2>/dev/null || echo -1)
    if [ "$osz" != "$rsz" ] || ! cmp -s "$sbase.orig" "$sbase.rt"; then
      G_OK=0
      G_DETAIL="$G_DETAIL [$sname orig=$osz rt=$rsz]"
    fi
  done < <(readelf -SW "$obj" 2>/dev/null | grep '^  \[' | grep -vE 'NULL|\.symtab|\.strtab|\.shstrtab|\.comment' | sed -E 's/^[[:space:]]*\[[ 0-9]+\][[:space:]]+//')
}

run_case() {
  local label="$1" input="$2"
  local t0 t1 secs
  t0=$(date +%s.%N)
  rm -rf "$OUT/$label"; mkdir -p "$OUT/$label"
  if ! "$DBIN" --json --outdir "$OUT/$label" "$input" > "$OUT/$label.json" 2>"$OUT/$label.err"; then
    t1=$(date +%s.%N); secs=$(echo "$t1 - $t0" | bc)
    local jerr
    jerr=$(python3 -c "import json;print(json.load(open('$OUT/$label.json'))['errors'])" 2>/dev/null || head -c 100 "$OUT/$label.json")
    add_row "$label" "FAIL" "dbin error: $jerr" "$secs"
    return
  fi
  # for archives, work per member: extract and pair with <stem>-<member>.s
  local is_a=0
  case "$input" in *.a) is_a=1;; esac
  local ok=1 detail="" npairs=0
  if [ "$is_a" = 1 ]; then
    mkdir -p "$OUT/$label/extract"
    ( cd "$OUT/$label/extract" && ar x "$input" ) || { add_row "$label" FAIL "ar extract failed" "0"; return; }
    local stem; stem=$(basename "$input" .a)
    local m mf
    for mf in "$OUT/$label/extract"/*; do
      [ -f "$mf" ] || continue
      local mname; mname=$(basename "$mf")
      local mstem; mstem=$(basename "$mname"); mstem=${mstem%.*}
      local sf="$OUT/$label/$stem-$mstem.s"
      if [ ! -f "$sf" ]; then ok=0; detail="$detail [no .s for $mname]"; continue; fi
      local ascmd; ascmd=$(asm_for "$sf")
      case "$ascmd" in
        HOSTAS)   as -o "$sf.o" "$sf" 2>"$sf.aserr" ;;
        AS32)     as --32 -o "$sf.o" "$sf" 2>"$sf.aserr" ;;
        CLANG64)  clang --target=aarch64-linux-gnu -c -o "$sf.o" "$sf" 2>"$sf.aserr" ;;
        CLANGARM) clang --target=armv7a-linux-gnueabihf -c -o "$sf.o" "$sf" 2>"$sf.aserr" ;;
        *) ok=0; detail="$detail [unknown arch in $sf]"; continue ;;
      esac
      if [ $? != 0 ]; then
        ok=0
        detail="$detail [$mname reassemble failed: $(head -c 90 "$sf.aserr" | tr '\n' ' ')]"
        continue
      fi
      npairs=$((npairs+1))
      compare_object "$mf" "$sf.o"
      if [ "$G_OK" != 1 ]; then ok=0; detail="$detail [$mname:$G_DETAIL]"; fi
    done
  else
    local sf
    for sf in "$OUT/$label"/*.s; do
      [ -e "$sf" ] || continue
      local ascmd; ascmd=$(asm_for "$sf")
      case "$ascmd" in
        HOSTAS)   as -o "$sf.o" "$sf" 2>"$sf.aserr" ;;
        AS32)     as --32 -o "$sf.o" "$sf" 2>"$sf.aserr" ;;
        CLANG64)  clang --target=aarch64-linux-gnu -c -o "$sf.o" "$sf" 2>"$sf.aserr" ;;
        CLANGARM) clang --target=armv7a-linux-gnueabihf -c -o "$sf.o" "$sf" 2>"$sf.aserr" ;;
        *) ok=0; detail="$detail [unknown arch in $sf]"; continue ;;
      esac
      if [ $? != 0 ]; then
        ok=0
        detail="$detail [reassemble failed: $(head -c 90 "$sf.aserr" | tr '\n' ' ')]"
        continue
      fi
      npairs=$((npairs+1))
      compare_object "$input" "$sf.o"
      if [ "$G_OK" != 1 ]; then ok=0; detail="$detail $G_DETAIL"; fi
    done
    [ -e "$OUT/$label"/*.s ] || { ok=0; detail=" [dbin produced no .s files]"; }
  fi
  t1=$(date +%s.%N); secs=$(echo "$t1 - $t0" | bc)
  if [ "$ok" = 1 ]; then
    add_row "$label" "PASS" "byte-identical across $npairs object(s)" "$secs"
  else
    add_row "$label" "FAIL" "$detail" "$secs"
  fi
}

cp "$CORPUS/x86_64.o" "$CORPUS/x86_64_stripped.o"; strip --strip-all "$CORPUS/x86_64_stripped.o"
run_case "x86_64.o"        "$CORPUS/x86_64.o"
run_case "x86_64.stripped" "$CORPUS/x86_64_stripped.o"
run_case "i386.o"          "$CORPUS/i386.o"
run_case "aarch64.o"       "$CORPUS/aarch64.o"
run_case "armv7.o"         "$CORPUS/armv7.o"
run_case "empty.o"         "$CORPUS/empty.o"
run_case "libtest.a"       "$CORPUS/libtest.a"
run_case "dyn_hello"       "$CORPUS/dyn_hello"
run_case "static_hello"    "$CORPUS/static_hello"
run_case "stripped_nosym"  "$CORPUS/stripped_nosym"
[ -n "$LIBC" ] && run_case "libc.so.6"     "$LIBC"
[ -n "$LIBC" ] || add_row "libc.so.6" "NOT TESTED" "no system libc.so.6 found" "0"
run_case "huge_100mb"      "$CORPUS/huge_100mb"

echo
echo "=== Round-trip matrix ==="
for r in "${ROWS[@]}"; do
  label=${r%%|*}
  status=$(echo "$r" | sed 's/.*status=\([^|]*\).*/\1/')
  detail=$(echo "$r" | sed 's/.*detail=//; s/|time=.*//')
  time=$(echo "$r" | sed 's/.*time=//')
  printf '%-16s %-11s %8ss  %s\n' "$label" "$status" "$time" "$detail"
done
echo
echo "PASS=$PASS FAIL=$FAIL"
