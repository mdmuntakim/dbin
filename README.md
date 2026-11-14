# dbin

`dbin` is a single static C++17 binary that takes any compiled binary, inventories
everything inside it — including all object modules — and disassembles each module
into reassemblable GNU-syntax `.s` files named after the input.

## What it does

1. **Inventory** — format, architecture, endianness, bitness, section count, and the
   object modules it contains (names + sizes). `--json` for CI.
2. **Module discovery** — standalone `.o`, members of `.a` archives (non-ELF members
   are hard errors with the reason), and the relocatable/executable image itself.
3. **Disassembly** — one `.s` per module: `foo.o` → `foo.s`, archive member
   `printf.o` in `foo.a` → `foo-printf.o.s`.
4. **Output** — section directives, `.globl`, symbol labels, address comments,
   `.byte`/`.quad` data, branch/call labels. Must assemble with `as`/`clang`.

## Byte-faithful round-trip contract

The emitter only renders an instruction as a mnemonic when `as` provably
re-encodes it to the same bytes; everything else is emitted as `.byte` at exact
instruction boundaries with the address comment. That is what makes the output
round-trip byte-identical. Decoders exist for x86/x86-64 (full length decoding,
mnemonic rendering for the common reg-reg/imm/branch subset), AArch64 (B/BL/CBZ/
CBNZ/TBZ/TBNZ/B.cond rendered, rest at 4-byte granularity), ARM/Thumb (length
decoding + branch targets, bytes-only rendering in v1).

Relocations: for `ET_REL` objects, PC-relative call/jump relocations
(`R_X86_64_PC32/PLT32`, `R_AARCH64_CALL26/JUMP26`) are emitted as assembler
directives (`call foo`), which the assembler turns back into the same hole bytes;
other relocations are emitted as comments so the section bytes stay identical.

## Usage

```
dbin [--json] [--outdir DIR] [--no-disasm] <file>
```

## Build

```
make            # host build, g++ -std=c++17 -O2 -flto -Wl,--gc-sections -s
make static     # the release binary for this host (fully static)
make android    # Termux/Android: arm64-v8a, armeabi-v7a and x86_64, bionic
make linux-aarch64   # generic Linux aarch64, needs aarch64-linux-gnu-g++
```

The Android targets need the NDK (`ANDROID_NDK_HOME`, or an NDK under
`/usr/local/lib/android/sdk/ndk/`). Every target compiles into its own object
directory (`build/<target>`), so a cross build never links a host object.

## Android / Termux

**On Termux use `dbin-android-aarch64`** (or `dbin-android-armv7a` on a 32-bit
device). The `dbin` and `dbin-linux-aarch64` assets are glibc builds for
ordinary Linux and do not run under Termux.

The 0.1.0 asset `dbin-aarch64` was a generic `aarch64-linux-gnu` static binary
and died on Android with `unknown signal 31` before printing anything. On arm64
Linux signal 31 is `SIGSYS`. During startup glibc registers restartable
sequences with `rseq(2)`; Android's app seccomp allowlist
(`SECCOMP_ALLOWLIST_APP.TXT` / `SECCOMP_ALLOWLIST_COMMON.TXT` in bionic) does
not contain `rseq`, so the kernel traps the syscall and kills the process with
`SIGSYS`. It is not a dbin bug and not something an emulator can mask: with a
one-line seccomp filter that traps only `rseq`, the glibc build dies with
`Bad system call (core dumped)` (exit 159 = 128 + 31) and no output, while the
NDK build runs normally and its syscall trace contains no `rseq`/`clone3`.

Rebuilding against bionic fixes it: bionic never calls `rseq`, so the binary
stays inside the Android seccomp allowlist. `tests/android-abi.sh` checks this
on every build — it executes each ABI under qemu-user and fails if `rseq`
appears in the trace.

## Status

- x86-64 / i386 / AArch64 / ARM(Thumb) length decoders; mnemonic rendering for
  x86 and AArch64 branches; ARM/Thumb rendered as bytes (documented v1 limit).
- ELF 32/64 both endians, `.a` archives, stripped and unstripped inputs.
- Round-trip gate: `tests/roundtrip.sh` builds a corpus and compares reassembled
  section bytes with the originals.
- Android ABI gate: `tests/android-abi.sh` builds and executes arm64-v8a,
  armeabi-v7a and x86_64, and runs the full round-trip gate through
  `qemu-aarch64`.

## License

MIT
