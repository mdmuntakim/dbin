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
make            # g++ -std=c++17 -O2 -flto -Wl,--gc-sections -s
```

Cross builds: `make CXX=aarch64-linux-gnu-g++` etc.

## Status

- x86-64 / i386 / AArch64 / ARM(Thumb) length decoders; mnemonic rendering for
  x86 and AArch64 branches; ARM/Thumb rendered as bytes (documented v1 limit).
- ELF 32/64 both endians, `.a` archives, stripped and unstripped inputs.
- Round-trip gate: `tests/roundtrip.sh` builds a corpus and compares reassembled
  section bytes with the originals.

## License

MIT
