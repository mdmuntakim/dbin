// dbin - static binary inventory and reassemblable assembly dumper.
// SPDX-License-Identifier: MIT
#pragma once
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <optional>

struct Section {
    std::string name;
    uint32_t type = 0;
    uint32_t link = 0, info = 0;
    uint64_t flags = 0, addr = 0, offset = 0, size = 0, entsize = 0, addralign = 1;
};

struct Symbol {
    std::string name;
    uint64_t value = 0, size = 0;
    uint8_t type = 0, bind = 0, shndx = 0, vis = 0;
};

struct Reloc {
    uint64_t offset = 0;
    uint64_t type = 0;
    int64_t addend = 0;
    uint32_t sym = 0;
};

struct ElfImage {
    bool ok = false;
    std::string error;
    int bits = 0;            // 32 or 64
    bool be = false;         // big endian
    uint16_t machine = 0, etype = 0;
    std::vector<Section> sections;
    std::vector<Symbol> symtab, dynsym;
    std::map<uint32_t, std::vector<Reloc>> relocs; // keyed by target section index
    const uint8_t* base = nullptr;
    uint64_t fileSize = 0;

    const uint8_t* secBytes(uint32_t idx, uint64_t& outSize) const {
        outSize = 0;
        if (idx >= sections.size()) return nullptr;
        const Section& s = sections[idx];
        if (s.type == 8 /*NOBITS*/ || s.offset + s.size > fileSize) return nullptr;
        outSize = s.size;
        return base + s.offset;
    }
};

bool parseElfInto(ElfImage& e, const uint8_t* base, uint64_t size);

// Archive (.a) parsing
struct ArchiveMember {
    std::string name;
    uint64_t offset = 0, size = 0;
};
bool parseArchive(const uint8_t* base, uint64_t size, std::vector<ArchiveMember>& out, std::string& err);

// One decoded instruction. text empty => emit raw bytes; otherwise text is the
// GNU-syntax instruction (labels already substituted by the emitter).
struct Insn {
    uint64_t off = 0;       // offset within section
    uint32_t len = 0;
    uint64_t target = 0;    // section offset of branch/call target
    bool hasTarget = false; // target is valid
    bool isCall = false;    // call-style target (function label)
    bool isFlowEnd = false; // no fallthrough (jmp/ret)
    std::string text;       // rendered instruction or "" for .byte
    std::string comment;
};

// Architecture decoders. All return false (len==0) on undecodable bytes.
bool decodeX86(const uint8_t* p, uint64_t avail, uint64_t off, int bits, Insn& out);
bool decodeA64(const uint8_t* p, uint64_t avail, uint64_t off, Insn& out);
bool decodeArm(const uint8_t* p, uint64_t avail, uint64_t off, bool thumb, Insn& out);

bool emitModuleS(const ElfImage& e, const std::string& moduleLabel, const std::string& outPath,
                 std::string& err, std::string& statsLine);
std::string sanitizeSymbol(const std::string& n);
std::string archName(uint16_t machine);
std::string elfTypeName(uint16_t t);
