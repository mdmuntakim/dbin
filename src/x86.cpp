// x86 / x86-64 instruction length decoder + conservative GNU-AT&T renderer.
// Anything not provably reassembled to identical bytes is emitted as .byte.
// SPDX-License-Identifier: MIT
#include "dbin.hpp"
#include <cstring>

namespace {

bool g_init = false;
struct OpInfo { bool modrm; uint8_t imm; };
OpInfo op1[256], op2[256];

void initTables() {
    if (g_init) return;
    g_init = true;
    auto set = [](OpInfo* t, int lo, int hi, bool modrm, uint8_t imm = 0) {
        for (int i = lo; i <= hi; i++) t[i] = {modrm, imm};
    };
    for (int i = 0; i < 256; i++) { op1[i] = {false, 0}; op2[i] = {false, 0}; }
    // 1-byte map: ALU r/m,r and r,r/m forms (xx0,xx1,xx2,xx3)
    for (int b = 0; b < 8; b++) for (int r = 0; r < 4; r++) op1[b * 8 + r] = {true, 0};
    op1[0x62] = {true, 0}; op1[0x63] = {true, 0};
    op1[0x69] = {true, 2}; op1[0x6B] = {true, 1};
    set(op1, 0x70, 0x7F, false, 1);
    op1[0x80] = {true, 1}; op1[0x81] = {true, 2}; op1[0x82] = {true, 1}; op1[0x83] = {true, 1};
    op1[0x84] = {true, 0}; op1[0x85] = {true, 0};
    op1[0x86] = {true, 0}; op1[0x87] = {true, 0};
    set(op1, 0x88, 0x8F, true);
    op1[0xC0] = {true, 1}; op1[0xC1] = {true, 1};
    op1[0xC6] = {true, 1}; op1[0xC7] = {true, 2};
    op1[0xC8] = {false, 4}; // enter iw,ib (special)
    set(op1, 0xD0, 0xD3, true);
    op1[0xD4] = {false, 1}; op1[0xD5] = {false, 1};
    set(op1, 0xD8, 0xDF, true);
    set(op1, 0xE0, 0xE3, false, 1);
    op1[0xE8] = {false, 3}; op1[0xE9] = {false, 3}; // rel32 (special)
    op1[0xEB] = {false, 1};
    op1[0xF6] = {true, 4}; op1[0xF7] = {true, 4}; // imm only for reg<2
    op1[0xFE] = {true, 0}; op1[0xFF] = {true, 0};
    // imm forms (byte / wide) handled inline: 04,0C,...,3D, A8, A9, B0-BF, 68, 6A

    // 2-byte map
    set(op2, 0x00, 0x0D, true);
    op2[0x0F] = {true, 1}; // 3dnow
    set(op2, 0x10, 0x1F, true);
    set(op2, 0x20, 0x25, true);
    set(op2, 0x28, 0x2F, true);
    set(op2, 0x40, 0x7F, true);
    op2[0xA3] = {true, 0}; op2[0xA4] = {true, 1}; op2[0xA5] = {true, 0};
    op2[0xAB] = {true, 0}; op2[0xAC] = {true, 1}; op2[0xAD] = {true, 0};
    op2[0xAF] = {true, 0};
    op2[0xB0] = {true, 0}; op2[0xB1] = {true, 0};
    set(op2, 0xB2, 0xB9, true);
    op2[0xBA] = {true, 4}; // imm8 only when reg>=4
    set(op2, 0xBB, 0xBF, true);
    op2[0xC0] = {true, 0}; op2[0xC1] = {true, 0};
    op2[0xC2] = {true, 1}; op2[0xC3] = {true, 0};
    op2[0xC4] = {true, 1}; op2[0xC5] = {true, 1}; op2[0xC6] = {true, 1}; op2[0xC7] = {true, 0};
    set(op2, 0xD0, 0xFF, true);
    // 0F80-0F8F jcc rel32 (special), 0FA0-0FA2, 0FA8-0FAA, 0FC8-0FCF no modrm (defaults above are false? 0FA0..0FA2 and 0FA8..0FAA lie inside no set range: correct, they default {false,0}; but 0F A8? we set nothing -> false. 0FC8-0FCF inside 0xD0-0xFF set - fix:
    for (int i = 0xC8; i <= 0xCF; i++) op2[i] = {false, 0};
    op2[0x77] = {false, 0}; // emms
    op2[0x30] = {false, 0}; op2[0x31] = {false, 0}; op2[0x32] = {false, 0};
    op2[0x33] = {false, 0}; op2[0x34] = {false, 0}; op2[0x35] = {false, 0};
    op2[0x37] = {false, 0};
}

const char* reg8[16]  = {"al","cl","dl","bl","spl","bpl","sil","dil","r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b"};
const char* reg16[16] = {"ax","cx","dx","bx","sp","bp","si","di","r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w"};
const char* reg32[16] = {"eax","ecx","edx","ebx","esp","ebp","esi","edi","r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d"};
const char* reg64[16] = {"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15"};
const char* ccName[16] = {"o","no","b","ae","e","ne","be","a","s","ns","p","np","l","ge","le","g"};

inline int extB(uint8_t rex, int v) { return v + ((rex & 1) ? 8 : 0); }
inline int extX(uint8_t rex, int v) { return v + ((rex & 2) ? 8 : 0); }

std::string regName(int size, uint8_t rex, int v) {
    int r = rex ? extB(rex, v) : v;
    if (size == 8) return std::string(reg8[rex ? r : v]);
    if (size == 16) return std::string(reg16[r]);
    if (size == 32) return std::string(reg32[r]);
    return std::string(reg64[r]);
}

// read modrm + possible sib/displacement; returns bytes consumed, -1 on truncation
int readModrm(const uint8_t* p, uint64_t avail, uint64_t startI, uint8_t& mod, uint8_t& reg, uint8_t& rm) {
    if (startI >= avail) return -1;
    uint8_t m = p[startI];
    mod = m >> 6; reg = (m >> 3) & 7; rm = m & 7;
    uint64_t i = startI + 1;
    if (mod != 3 && rm == 4) {
        if (i >= avail) return -1;
        uint8_t sib = p[i++];
        uint8_t base = sib & 7;
        if (mod == 0 && base == 5) i += 4;
        else if (mod == 1) i += 1;
        else if (mod == 2) i += 4;
    } else if (mod == 0 && rm == 5) i += 4;
    else if (mod == 1) i += 1;
    else if (mod == 2) i += 4;
    return (int)(i - startI);
}

} // namespace

bool decodeX86(const uint8_t* p, uint64_t avail, uint64_t off, int bits, Insn& out)
{
    initTables();
    uint64_t i = 0;
    uint8_t rex = 0; bool hasRex = false;
    bool opsize16 = false, rep = false, repnz = false, lock = false, seg = false;
    while (i < avail) {
        uint8_t b = p[i];
        if (b == 0x66) { opsize16 = true; i++; if (hasRex) { rex = 0; hasRex = false; } }
        else if (b == 0x67 || b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 || b == 0x64 || b == 0x65) { seg = true; i++; if (hasRex) { rex = 0; hasRex = false; } }
        else if (b == 0xF0) { lock = true; i++; if (hasRex) { rex = 0; hasRex = false; } }
        else if (b == 0xF2) { repnz = true; i++; if (hasRex) { rex = 0; hasRex = false; } }
        else if (b == 0xF3) { rep = true; i++; if (hasRex) { rex = 0; hasRex = false; } }
        else if (bits == 64 && b >= 0x40 && b <= 0x4F) { rex = b; hasRex = true; i++; }
        else break;
        if (i > 15) return false;
    }
    if (i >= avail) return false;
    uint8_t op = p[i++];

    int osize = 32;
    if (opsize16) osize = 16;
    else if (bits == 64 && (rex & 8)) osize = 64;

    std::string text;
    bool hasTarget = false, isCall = false, isFlowEnd = false;
    uint64_t target = 0;

    // helper: ALU/mov reg-reg canonical check
    auto readImm = [&](int n, bool signedImm) -> bool {
        if (i + (uint64_t)n > avail) return false;
        if (signedImm) {
            int64_t v = 0;
            if (n == 1) v = (int8_t)p[i];
            else if (n == 2) { int16_t t; memcpy(&t, p + i, 2); v = t; }
            else if (n == 4) { int32_t t; memcpy(&t, p + i, 4); v = t; }
            (void)v;
        }
        i += (uint64_t)n;
        return true;
    };

    if (op == 0x0F) {
        if (i >= avail) return false;
        uint8_t op2v = p[i++];
        int map = 1;
        uint8_t opcode = op2v;
        if (op2v == 0x38 || op2v == 0x3A) {
            map = op2v == 0x38 ? 2 : 3;
            if (i >= avail) return false;
            opcode = p[i++];
        }
        uint8_t immKind = 0;
        bool needModrm;
        if (map == 1) { needModrm = op2[op2v].modrm; immKind = op2[op2v].imm; }
        else if (map == 2) { needModrm = true; }
        else { needModrm = true; immKind = 1; }
        uint8_t mod = 0, reg = 0, rm = 0;
        if (needModrm) {
            int c = readModrm(p, avail, i, mod, reg, rm);
            if (c < 0) return false;
            i += (uint64_t)c;
            if (op2v == 0xBA && reg >= 4) immKind = 1;
        }
        if (immKind == 1) { if (!readImm(1, false)) return false; }
        else if (immKind == 2) { if (!readImm(osize / 8, false)) return false; }
        else if (immKind == 3) { if (!readImm(2, false)) return false; }
        else if (immKind == 4 && reg < 2) { if (!readImm(op == 0xF6 ? 1 : osize / 8, false)) return false; }
        if (i > avail) return false;

        // rendered 2-byte forms (no prefixes except none)
        if (!lock && !rep && !repnz && !seg && !opsize16 && !hasRex && map == 1) {
            if (op2v == 0x05) text = "syscall";
            else if (op2v == 0x0B) text = "ud2";
            else if (op2v == 0xA2) text = "cpuid";
            else if (op2v == 0x1E && rep && mod == 3 && rm == 7) text = "endbr64";
            else if (op2v == 0x1E && rep && mod == 3 && rm == 6) text = "endbr32";
        }
        if (map == 1 && op2v >= 0x80 && op2v <= 0x8F) {
            if (i + 4 > avail) return false;
            int32_t rel; memcpy(&rel, p + i, 4);
            i += 4;
            target = off + i + (uint64_t)(int64_t)rel;
            hasTarget = true;
            if (!lock && !rep && !repnz && !seg && !opsize16 && !hasRex)
                text = std::string("j") + ccName[op2v - 0x80] + " TGT";
        }
        out.len = (uint32_t)i;
        out.text = text; out.hasTarget = hasTarget; out.target = target;
        out.isCall = isCall; out.isFlowEnd = isFlowEnd;
        return true;
    }

    // VEX (C4/C5) / EVEX (62): length decode only
    if (op == 0xC4 || op == 0xC5 || op == 0x62) {
        int plen = op == 0xC5 ? 1 : (op == 0xC4 ? 2 : 3);
        if ((uint64_t)i + (uint64_t)plen + 1 > avail) return false;
        uint8_t mapByte;
        if (op == 0xC5) mapByte = 1;
        else if (op == 0xC4) mapByte = (uint8_t)(p[i + 1] & 0x1F);
        else mapByte = (uint8_t)(p[i] & 0x7);
        i += (uint64_t)plen;
        if (i >= avail) return false;
        uint8_t vop = p[i++];
        int map = mapByte == 1 ? 1 : (mapByte == 2 ? 2 : (mapByte == 3 ? 3 : 0));
        if (map == 0) return false;
        uint8_t immKind = 0;
        bool needModrm;
        if (map == 1) { needModrm = op2[vop].modrm; immKind = op2[vop].imm; }
        else if (map == 2) { needModrm = true; }
        else { needModrm = true; immKind = 1; }
        uint8_t mod, reg, rm;
        if (needModrm) {
            int c = readModrm(p, avail, i, mod, reg, rm);
            if (c < 0) return false;
            i += (uint64_t)c;
            if (vop == 0xBA && reg >= 4) immKind = 1;
        }
        if (immKind == 1 && !readImm(1, false)) return false;
        else if (immKind == 2 && !readImm(osize / 8, false)) return false;
        if (i > avail) return false;
        out.len = (uint32_t)i;
        return true;
    }

    // FPU D8-DF: modrm only
    if (op >= 0xD8 && op <= 0xDF) {
        uint8_t mod, reg, rm;
        int c = readModrm(p, avail, i, mod, reg, rm);
        if (c < 0) return false;
        i += (uint64_t)c;
        if (i > avail) return false;
        out.len = (uint32_t)i;
        return true;
    }

    OpInfo inf = op1[op];
    uint8_t mod = 0, reg = 0, rm = 0;
    bool haveModrmBytes = false;
    if (inf.modrm) {
        int c = readModrm(p, avail, i, mod, reg, rm);
        if (c < 0) return false;
        i += (uint64_t)c;
        haveModrmBytes = true;
        (void)haveModrmBytes;
    }

    // immediates per-opcode
    if (op == 0x04 || op == 0x0C || op == 0x14 || op == 0x1C || op == 0x24 || op == 0x2C || op == 0x34 || op == 0x3C || op == 0xA8) {
        if (!readImm(1, true)) return false;
    } else if (op == 0x05 || op == 0x0D || op == 0x15 || op == 0x1D || op == 0x25 || op == 0x2D || op == 0x35 || op == 0x3D || op == 0xA9) {
        if (!readImm(osize / 8, true)) return false;
    } else if (op >= 0xB0 && op <= 0xB7) {
        if (!readImm(1, true)) return false;
    } else if (op >= 0xB8 && op <= 0xBF) {
        if (bits == 64 && (rex & 8)) { if (!readImm(8, false)) return false; }
        else if (!readImm(osize / 8, false)) return false;
    } else if (op == 0x68) {
        if (!readImm(osize / 8, true)) return false;
    } else if (op == 0x6A) {
        if (!readImm(1, true)) return false;
    } else if (op == 0xE8 || op == 0xE9) {
        if (i + 4 > avail) return false;
        int32_t rel; memcpy(&rel, p + i, 4);
        i += 4;
        target = off + i + (uint64_t)(int64_t)rel;
        hasTarget = true; isCall = (op == 0xE8);
        if (!lock && !seg && !rep && !repnz && !opsize16)
            text = std::string(op == 0xE8 ? "call" : "jmp") + " TGT";
    } else if (op == 0xEB) {
        if (!readImm(1, true)) return false;
        // imm is last byte: rel = imm
        int64_t rel = (int8_t)p[i - 1];
        target = off + i + (uint64_t)rel;
        hasTarget = true;
        if (!lock && !seg && !rep && !repnz && !opsize16 && !hasRex) text = "jmp TGT";
    } else if (op >= 0x70 && op <= 0x7F) {
        if (!readImm(1, true)) return false;
        int64_t rel = (int8_t)p[i - 1];
        target = off + i + (uint64_t)rel;
        hasTarget = true;
        if (!lock && !seg && !rep && !repnz && !opsize16 && !hasRex)
            text = std::string("j") + ccName[op - 0x70] + " TGT";
    } else if (op == 0xC8) { // enter
        if (!readImm(2, false)) return false;
        if (i >= avail) return false;
        i += 1;
    } else if (inf.imm == 1) {
        if (!readImm(1, true)) return false;
    } else if (inf.imm == 2) {
        if (!readImm(osize / 8, true)) return false;
    } else if (inf.imm == 3) {
        if (!readImm(2, true)) return false;
    } else if (inf.imm == 4 && reg < 2) {
        if (!readImm(op == 0xF6 ? 1 : osize / 8, true)) return false;
    }
    if (i > avail) return false;

    // ---- rendering (conservative, byte-faithful) ----
    if (!lock && !rep && !repnz && !seg && text.empty()) {
        bool memop = inf.modrm && mod != 3;
        auto sfx = [&](int sz) -> const char* { return sz == 8 ? "b" : sz == 16 ? "w" : sz == 32 ? "l" : "q"; };
        if (op >= 0x50 && op <= 0x5F && osize != 16) {
            const char* r = bits == 64 ? reg64[rex ? extB(rex, op - 0x50) : op - 0x50]
                                       : reg32[op - 0x50];
            text = std::string(op < 0x58 ? "push %" : "pop %") + r;
        } else if (op == 0xC3 && !opsize16 && !hasRex) { text = "ret"; isFlowEnd = true; }
        else if (op == 0xC9 && !opsize16 && !hasRex) { text = "leave"; }
        else if (op == 0xCC) { text = "int3"; isFlowEnd = true; }
        else if (op == 0x90 && !hasRex && !opsize16) { text = "nop"; }
        else if (op == 0x98 && !opsize16 && !hasRex) { text = bits == 64 ? "cltq" : "cwde"; }
        else if (op == 0x99 && !opsize16 && !hasRex) { text = bits == 64 ? "cltd" : "cdq"; }
        else if (!memop && inf.modrm && mod == 3) {
            int sz = osize;
            if ((op < 0x40) && (op & 7) <= 3) {
                static const char* alu[8] = {"add","or","adc","sbb","and","sub","xor","cmp"};
                const char* mn = alu[(op >> 3) & 7];
                int dir = op & 3; // 0: r/m8,r8  1: r/m,r  2: r8,r/m8  3: r,r/m
                int canonicalDir = sz == 8 ? 0 : 1;
                if (dir == canonicalDir) {
                    int dst = dir <= 1 ? (rex ? extB(rex, rm) : rm) : (rex ? extX(rex, reg) : reg);
                    int src = dir <= 1 ? (rex ? extX(rex, reg) : reg) : (rex ? extB(rex, rm) : rm);
                    text = std::string(mn) + sfx(sz) + " %" + regName(sz, rex, src) + ", %" + regName(sz, rex, dst);
                }
            } else if (op == 0x84 || op == 0x85) {
                int r1 = rex ? extX(rex, reg) : reg;
                int r2 = rex ? extB(rex, rm) : rm;
                text = std::string("test") + sfx(sz) + " %" + regName(sz, rex, r2) + ", %" + regName(sz, rex, r1);
            } else if (op == 0x88) {
                text = std::string("movb %" ) + regName(8, rex, rex ? extX(rex, reg) : reg) + ", %" + regName(8, rex, rex ? extB(rex, rm) : rm);
            } else if (op == 0x89) {
                text = std::string("mov") + sfx(sz) + " %" + regName(sz, rex, rex ? extX(rex, reg) : reg) + ", %" + regName(sz, rex, rex ? extB(rex, rm) : rm);
            }
        }
        else if (op >= 0xB0 && op <= 0xB7) {
            text = std::string("movb $") + std::to_string((int8_t)p[i - 1]) + ", %" + regName(8, rex, op - 0xB0);
        }
        else if (op >= 0xB8 && op <= 0xBF && osize == 32 && !hasRex) {
            int32_t v; memcpy(&v, p + i - 4, 4);
            text = std::string("movl $") + std::to_string(v) + ", %" + reg32[op - 0xB8];
        }
        else if (op >= 0xB8 && op <= 0xBF && osize == 16 && !hasRex) {
            int16_t v; memcpy(&v, p + i - 2, 2);
            text = std::string("movw $") + std::to_string(v) + ", %" + reg16[op - 0xB8];
        }
        else if (op >= 0x80 && op <= 0x83 && mod == 3) {
            static const char* alu[8] = {"add","or","adc","sbb","and","sub","xor","cmp"};
            const char* mn = alu[reg];
            if (op == 0x80) {
                text = std::string(mn) + "b $" + std::to_string((int8_t)p[i - 1]) + ", %" + regName(8, rex, rex ? extB(rex, rm) : rm);
            } else if (op == 0x83 && osize != 16) {
                text = std::string(mn) + sfx(osize) + " $" + std::to_string((int8_t)p[i - 1]) + ", %" + regName(osize, rex, rex ? extB(rex, rm) : rm);
            } else if (op == 0x83) {
                text = std::string(mn) + "w $" + std::to_string((int8_t)p[i - 1]) + ", %" + regName(16, rex, rex ? extB(rex, rm) : rm);
            } else { // 0x81 with wide imm: as keeps 81 when imm not imm8-fittable
                int64_t v = 0;
                int n = opsize16 ? 2 : osize / 8;
                if (n == 2) { int16_t t; memcpy(&t, p + i - 2, 2); v = t; }
                else { int32_t t; memcpy(&t, p + i - 4, 4); v = t; }
                if (v < -128 || v > 127)
                    text = std::string(mn) + sfx(opsize16 ? 16 : osize) + " $" + std::to_string(v) + ", %" + regName(opsize16 ? 16 : osize, rex, rex ? extB(rex, rm) : rm);
            }
        }
        else if (op == 0x8D && mod != 3 && rm != 4 && rm != 5 && mod == 1 && !opsize16 && !seg) {
            // lea disp8(base), %reg — no SIB involved, as reassembles identically
            static const char* b32[8] = {"eax","ecx","edx","ebx","esp","ebp","esi","edi"};
            std::string bn = bits == 64 ? std::string("%") + reg64[rex ? extB(rex, rm) : rm]
                                        : std::string("%") + b32[rm];
            int8_t d = (int8_t)p[i - 1];
            int dsz = osize == 16 ? 16 : (bits == 64 && (rex & 8)) ? 64 : 32;
            text = std::string("lea") + sfx(dsz) + " " + std::to_string(d) + "(" + bn + "), %" + regName(dsz, rex, rex ? extX(rex, reg) : reg);
        }
    }

    out.len = (uint32_t)i;
    out.text = text;
    out.hasTarget = hasTarget; out.target = target;
    out.isCall = isCall; out.isFlowEnd = isFlowEnd;
    return true;
}
