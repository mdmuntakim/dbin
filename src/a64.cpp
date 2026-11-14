// AArch64 (A64): fixed 4-byte instructions. Renders branches to labels;
// everything else emitted as .byte at instruction granularity (v1).
// SPDX-License-Identifier: MIT
#include "dbin.hpp"
#include <cstring>

bool decodeA64(const uint8_t* p, uint64_t avail, uint64_t off, Insn& out)
{
    if (avail < 4) return false;
    uint32_t w; memcpy(&w, p, 4);
    out.len = 4;
    out.hasTarget = false; out.isCall = false; out.isFlowEnd = false;
    int64_t simm26 = (int64_t)(w & 0x03FFFFFFu);
    if (simm26 > 0x1FFFFFF) simm26 -= 0x4000000;
    int64_t simm19 = (int64_t)((w >> 5) & 0x7FFFF);
    if (simm19 > 0x3FFFF) simm19 -= 0x80000;
    int64_t simm14 = (int64_t)((w >> 5) & 0x3FFF);
    if (simm14 > 0x1FFF) simm14 -= 0x4000;

    // B / BL: 00101 imm26
    if ((w & 0x7C000000) == 0x14000000) {
        out.target = off + (uint64_t)(simm26 * 4);
        out.hasTarget = true;
        out.isCall = (w & 0x80000000) != 0;
        out.isFlowEnd = !out.isCall;
        out.text = std::string(out.isCall ? "bl" : "b") + " TGT";
        return true;
    }
    // CBZ/CBNZ: sf 011010 sf? op = bit31(sf), bit24 group 0110100/1, bit? op bit24? encoding: sf 0110100 op imm19 Rt
    if ((w & 0x7E000000) == 0x34000000) {
        out.target = off + (uint64_t)(simm19 * 4);
        out.hasTarget = true;
        int rt = w & 31;
        bool sf = (w >> 31) & 1, nz = (w >> 24) & 1;
        out.text = std::string(nz ? "cbnz " : "cbz ") + (sf ? "x" : "w") + std::to_string(rt) + ", TGT";
        return true;
    }
    // TBZ/TBNZ: b5 011011 op b40 imm14 Rt
    if ((w & 0x7E000000) == 0x36000000) {
        out.target = off + (uint64_t)(simm14 * 4);
        out.hasTarget = true;
        int rt = w & 31;
        int b40 = (w >> 19) & 0x1F;
        bool sf = (w >> 31) & 1, nz = (w >> 24) & 1;
        out.text = std::string(nz ? "tbnz " : "tbz ") + (sf ? "x" : "w") + std::to_string(rt)
                 + ", #" + std::to_string((sf ? 32 : 0) + b40) + ", TGT";
        return true;
    }
    // B.cond: 0101010 0 imm19 cond
    if ((w & 0xFF000010) == 0x54000000) {
        int cond = w & 0xF;
        out.target = off + (uint64_t)(simm19 * 4);
        out.hasTarget = true;
        static const char* cc[16] = {"eq","ne","cs","cc","mi","pl","vs","vc","hi","ls","ge","lt","gt","le","al","nv"};
        out.text = std::string("b.") + cc[cond] + " TGT";
        return true;
    }
    // ADR: op0 immlo 10000 immhi Rd -> 0 immlo 10000 immhi Rd
    if ((w & 0x1F000000) == 0x10000000 && (w & 0x60000000) != 0x60000000) {
        // distinguish ADR (bit28-31 = 0 immlo... ) ADRP sets bit31
        bool adrp = (w >> 31) & 1;
        out.isFlowEnd = false;
        out.text = adrp ? "" : ""; // v1: bytes
        return true;
    }
    return true; // 4 bytes, bytes-only
}
