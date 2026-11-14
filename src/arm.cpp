// ARM A32 (fixed 4 bytes) and Thumb-2 (2/4 bytes). v1: bytes-only output,
// branch targets recovered for B/BL/Bcc (A32) and B/Bcc/BL/CB(N)Z (Thumb).
// Labels come from the targets; instructions themselves are .byte so the
// round-trip is byte-identical by construction.
// SPDX-License-Identifier: MIT
#include "dbin.hpp"
#include <cstring>

static int64_t sextN(int64_t v, int bits) {
    if ((v >> (bits - 1)) & 1) v -= (int64_t)1 << bits;
    return v;
}

bool decodeArm(const uint8_t* p, uint64_t avail, uint64_t off, bool thumb, Insn& out)
{
    if (thumb) {
        if (avail < 2) return false;
        uint16_t hw1; memcpy(&hw1, p, 2);
        bool wide = (hw1 >= 0xE800); // 1110 1xxx / 1111 xxxx prefixes => 32-bit
        uint32_t len = wide ? 4 : 2;
        if (len > avail) return false;
        out.len = len;
        out.hasTarget = false; out.isCall = false; out.isFlowEnd = false;
        out.text.clear();
        if (!wide) {
            // B<cond> T1: 1101 cond imm8 (cond != 111x)
            if ((hw1 & 0xF000) == 0xD000 && (hw1 & 0x0F00) <= 0x0D00) {
                int64_t imm = sextN(hw1 & 0xFF, 8) * 2;
                out.target = off + 4 + (uint64_t)imm;
                out.hasTarget = true; out.isFlowEnd = true;
            }
            // B T2: 11100 imm11
            else if ((hw1 & 0xF800) == 0xE000) {
                int64_t imm = sextN(hw1 & 0x7FF, 11) * 2;
                out.target = off + 4 + (uint64_t)imm;
                out.hasTarget = true; out.isFlowEnd = true;
            }
            // CBZ/CBNZ: 1011 0 0/1 1 i imm5 rn   (0xB1/0xB3 cbz, 0xB9/0xBB cbnz)
            else if ((hw1 & 0xF500) == 0xB100 || (hw1 & 0xF500) == 0xB900) {
                int i5 = (((hw1 >> 9) & 1) << 5) | ((hw1 >> 3) & 0x1F);
                int64_t imm = sextN(i5, 6) * 2;
                out.target = off + 4 + (uint64_t)imm;
                out.hasTarget = true;
            }
        }
        return true;
    }

    // ARM A32: fixed 4 bytes
    if (avail < 4) return false;
    uint32_t w; memcpy(&w, p, 4);
    out.len = 4;
    out.hasTarget = false; out.isCall = false; out.isFlowEnd = false;
    out.text.clear();
    uint32_t cond = w >> 28;
    // B/BL: cond 101 L imm24
    if ((w & 0x0E000000) == 0x0A000000 && cond != 0xF) {
        int64_t imm = sextN(w & 0x00FFFFFF, 24) * 4;
        out.target = off + 8 + (uint64_t)imm;
        out.hasTarget = true;
        bool l = (w & 0x01000000) != 0;
        out.isCall = l;
        out.isFlowEnd = !l;
    }
    return true;
}
