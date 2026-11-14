// .s emission: labels, disassembled code, data bytes, relocation-aware forms.
// SPDX-License-Identifier: MIT
#include "dbin.hpp"
#include <cinttypes>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <algorithm>

namespace {

std::string hx(uint64_t v) {
    char b[32];
    snprintf(b, sizeof b, "%" PRIx64, v);
    return b;
}

std::string commentAddr(uint64_t a) { return "/* 0x" + hx(a) + " */"; }

bool nameOkChar(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '$' || c == '.';
}

std::string uniqName(std::map<std::string, int>& used, std::string n) {
    if (n.empty() || n[0] == '.' || (n[0] >= '0' && n[0] <= '9')) n = "sym_" + n;
    for (auto& ch : n) if (!nameOkChar(ch)) ch = '_';
    while (used.count(n)) n += "_x";
    used[n] = 1;
    return n;
}

std::string relocName(uint16_t machine, uint64_t t) {
    if (machine == 62) switch (t) {
        case 1: return "R_X86_64_64"; case 2: return "R_X86_64_PC32"; case 4: return "R_X86_64_PLT32";
        case 9: return "R_X86_64_32"; case 10: return "R_X86_64_32S"; case 11: return "R_X86_64_16";
        case 12: return "R_X86_64_PC16"; case 8: return "R_X86_64_PC8"; case 3: return "R_X86_64_GOTPCREL";
        case 20: return "R_X86_64_8"; case 21: return "R_X86_64_PC64";
        case 37: return "R_X86_64_PC32_BND"; case 38: return "R_X86_64_PLT32_BND";
        default: break;
    }
    if (machine == 3) switch (t) {
        case 1: return "R_386_32"; case 2: return "R_386_PC32"; case 4: return "R_386_PLT32";
        case 10: return "R_386_16"; case 11: return "R_386_PC16";
        default: break;
    }
    if (machine == 183) switch (t) {
        case 257: return "R_AARCH64_ABS64"; case 258: return "R_AARCH64_ABS32";
        case 282: return "R_AARCH64_JUMP26"; case 283: return "R_AARCH64_CALL26";
        case 275: return "R_AARCH64_ADR_PREL_PG_HI21"; case 277: return "R_AARCH64_ADD_ABS_LO12_NC";
        case 274: return "R_AARCH64_LDST64_ABS_LO12_NC"; case 281: return "R_AARCH64_LD_PREL_LO19";
        default: break;
    }
    if (machine == 40) switch (t) {
        case 2: return "R_ARM_PC24"; case 3: return "R_ARM_ABS32"; case 28: return "R_ARM_CALL";
        case 29: return "R_ARM_THM_CALL"; case 30: return "R_ARM_REL32";
        default: break;
    }
    char b[32]; snprintf(b, sizeof b, "R_%u", (unsigned)t);
    return b;
}

struct Label {
    std::string name;
    bool global = false, func = false, object = false;
};

struct Out {
    std::FILE* f = nullptr;
    explicit Out(std::FILE* f_) : f(f_) {}
    void p(const char* fmt, ...) __attribute__((format(printf, 2, 3))) {
        va_list ap; va_start(ap, fmt); std::vfprintf(f, fmt, ap); va_end(ap);
        fputc('\n', f);
    }
};

} // namespace

bool emitModuleS(const ElfImage& e, const std::string& moduleLabel, const std::string& outPath,
                 std::string& err, std::string& statsLine)
{
    if (!e.ok) { err = e.error; return false; }
    std::FILE* f = std::fopen(outPath.c_str(), "w");
    if (!f) { err = "cannot create " + outPath; return false; }
    Out out(f);

    const bool isExec = e.etype == 2 || e.etype == 3; // ET_EXEC / ET_DYN
    bool thumbMode = false;
    if (e.machine == 40) {
        for (const Symbol& s : e.symtab)
            if (s.type == 2 && s.shndx < e.sections.size() &&
                (e.sections[s.shndx].flags & 0x4) && (s.value & 1)) { thumbMode = true; break; }
        for (const Symbol& s : e.dynsym)
            if (s.type == 2 && s.shndx < e.sections.size() &&
                (e.sections[s.shndx].flags & 0x4) && (s.value & 1)) { thumbMode = true; break; }
    }

    // reloc section symtab lookup: relocs targeting section si come from a
    // SHT_REL(A) section with sh_info == si and sh_link == symtab index
    std::map<uint32_t, const std::vector<Symbol>*> relSyms;
    for (size_t i = 0; i < e.sections.size(); i++) {
        const Section& s = e.sections[i];
        if (s.type != 4 && s.type != 9) continue;
        if (s.link < e.sections.size() && e.sections[s.link].type == 2) relSyms[s.info] = &e.symtab;
        else relSyms[s.info] = &e.dynsym;
    }

    // label key: for ET_REL, per section ((si<<48)|off); for exec, absolute addr
    auto keyOf = [&](uint32_t si, uint64_t off) -> uint64_t {
        return isExec ? e.sections[si].addr + off : (((uint64_t)si << 48) | off);
    };

    // ---- pass 1: sweep executable sections ----
    struct Sweep {
        std::vector<Insn> insns;
        std::set<uint64_t> targets, callTargets;
        uint64_t decodedBytes = 0, renderedBytes = 0, totalBytes = 0;
    };
    std::map<uint32_t, Sweep> sweeps;

    auto decodeOne = [&](const uint8_t* p, uint64_t avail, uint64_t off, Insn& in) -> bool {
        if (e.machine == 62 || e.machine == 3) return decodeX86(p, avail, off, e.bits, in);
        if (e.machine == 183) return decodeA64(p, avail, off, in);
        if (e.machine == 40) return decodeArm(p, avail, off, thumbMode, in);
        return false;
    };

    for (uint32_t si = 0; si < e.sections.size(); si++) {
        const Section& s = e.sections[si];
        if (!(s.flags & 0x4) || s.type != 1 || s.size == 0) continue;
        uint64_t n = 0;
        const uint8_t* d = e.secBytes(si, n);
        if (!d) { err = "cannot read exec section " + s.name; std::fclose(f); return false; }
        Sweep sw; sw.totalBytes = n;
        uint64_t pos = 0;
        while (pos < n) {
            Insn in;
            if (decodeOne(d + pos, n - pos, pos, in) && in.len > 0 && pos + in.len <= n) {
                in.off = pos;
                if (in.hasTarget && in.target < n) {
                    sw.targets.insert(in.target);
                    if (in.isCall) sw.callTargets.insert(in.target);
                }
                sw.insns.push_back(in);
                sw.decodedBytes += in.len;
                if (!in.text.empty()) sw.renderedBytes += in.len;
                pos += in.len;
            } else {
                pos += 1;
            }
        }
        sweeps[si] = std::move(sw);
    }

    // ---- labels ----
    std::map<uint64_t, std::vector<Label>> labels;
    std::map<std::string, int> usedNames;
    std::set<std::string> printedNames;
    auto addLabel = [&](uint64_t key, const std::string& raw, bool glob, bool func, bool object) {
        std::string nm = uniqName(usedNames, raw);
        labels[key].push_back({nm, glob, func, object});
    };
    for (const std::vector<Symbol>* table : {&e.symtab, &e.dynsym}) {
        for (const Symbol& s : *table) {
            if (s.shndx >= e.sections.size() || s.name.empty()) continue;
            if (s.type != 2 && s.type != 1 && s.bind == 0) continue;
            const Section& sec = e.sections[s.shndx];
            if (!(sec.flags & 0x2)) continue;
            // In ET_EXEC/ET_DYN st_value is the virtual address; in ET_REL it
            // is an offset inside the section.
            if (isExec) {
                if (s.value < sec.addr || s.value > sec.addr + sec.size) continue;
            } else if (s.value > sec.size) continue;
            addLabel(keyOf(s.shndx, isExec ? s.value - sec.addr : s.value), s.name,
                     s.bind != 0, s.type == 2, s.type == 1);
        }
    }
    for (auto& kv : sweeps) {
        const Section& sec = e.sections[kv.first];
        (void)sec;
        for (uint64_t t : kv.second.targets) {
            uint64_t key = keyOf(kv.first, t);
            // Prefer a local alias for branch targets: a call to a .globl
            // symbol makes as emit a PLT32 relocation instead of resolving the
            // displacement, which would not round-trip byte for byte.
            bool haveLocal = false;
            auto lit = labels.find(key);
            if (lit != labels.end())
                for (auto& l : lit->second) if (!l.global) haveLocal = true;
            if (haveLocal) continue;
            bool isCall = kv.second.callTargets.count(t) != 0;
            uint64_t shown = isExec ? e.sections[kv.first].addr + t : t;
            addLabel(key, (isCall ? "sub_" : "loc_") + hx(shown), false, true, false);
        }
    }

    auto labelAt = [&](uint64_t key) -> std::string {
        auto it = labels.find(key);
        if (it == labels.end() || it->second.empty()) return "";
        for (auto& l : it->second) if (!l.global) return l.name;
        return it->second[0].name;
    };

    // ---- pass 2: write file ----
    out.p("/* Generated by dbin - reassemblable disassembly of module: %s */", moduleLabel.c_str());
    out.p("/* architecture: %s, %d-bit, %s endian */", archName(e.machine).c_str(), e.bits, e.be ? "big" : "little");
    if (e.machine == 3 && e.bits == 32) out.p(".code32");
    out.p("");

    for (uint32_t si = 0; si < e.sections.size(); si++) {
        const Section& s = e.sections[si];
        bool alloc = (s.flags & 0x2) != 0;
        bool exec = (s.flags & 0x4) != 0;
        if (!alloc) continue;
        if (s.type != 1 && s.type != 8) continue;
        bool nobits = s.type == 8;

        std::string flags;
        if (alloc) flags += 'a';
        if (s.flags & 0x1) flags += 'w';
        if (exec) flags += 'x';
        // binutils spells the section type with @ on x86 and % on ARM/AArch64
        bool armStyle = e.machine == 40 || e.machine == 183;
        out.p("\t.section\t%s,\"%s\",%s", s.name.c_str(), flags.c_str(),
              nobits ? (armStyle ? "%nobits" : "@nobits") : (armStyle ? "%progbits" : "@progbits"));
        if (s.addralign > 1) out.p("\t.balign\t%llu", (unsigned long long)s.addralign);

        auto emitLabelGroup = [&](uint64_t key) {
            auto it = labels.find(key);
            if (it == labels.end()) return;
            for (auto& l : it->second) {
                if (printedNames.count(l.name)) continue; // overlapping sections (objcopy quirks): emit once
                printedNames.insert(l.name);
                if (l.global) out.p("\t.globl\t%s", l.name.c_str());
                if (l.func) out.p("\t.type\t%s, %%function", l.name.c_str());
                else if (l.object) out.p("\t.type\t%s, %%object", l.name.c_str());
                out.p("%s:", l.name.c_str());
            }
        };

        if (nobits) {
            uint64_t pos = 0;
            std::vector<uint64_t> offs;
            for (auto& kv : labels) {
                if (!isExec && (kv.first >> 48) != si) continue;
                uint64_t o = isExec ? kv.first - s.addr : (kv.first & 0xFFFFFFFFFFFF);
                if (o < s.size) offs.push_back(o);
            }
            std::sort(offs.begin(), offs.end());
            offs.erase(std::unique(offs.begin(), offs.end()), offs.end());
            for (uint64_t o : offs) {
                if (o > pos) out.p("\t.zero\t%llu", (unsigned long long)(o - pos));
                emitLabelGroup(keyOf(si, o));
                pos = o;
            }
            if (pos < s.size) out.p("\t.zero\t%llu", (unsigned long long)(s.size - pos));
            emitLabelGroup(keyOf(si, s.size));
            out.p("");
            continue;
        }

        uint64_t n = 0;
        const uint8_t* d = e.secBytes(si, n);
        if (!d) { err = "cannot read section " + s.name; std::fclose(f); return false; }

        std::map<uint64_t, const Reloc*> relocAt;
        const std::vector<Symbol>* relSymTab = nullptr;
        auto rit = relSyms.find(si);
        if (rit != relSyms.end()) {
            relSymTab = rit->second;
            auto rv = e.relocs.find(si);
            if (rv != e.relocs.end())
                for (const Reloc& r : rv->second) relocAt[r.offset] = &r;
        }
        auto symName = [&](uint32_t idx) -> std::string {
            const std::vector<Symbol>* t = relSymTab ? relSymTab : (e.symtab.size() ? &e.symtab : &e.dynsym);
            if (idx < t->size()) return (*t)[idx].name;
            return "";
        };

        if (exec) {
            std::map<uint64_t, const Insn*> insnAt;
            auto it = sweeps.find(si);
            if (it != sweeps.end())
                for (const Insn& in : it->second.insns) insnAt[in.off] = &in;
            // GNU as relaxes near jumps to the short form when they become
            // reachable, and several jumps can shrink mutually.  Count all
            // near-branch candidates between a branch and its target so the
            // worst-case relaxation can be ruled out before rendering.
            std::vector<std::pair<uint64_t, uint64_t>> nearBrs; // offset, target
            if (it != sweeps.end() && (e.machine == 62 || e.machine == 3))
                for (const Insn& in : it->second.insns)
                    if (in.len >= 5 && in.hasTarget && in.target < n &&
                        !in.text.empty() && in.text[0] == 'j')
                        nearBrs.push_back({in.off, in.target});
            uint64_t pos = 0;
            while (pos < n) {
                emitLabelGroup(keyOf(si, pos));
                auto ii = insnAt.find(pos);
                if (ii == insnAt.end()) {
                    uint64_t end = pos + 1;
                    while (end < n && (end - pos) < 8 && !insnAt.count(end) && !labels.count(keyOf(si, end))) end++;
                    std::string b;
                    for (uint64_t k = pos; k < end; k++) { if (k > pos) b += ","; b += "0x" + hx(d[k]); }
                    out.p("%s\t.byte\t%s", commentAddr(isExec ? e.sections[si].addr + pos : pos).c_str(), b.c_str());
                    pos = end;
                    continue;
                }
                const Insn& in = *ii->second;
                // A branch (or a symbol) can point at an offset that our
                // decoder considers the middle of an instruction, typically
                // after a desync.  Split the bytes there so the label is
                // defined at the exact offset instead of dangling.
                bool split = false;
                for (uint64_t k = pos + 1; k < pos + in.len; k++)
                    if (labels.count(keyOf(si, k))) { split = true; break; }
                if (split) {
                    uint64_t end = pos + in.len;
                    while (pos < end) {
                        emitLabelGroup(keyOf(si, pos));
                        uint64_t seg = std::min(pos + 8, end);
                        for (uint64_t k = pos + 1; k < seg; k++)
                            if (labels.count(keyOf(si, k))) { seg = k; break; }
                        std::string b;
                        for (uint64_t k = pos; k < seg; k++) { if (k > pos) b += ","; b += "0x" + hx(d[k]); }
                        out.p("%s\t.byte\t%s", commentAddr(isExec ? e.sections[si].addr + pos : pos).c_str(), b.c_str());
                        pos = seg;
                    }
                    continue;
                }
                std::string text = in.text;
                std::string extra;
                int64_t covRelAddend = 0;
                // find a reloc covering this instruction (insn start or its immediate slot)
                const Reloc* covRel = nullptr;
                {
                    auto r0 = relocAt.find(pos);
                    if (r0 != relocAt.end()) covRel = r0->second;
                    else for (uint64_t o = pos + 1; o < pos + in.len && !covRel; o++) {
                        auto r1 = relocAt.find(o);
                        if (r1 != relocAt.end()) covRel = r1->second;
                    }
                }
                // SHT_REL (i386 etc): addend is implicit in the slot bytes
                if (covRel && e.sections.size() > si) {
                    // find the REL(A) section kind for si
                    for (size_t k = 0; k < e.sections.size(); k++) {
                        const Section& rs = e.sections[k];
                        if ((rs.type == 4 || rs.type == 9) && rs.info == si) {
                            if (rs.type == 9) { // REL: slot bytes hold the addend
                                if (covRel->offset + 4 <= n) {
                                    int32_t a; memcpy(&a, d + covRel->offset, 4);
                                    covRelAddend = a;
                                }
                            } else covRelAddend = covRel->addend;
                            break;
                        }
                    }
                }
                if (!in.text.empty()) {
                    size_t sp = in.text.find(" TGT");
                    std::string tgt; // replacement
                    if (sp != std::string::npos && covRel) {
                        const Reloc& rr = *covRel;
                        int64_t addend = covRelAddend;
                        std::string nm = symName(rr.sym);
                        if (!nm.empty()) {
                            if ((e.machine == 62 || e.machine == 3) && (rr.type == 2 || rr.type == 4 || rr.type == 37 || rr.type == 38)) {
                                int64_t off_ = addend + 4;
                                if (off_ == 0) tgt = nm;
                                else tgt = nm + (off_ > 0 ? "+" : "-") + "0x" + hx((uint64_t)std::abs((long long)off_));
                            } else if (e.machine == 183 && (rr.type == 282 || rr.type == 283) && addend == 0) {
                                tgt = nm;
                            }
                        }
                        if (tgt.empty()) text.clear(); // reloc we can't express -> bytes
                        else text = in.text.substr(0, sp) + " " + tgt;
                    } else if (sp != std::string::npos) {
                        std::string nm = (in.target < n) ? labelAt(keyOf(si, in.target)) : "";
                        if (!nm.empty()) {
                            bool safe = true;
                            if (e.machine == 62 || e.machine == 3) {
                                uint64_t lo = std::min(pos, in.target);
                                uint64_t hi = std::max(pos, in.target);
                                uint64_t k = 0;
                                for (auto& nb : nearBrs)
                                    if (nb.first > lo && nb.first < hi) k++;
                                int64_t d = (int64_t)in.target - (int64_t)(pos + in.len);
                                // forward: shrinks between end and target pull the
                                // target closer (self-shrink cancels); backward:
                                // shrinks between target and start pull the branch
                                // closer, and self-shrink adds 4.
                                if (d > 0) safe = (d - 4 * (int64_t)k) > 127;
                                else safe = (d + 4 + 4 * (int64_t)k) < -128;
                            }
                            if (safe) text = in.text.substr(0, sp) + " " + nm;
                            else text.clear();
                        }
                        else text.clear();
                    }
                }
                if (covRel) {
                    const Reloc& rr = *covRel;
                    extra = " /* " + relocName(e.machine, rr.type) + " " + symName(rr.sym);
                    if (covRelAddend) {
                        extra += (covRelAddend < 0 ? "-0x" : "+0x");
                        extra += hx((uint64_t)std::abs((long long)covRelAddend));
                    }
                    extra += " */";
                }
                if (!text.empty()) {
                    out.p("%s\t%s%s", commentAddr(isExec ? e.sections[si].addr + pos : pos).c_str(), text.c_str(), extra.c_str());
                } else {
                    std::string b;
                    for (uint32_t k = 0; k < in.len; k++) { if (k) b += ","; b += "0x" + hx(d[pos + k]); }
                    out.p("%s\t.byte\t%s%s", commentAddr(isExec ? e.sections[si].addr + pos : pos).c_str(), b.c_str(), extra.c_str());
                }
                pos += in.len;
            }
            emitLabelGroup(keyOf(si, n));
        } else {
            uint64_t pos = 0;
            while (pos < n) {
                emitLabelGroup(keyOf(si, pos));
                std::string extra;
                auto r = relocAt.find(pos);
                if (r != relocAt.end()) {
                    const Reloc& rr = *r->second;
                    std::string nm = symName(rr.sym);
                    int bw = (e.machine == 183 && rr.type == 257) ? 8 : 4;
                    bool zero = pos + (uint64_t)bw <= n;
                    for (int k = 0; k < bw && zero; k++) zero = d[pos + k] == 0;
                    std::string dn;
                    if (!nm.empty() && zero) {
                        if (e.machine == 62 && rr.type == 1) dn = ".quad\t" + nm;
                        else if (e.machine == 62 && (rr.type == 9 || rr.type == 10)) dn = ".long\t" + nm;
                        else if (e.machine == 3 && rr.type == 1) dn = ".long\t" + nm;
                        else if (e.machine == 183 && rr.type == 257) dn = ".quad\t" + nm;
                        else if (e.machine == 183 && rr.type == 258) dn = ".long\t" + nm;
                        if (!dn.empty()) {
                            if (rr.addend) dn += (rr.addend < 0 ? "-0x" : "+0x") + std::string("0x") + hx((uint64_t)std::abs((long long)rr.addend));
                            out.p("%s\t%s", commentAddr(isExec ? e.sections[si].addr + pos : pos).c_str(), dn.c_str());
                            pos += (uint64_t)bw;
                            continue;
                        }
                    }
                    extra = " /* " + relocName(e.machine, rr.type) + " " + nm + " */";
                }
                uint64_t end = std::min(pos + 16, n);
                // never run a byte block across a label or a relocation slot,
                // otherwise the label would be defined nowhere and references
                // to it would assemble as undefined symbols.
                for (uint64_t k = pos + 1; k < end; k++) {
                    if (labels.count(keyOf(si, k)) || relocAt.count(k)) { end = k; break; }
                }
                std::string b;
                for (uint64_t k = pos; k < end; k++) { if (k > pos) b += ","; b += "0x" + hx(d[k]); }
                out.p("%s\t.byte\t%s%s", commentAddr(isExec ? e.sections[si].addr + pos : pos).c_str(), b.c_str(), extra.c_str());
                pos = end;
            }
            emitLabelGroup(keyOf(si, n));
        }
        out.p("");
    }

    uint64_t decoded = 0, rendered = 0, total = 0;
    for (auto& kv : sweeps) { decoded += kv.second.decodedBytes; rendered += kv.second.renderedBytes; total += kv.second.totalBytes; }
    char buf[256];
    snprintf(buf, sizeof buf, "code: %llu/%llu bytes decoded, %llu bytes rendered as mnemonics",
             (unsigned long long)decoded, (unsigned long long)total, (unsigned long long)rendered);
    statsLine = buf;
    std::fclose(f);
    return true;
}
