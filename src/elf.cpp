// ELF (32/64, both endians) + archive parsing for dbin.
// SPDX-License-Identifier: MIT
#include "dbin.hpp"
#include <cstring>
#include <cstdio>

namespace {

inline uint16_t rd16(const uint8_t* p, bool be) {
    uint16_t v; memcpy(&v, p, 2);
    if (be) v = __builtin_bswap16(v);
    return v;
}
inline uint32_t rd32(const uint8_t* p, bool be) {
    uint32_t v; memcpy(&v, p, 4);
    if (be) v = __builtin_bswap32(v);
    return v;
}
inline uint64_t rd64(const uint8_t* p, bool be) {
    uint64_t v; memcpy(&v, p, 8);
    if (be) v = __builtin_bswap64(v);
    return v;
}

std::string cstr(const uint8_t* p, uint64_t maxlen) {
    std::string s;
    for (uint64_t i = 0; i < maxlen && p[i]; i++) s.push_back((char)p[i]);
    return s;
}

} // namespace

bool parseArchive(const uint8_t* base, uint64_t size, std::vector<ArchiveMember>& out, std::string& err) {
    if (size < 8 || memcmp(base, "!<arch>\n", 8) != 0) { err = "not an ar archive"; return false; }
    uint64_t off = 8;
    std::string longNames; // "//" member
    while (off + 60 <= size) {
        const uint8_t* h = base + off;
        if (memcmp(h + 58, "`\n", 2) != 0) { err = "corrupt ar header"; return false; }
        uint64_t msize = 0;
        for (int i = 0; i < 10; i++) {
            char c = (char)h[48 + i];
            if (c == ' ') break;
            if (c < '0' || c > '9') { err = "corrupt ar size"; return false; }
            msize = msize * 10 + (c - '0');
        }
        if (off + 60 + msize > size) { err = "truncated ar member"; return false; }
        std::string name = cstr(h, 16);
        uint64_t dataOff = off + 60, dataEnd = dataOff + msize;
        if (name.rfind("/", 0) == 0 && (name == "/" || name == "/ ")) {
            // GNU symbol index, skip
        } else if (name.rfind("//", 0) == 0) {
            longNames = cstr(base + dataOff, msize);
        } else {
            if (name.rfind('/', 0) == 0) {
                // BSD style #1: name stored in data
                uint32_t nlen = 0;
                memcpy(&nlen, base + dataOff, 4);
                if (dataOff + 4 + nlen <= dataEnd) {
                    name = cstr(base + dataOff + 4, nlen);
                    dataOff += 4 + nlen;
                }
            } else if (!name.empty() && name.back() == '/') {
                name.pop_back();
                if (name.size() && name.back() == '/') { // long name reference
                    long int idx = strtol(name.c_str(), nullptr, 10);
                    uint64_t p = (uint64_t)(idx < 0 ? 0 : idx);
                    std::string ln;
                    while (p < longNames.size() && longNames[p] != '\n' && longNames[p] != '/') ln.push_back(longNames[p++]);
                    name = ln;
                }
            }
            if (dataOff < dataEnd) out.push_back({name, dataOff, dataEnd - dataOff});
        }
        off = dataEnd;
        if (msize & 1) off++; // ar pads members to even offsets
    }
    return true;
}

namespace {

struct Reader {
    const uint8_t* b; uint64_t n; bool be; int bits;
    uint16_t u16(const uint8_t* p) const { return rd16(p, be); }
    uint32_t u32(const uint8_t* p) const { return rd32(p, be); }
    uint64_t u64(const uint8_t* p) const { return bits == 64 ? rd64(p, be) : rd32(p, be); }
    uint64_t addr(const uint8_t* p) const { return u64(p); }
    uint64_t off(const uint8_t* p) const { return u64(p); }
    uint64_t xword(const uint8_t* p) const { return u64(p); }
};

} // namespace

// Parse an ELF image from [base, base+size).
bool parseElfInto(ElfImage& e, const uint8_t* base, uint64_t size)
{
    e = ElfImage{};
    e.base = base; e.fileSize = size;
    if (size < 52) { e.error = "file too small for ELF header"; return false; }
    if (memcmp(base, "\x7f" "ELF", 4) != 0) { e.error = "missing ELF magic"; return false; }
    uint8_t cls = base[4], dat = base[5];
    if (cls != 1 && cls != 2) { e.error = "invalid EI_CLASS"; return false; }
    if (dat != 1 && dat != 2) { e.error = "invalid EI_DATA"; return false; }
    e.bits = cls == 2 ? 64 : 32;
    e.be = dat == 2;
    Reader r{base, size, e.be, e.bits};

    uint16_t ver = r.u16(base + 16);
    if (ver != 1) { e.error = "unsupported ELF version"; return false; }
    e.etype = r.u16(base + 16);
    e.machine = r.u16(base + 18);

    const size_t e32h = 52, e64h = 64;
    if ((e.bits == 64 && size < e64h) || (e.bits == 32 && size < e32h)) { e.error = "truncated ELF header"; return false; }

    uint64_t shoff, shsize, shnum, shstrndx, shentsize;
    if (e.bits == 64) {
        shoff = r.u64(base + 40);
        shentsize = r.u16(base + 58);
        shnum = r.u16(base + 60);
        shstrndx = r.u16(base + 62);
    } else {
        shoff = r.u32(base + 32);
        shentsize = r.u16(base + 46);
        shnum = r.u16(base + 48);
        shstrndx = r.u16(base + 50);
    }

    // handle extended numbering (shnum == 0, real value in section[0].sh_size)
    auto readShdr = [&](uint64_t idx, uint64_t& nameOff, uint64_t& type, uint64_t& flags,
                        uint64_t& addr, uint64_t& offset, uint64_t& sizeOut, uint64_t& link,
                        uint64_t& info, uint64_t& addralign, uint64_t& entsize) -> bool {
        if (shoff + (idx + 1) * shentsize > size) return false;
        const uint8_t* p = base + shoff + idx * shentsize;
        if (e.bits == 64) {
            nameOff = r.u32(p); type = r.u32(p + 4); flags = r.u64(p + 8); addr = r.u64(p + 16);
            offset = r.u64(p + 24); sizeOut = r.u64(p + 32); link = r.u32(p + 40);
            info = r.u32(p + 44); addralign = r.u64(p + 48); entsize = r.u64(p + 56);
        } else {
            nameOff = r.u32(p); type = r.u32(p + 4); flags = r.u32(p + 8); addr = r.u32(p + 12);
            offset = r.u32(p + 16); sizeOut = r.u32(p + 20); link = r.u32(p + 24);
            info = r.u32(p + 28); addralign = r.u32(p + 32); entsize = r.u32(p + 36);
        }
        return true;
    };

    uint64_t n0name, n0type, n0flags, n0addr, n0off, n0size, n0link, n0info, n0align, n0entsize;
    if (shoff == 0) { shnum = 0; }
    else if (!readShdr(0, n0name, n0type, n0flags, n0addr, n0off, n0size, n0link, n0info, n0align, n0entsize)) {
        e.error = "section header table out of range"; return false;
    } else if (shnum == 0 || shstrndx == 0xffff /*SHN_XINDEX*/) {
        if (shnum == 0) shnum = n0size;
        if (shstrndx == 0xffff) shstrndx = n0link;
    }

    if (shnum == 0) { e.error = "ELF image has no sections"; return false; }
    if (shnum > 100000) { e.error = "implausible section count"; return false; }

    e.sections.resize(shnum);
    for (uint64_t i = 0; i < shnum; i++) {
        uint64_t nameOff, type, flags, addr, offset, sz, link, info, addralign, entsize;
        if (!readShdr(i, nameOff, type, flags, addr, offset, sz, link, info, addralign, entsize)) {
            e.error = "section header out of range"; return false;
        }
        Section& s = e.sections[i];
        s.type = (uint32_t)type; s.flags = flags; s.addr = addr; s.offset = offset;
        s.size = sz; s.link = (uint32_t)link; s.info = (uint32_t)info;
        s.addralign = addralign ? addralign : 1; s.entsize = entsize;
    }

    // section name string table
    if (shstrndx < shnum) {
        const Section& st = e.sections[shstrndx];
        if (st.type == 3 && st.offset + st.size <= size) {
            for (size_t i = 0; i < e.sections.size(); i++) {
                uint64_t no = 0;
                if (e.bits == 64) readShdr(i, no, n0type, n0flags, n0addr, n0off, n0size, n0link, n0info, n0align, n0entsize);
                else readShdr(i, no, n0type, n0flags, n0addr, n0off, n0size, n0link, n0info, n0align, n0entsize);
                if (no < st.size) {
                    Section& s = e.sections[i];
                    s.name = cstr(base + st.offset + no, st.size - no);
                }
            }
        }
    }

    // symbol tables
    auto readSyms = [&](uint32_t idx, std::vector<Symbol>& out) {
        if (idx >= e.sections.size()) return;
        const Section& s = e.sections[idx];
        if (s.type != 2 && s.type != 11) return;
        uint64_t strn = 0; const uint8_t* strb = nullptr; uint64_t strsize = 0;
        if (s.link < e.sections.size()) {
            const Section& st = e.sections[s.link];
            strb = base + st.offset; strsize = st.size;
            if (st.offset + st.size > size) { strb = nullptr; }
        }
        const uint8_t* p = base + s.offset;
        if (s.offset + s.size > size) return;
        size_t esz = e.bits == 64 ? 24 : 16;
        size_t count = s.size / esz;
        for (size_t i = 0; i < count; i++) {
            const uint8_t* q = p + i * esz;
            Symbol y;
            uint32_t nameOff; uint64_t val, sz2; uint8_t info, other; uint16_t shn;
            if (e.bits == 64) {
                nameOff = r.u32(q); info = q[4]; other = q[5]; shn = r.u16(q + 6);
                val = r.u64(q + 8); sz2 = r.u64(q + 16);
            } else {
                nameOff = r.u32(q); val = r.u32(q + 4); sz2 = r.u32(q + 8);
                info = q[12]; other = q[13]; shn = r.u16(q + 14);
            }
            y.name = (strb && nameOff < strsize) ? cstr(strb + nameOff, strsize - nameOff) : std::string();
            y.value = val; y.size = sz2; y.type = info & 0xf; y.bind = info >> 4; y.shndx = (uint8_t)shn;
            y.vis = other & 3;
            out.push_back(std::move(y));
        }
    };
    for (size_t i = 0; i < e.sections.size(); i++) {
        if (e.sections[i].type == 2) readSyms((uint32_t)i, e.symtab);
        else if (e.sections[i].type == 11) readSyms((uint32_t)i, e.dynsym);
    }

    // relocations
    for (size_t i = 0; i < e.sections.size(); i++) {
        const Section& s = e.sections[i];
        if (s.type != 4 && s.type != 9) continue; // SHT_REL / SHT_RELA
        if (s.offset + s.size > size) continue;
        bool rela = s.type == 9;
        size_t esz = e.bits == 64 ? (rela ? 24 : 16) : (rela ? 12 : 8);
        size_t count = s.size / esz;
        const uint8_t* p = base + s.offset;
        std::vector<Reloc>& v = e.relocs[s.info];
        for (size_t j = 0; j < count; j++) {
            const uint8_t* q = p + j * esz;
            Reloc rr;
            if (e.bits == 64) {
                rr.offset = r.u64(q); rr.type = r.u32(q + 8);
                rr.sym = r.u32(q + 12); rr.addend = rela ? (int64_t)r.u64(q + 16) : 0;
            } else {
                rr.offset = r.u32(q);
                uint32_t info = r.u32(q + 4);
                rr.type = info >> 8; rr.sym = info & 0xff;
                rr.addend = rela ? (int64_t)(int32_t)r.u32(q + 8) : 0;
            }
            v.push_back(rr);
        }
    }

    e.ok = true;
    return true;
}

