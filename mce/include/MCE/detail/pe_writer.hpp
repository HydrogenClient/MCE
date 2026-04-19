#pragma once
#include "types.hpp"
#include <unordered_map>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <vector>
#include <string>
#include <ctime>
#include <cassert>

/*
 * pe_writer.hpp — PE32+ (x86-64) executable writer
 *
 * Produces a valid, runnable Windows PE64 binary entirely from scratch.
 *
 * Section layout (in order):
 *   .text   – RX  – code supplied by user
 *   .rdata  – R   – optional read-only data
 *   .data   – RW  – optional read-write data
 *   .idata  – RW  – import directory (built automatically)
 *
 * Import directory layout inside .idata:
 *   [IDT]        (num_dlls+1) × IMAGE_IMPORT_DESCRIPTOR (20 bytes each)
 *   [ILT]        for each DLL: (num_funcs+1) × 8 bytes (null-terminated)
 *   [IAT]        same structure as ILT; loader fills in function VAs
 *   [HintNames]  for each function: u16 hint + name + '\0' + optional pad
 *   [DLLNames]   null-terminated DLL name strings
 *
 * All RVAs inside .idata are computed after section layout is known.
 */

namespace mce {
namespace pe {

// ─── Type aliases ─────────────────────────────────────────────────────────────
using u8  = mce::u8;
using u16 = mce::u16;
using u32 = mce::u32;
using u64 = mce::u64;
using i32 = mce::i32;
using usize = mce::usize;

// ─── PE constants ─────────────────────────────────────────────────────────────
static constexpr u32 IMAGE_NT_SIGNATURE           = 0x00004550;
static constexpr u16 IMAGE_FILE_MACHINE_AMD64     = 0x8664;
static constexpr u16 IMAGE_FILE_FLAGS             = 0x0022; // exe + large-address-aware
static constexpr u16 MAGIC_PE32PLUS               = 0x020B;
static constexpr u16 SUBSYSTEM_CONSOLE            = 0x0003;
static constexpr u16 SUBSYSTEM_WINDOWS            = 0x0002;
static constexpr u16 DLL_CHARS                    = 0x8120; // NX + no SEH + TS-aware (no ASLR)

static constexpr u32 SEC_CODE  = 0x60000020; // read | exec | contains-code
static constexpr u32 SEC_RDATA = 0x40000040; // read | initialized-data
static constexpr u32 SEC_DATA  = 0xC0000040; // read | write | initialized-data

// ─── Low-level emit helpers ───────────────────────────────────────────────────
namespace detail {
    inline void w8 (std::vector<u8>& v, u8  x) { v.push_back(x); }
    inline void w16(std::vector<u8>& v, u16 x) {
        v.push_back(u8(x));
        v.push_back(u8(x >> 8));
    }
    inline void w32(std::vector<u8>& v, u32 x) {
        v.push_back(u8(x));        v.push_back(u8(x >>  8));
        v.push_back(u8(x >> 16));  v.push_back(u8(x >> 24));
    }
    inline void w64(std::vector<u8>& v, u64 x) {
        w32(v, u32(x));
        w32(v, u32(x >> 32));
    }
    inline void wzero(std::vector<u8>& v, usize n) {
        v.insert(v.end(), n, 0u);
    }
    inline void wbytes(std::vector<u8>& v, const u8* p, usize n) {
        v.insert(v.end(), p, p + n);
    }
    inline void walign(std::vector<u8>& v, usize align) {
        usize rem = v.size() % align;
        if (rem) wzero(v, align - rem);
    }
    inline void p32(std::vector<u8>& v, usize off, u32 x) {
        v[off+0]=u8(x);       v[off+1]=u8(x>>8);
        v[off+2]=u8(x>>16);   v[off+3]=u8(x>>24);
    }
    inline u32 rdw(const std::vector<u8>& v, usize o) {
        return u32(v[o]) | u32(v[o+1])<<8 | u32(v[o+2])<<16 | u32(v[o+3])<<24;
    }
    inline u32 align_up(u32 v, u32 a) { return (v + a - 1) & ~(a - 1); }
} // namespace detail

// ─── PESection ───────────────────────────────────────────────────────────────
struct PESection {
    std::string      name;
    u32              characteristics = 0;
    std::vector<u8>  data;

    // Filled during layout:
    u32 rva        = 0;
    u32 raw_offset = 0;
    u32 raw_size   = 0;   // file-aligned size of data
    u32 virt_size  = 0;   // actual data size (= data.size() or explicit)

    PESection() = default;
    PESection(const std::string& n, u32 chars) : name(n), characteristics(chars) {}
};

// ─── PEBuilder ────────────────────────────────────────────────────────────────
class PEBuilder {
public:
    // ─── Layout constants ─────────────────────────────────────────────────
    static constexpr u32 FILE_ALIGN = 0x200;
    static constexpr u32 SEC_ALIGN  = 0x1000;
    static constexpr u64 IMAGE_BASE = 0x0000000140000000ULL;
    static constexpr u32 NUM_DATA_DIRS = 16;

    u16 subsystem  = SUBSYSTEM_CONSOLE;
    u64 image_base = IMAGE_BASE;

    // ─── Public API ───────────────────────────────────────────────────────

    // Add a user section (returns reference to data buffer)
    std::vector<u8>& add_section(const std::string& name, u32 chars) {
        user_sections_.emplace_back(name, chars);
        return user_sections_.back().data;
    }

    // Record an import. Each (dll, func) pair is imported by name.
    void add_import(const std::string& dll, const std::string& func, u16 hint = 0) {
        // Find existing DLL group or create one
        for (auto& g : import_groups_) {
            if (g.dll == dll) { g.funcs.push_back({func, hint}); return; }
        }
        import_groups_.push_back({ dll, {{ func, hint }} });
    }

    PEBuilder& import(const std::string& dll, const std::string& func, u16 hint = 0) {
        add_import(dll, func, hint);
        return *this;
    }

    // Build the PE image. entry_rva_in_text is the entry-point byte offset
    // within the first .text section added.
    // Returns the assembled image. Also fills iat_rvas_ map.
    std::vector<u8> build(u32 entry_rva_in_text = 0) {
        using namespace detail;

        iat_rvas_.clear();

        // ── 1. Build .idata section ──────────────────────────────────────
        PESection idata_sec;
        idata_sec.name            = ".idata";
        idata_sec.characteristics = SEC_DATA;
        build_idata(idata_sec); // data + iat_rvas_ partially (offsets, not RVAs)

        // ── 2. Collect all sections ───────────────────────────────────────
        std::vector<PESection*> secs;
        for (auto& s : user_sections_) secs.push_back(&s);
        if (!idata_sec.data.empty())   secs.push_back(&idata_sec);

        u32 num_sections = u32(secs.size());

        // ── 3. Compute header size ────────────────────────────────────────
        // DOS stub (64) + PE sig (4) + COFF (20) + OptHdr (112) + DataDirs(16×8) + SectionTable
        static constexpr u32 OPT_HDR_SIZE = 112 + NUM_DATA_DIRS * 8;
        u32 header_raw = 64 + 4 + 20 + OPT_HDR_SIZE + num_sections * 40;
        u32 header_aligned = align_up(header_raw, FILE_ALIGN);

        // ── 4. Layout sections ────────────────────────────────────────────
        u32 cur_rva = SEC_ALIGN;          // first section at RVA 0x1000
        u32 cur_raw = header_aligned;

        for (auto* s : secs) {
            s->virt_size  = u32(s->data.size());
            s->raw_size   = align_up(s->virt_size, FILE_ALIGN);
            s->rva        = cur_rva;
            s->raw_offset = cur_raw;
            cur_rva       = align_up(cur_rva + s->virt_size, SEC_ALIGN);
            cur_raw      += s->raw_size;
        }

        // ── 5. Patch .idata RVAs (add idata section RVA to all offsets) ──
        if (!idata_sec.data.empty()) {
            patch_idata_rvas(idata_sec);
        }

        // ── 6. Collect sizes ──────────────────────────────────────────────
        u32 image_size = cur_rva;
        u32 entry_point = 0;
        for (auto* s : secs) {
            if (s->name == ".text") { entry_point = s->rva + entry_rva_in_text; break; }
        }

        u32 import_dir_rva  = 0;
        u32 import_dir_size = 0;
        if (!idata_sec.data.empty()) {
            import_dir_rva  = idata_sec.rva + idt_offset_in_idata_;
            import_dir_size = u32(import_groups_.size() + 1) * 20;
        }

        // ── 7. Emit header ────────────────────────────────────────────────
        std::vector<u8> out;
        out.reserve(cur_raw);

        // DOS stub (64 bytes). e_lfanew = 0x40.
        static const u8 dos[64] = {
            0x4D,0x5A,0x90,0x00,0x03,0x00,0x00,0x00,
            0x04,0x00,0x00,0x00,0xFF,0xFF,0x00,0x00,
            0xB8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x40,0x00,0x00,0x00  // e_lfanew at [0x3C]
        };
        wbytes(out, dos, 64);

        // NT signature
        w32(out, IMAGE_NT_SIGNATURE);

        // COFF header (20 bytes)
        w16(out, IMAGE_FILE_MACHINE_AMD64);
        w16(out, u16(num_sections));
        w32(out, u32(std::time(nullptr)));
        w32(out, 0);   // PointerToSymbolTable
        w32(out, 0);   // NumberOfSymbols
        w16(out, u16(OPT_HDR_SIZE));
        w16(out, IMAGE_FILE_FLAGS);

        // Optional header — PE32+ (112 bytes fixed + data dirs)
        w16(out, MAGIC_PE32PLUS);
        w8 (out, 14); w8(out, 0);   // linker version 14.0

        // Compute size_of_code / initialized_data
        u32 code_sz = 0, idata_sz = 0;
        for (auto* s : secs) {
            if (s->characteristics & 0x20) code_sz  += s->raw_size;
            else                           idata_sz += s->raw_size;
        }
        w32(out, code_sz);
        w32(out, idata_sz);
        w32(out, 0);                      // SizeOfUninitializedData
        w32(out, entry_point);
        w32(out, 0);                      // BaseOfCode (unused in PE32+)
        w64(out, image_base);
        w32(out, SEC_ALIGN);
        w32(out, FILE_ALIGN);
        w16(out, 6); w16(out, 0);         // OS version (6.0 = Vista+)
        w16(out, 0); w16(out, 0);         // Image version
        w16(out, 6); w16(out, 0);         // Subsystem version (6.0)
        w32(out, 0);                      // Win32VersionValue (must be 0)
        w32(out, image_size);
        w32(out, header_aligned);
        w32(out, 0);                      // CheckSum
        w16(out, subsystem);
        w16(out, DLL_CHARS);
        w64(out, 0x100000ULL);            // SizeOfStackReserve (1 MB)
        w64(out, 0x001000ULL);            // SizeOfStackCommit  (4 KB)
        w64(out, 0x100000ULL);            // SizeOfHeapReserve
        w64(out, 0x001000ULL);            // SizeOfHeapCommit
        w32(out, 0);                      // LoaderFlags
        w32(out, NUM_DATA_DIRS);

        // Data directories (16 × 8 bytes)
        for (u32 i = 0; i < NUM_DATA_DIRS; i++) {
            if (i == 1) {                 // Import directory
                w32(out, import_dir_rva);
                w32(out, import_dir_size);
            } else {
                w32(out, 0); w32(out, 0);
            }
        }

        // ── 8. Section table (40 bytes each) ─────────────────────────────
        for (auto* s : secs) {
            u8 name8[8] = {};
            for (int i = 0; i < 8 && size_t(i) < s->name.size(); i++)
                name8[i] = u8(s->name[i]);
            wbytes(out, name8, 8);
            w32(out, s->virt_size);
            w32(out, s->rva);
            w32(out, s->raw_size);
            w32(out, s->raw_offset);
            w32(out, 0); w32(out, 0);    // relocs / linenums (none)
            w16(out, 0); w16(out, 0);    // reloc count / linenum count
            w32(out, s->characteristics);
        }

        // Pad header to FILE_ALIGN
        wzero(out, header_aligned - u32(out.size()));

        // ── 9. Section data ───────────────────────────────────────────────
        for (auto* s : secs) {
            wbytes(out, s->data.data(), s->data.size());
            wzero(out, s->raw_size - s->virt_size); // zero-pad to file alignment
        }

        return out;
    }

    // After build(), returns the RVA of an IAT slot (0 if not found).
    u32 get_iat_rva(const std::string& dll, const std::string& func) const {
        auto key = dll + '\x01' + func;
        auto it  = iat_rvas_.find(key);
        return it != iat_rvas_.end() ? it->second : 0u;
    }

private:
    // ─── User sections ────────────────────────────────────────────────────
    std::vector<PESection> user_sections_;

    // ─── Import table state ───────────────────────────────────────────────
    struct ImpFunc { std::string name; u16 hint; };
    struct ImpDll  { std::string dll;  std::vector<ImpFunc> funcs; };
    std::vector<ImpDll> import_groups_;

    // key = dll + '\x01' + func  →  IAT slot RVA (filled after build)
    std::unordered_map<std::string, u32> iat_rvas_;

    // Byte offsets within the idata blob:
    u32 idt_offset_in_idata_ = 0;   // IDT starts here (always 0)
    u32 iat_offset_in_idata_ = 0;   // Start of IAT block

    // ─── Build .idata blob ────────────────────────────────────────────────
    //
    // Blob layout:
    //   [0]               IDT   (N+1) × 20 bytes
    //   [ilt_off]         ILT   for each DLL (num_funcs+1) × 8 bytes each
    //   [iat_off]         IAT   same layout as ILT
    //   [hn_off]          Hint/Name table entries
    //   [dll_names_off]   DLL name strings
    //
    // All internal RVA fields are stored as offsets from blob base;
    // patch_idata_rvas() adds the section RVA to convert them.
    //
    void build_idata(PESection& sec) {
        using namespace detail;

        if (import_groups_.empty()) return;

        const u32 ndlls = u32(import_groups_.size());

        // Count total functions
        u32 total_funcs = 0;
        for (auto& g : import_groups_) total_funcs += u32(g.funcs.size());

        // ── Compute block offsets ─────────────────────────────────────────
        u32 idt_off  = 0;
        u32 idt_size = (ndlls + 1) * 20;

        // ILT: for each DLL, (funcs+1) × 8 bytes (null terminated)
        u32 ilt_off  = idt_size;
        // Pre-compute per-DLL ILT offset
        std::vector<u32> dll_ilt_off(ndlls);
        u32 ilt_cur = ilt_off;
        for (u32 di = 0; di < ndlls; di++) {
            dll_ilt_off[di] = ilt_cur;
            ilt_cur += (u32(import_groups_[di].funcs.size()) + 1) * 8;
        }
        u32 ilt_total = ilt_cur - ilt_off;

        // IAT: same layout as ILT
        u32 iat_off  = ilt_off + ilt_total;
        iat_offset_in_idata_ = iat_off;
        std::vector<u32> dll_iat_off(ndlls);
        u32 iat_cur = iat_off;
        for (u32 di = 0; di < ndlls; di++) {
            dll_iat_off[di] = iat_cur;
            iat_cur += (u32(import_groups_[di].funcs.size()) + 1) * 8;
        }
        u32 iat_total = iat_cur - iat_off;

        // Hint/Name table
        u32 hn_off = iat_off + iat_total;
        // Pre-compute per-function HN offsets
        std::vector<std::vector<u32>> func_hn_off(ndlls);
        u32 hn_cur = hn_off;
        for (u32 di = 0; di < ndlls; di++) {
            func_hn_off[di].resize(import_groups_[di].funcs.size());
            for (u32 fi = 0; fi < u32(import_groups_[di].funcs.size()); fi++) {
                func_hn_off[di][fi] = hn_cur;
                u32 entry = 2 + u32(import_groups_[di].funcs[fi].name.size()) + 1;
                if (entry & 1) entry++; // WORD-align
                hn_cur += entry;
            }
        }
        u32 hn_total = hn_cur - hn_off;

        // DLL names
        u32 dllnames_off = hn_off + hn_total;
        std::vector<u32> dll_name_off(ndlls);
        u32 dllnames_cur = dllnames_off;
        for (u32 di = 0; di < ndlls; di++) {
            dll_name_off[di] = dllnames_cur;
            dllnames_cur += u32(import_groups_[di].dll.size()) + 1;
        }

        u32 total_size = dllnames_cur;
        sec.data.assign(total_size, 0);

        idt_offset_in_idata_ = 0;

        auto wr32 = [&](u32 off, u32 v) {
            sec.data[off+0]=u8(v);      sec.data[off+1]=u8(v>>8);
            sec.data[off+2]=u8(v>>16);  sec.data[off+3]=u8(v>>24);
        };
        auto wr64 = [&](u32 off, u64 v) {
            wr32(off,   u32(v));
            wr32(off+4, u32(v>>32));
        };

        // ── Emit IDT ──────────────────────────────────────────────────────
        for (u32 di = 0; di < ndlls; di++) {
            u32 base = idt_off + di * 20;
            // OriginalFirstThunk (ILT RVA — stored as offset, patched later)
            wr32(base +  0, dll_ilt_off[di]);
            wr32(base +  4, 0);                  // TimeDateStamp
            wr32(base +  8, 0);                  // ForwarderChain
            wr32(base + 12, dll_name_off[di]);   // Name RVA (offset, patch later)
            wr32(base + 16, dll_iat_off[di]);    // FirstThunk / IAT RVA (patch later)
        }
        // Null terminator IDT entry (all zeros — already zeroed)

        // ── Emit ILT + IAT ────────────────────────────────────────────────
        for (u32 di = 0; di < ndlls; di++) {
            u32 nf = u32(import_groups_[di].funcs.size());
            for (u32 fi = 0; fi < nf; fi++) {
                // By-name: bit63=0, bits[30:0] = RVA of hint/name entry
                u64 hn_rva = u64(func_hn_off[di][fi]); // offset (patch later)
                wr64(dll_ilt_off[di] + fi * 8, hn_rva);
                wr64(dll_iat_off[di] + fi * 8, hn_rva);

                // Record IAT slot offset (will add sectionRVA in patch step)
                auto key = import_groups_[di].dll + '\x01' + import_groups_[di].funcs[fi].name;
                iat_rvas_[key] = dll_iat_off[di] + fi * 8; // offset for now
            }
            // Null qword terminators already zeroed
        }

        // ── Emit Hint/Name table ──────────────────────────────────────────
        for (u32 di = 0; di < ndlls; di++) {
            for (u32 fi = 0; fi < u32(import_groups_[di].funcs.size()); fi++) {
                u32 off  = func_hn_off[di][fi];
                u16 hint = import_groups_[di].funcs[fi].hint;
                sec.data[off+0] = u8(hint);
                sec.data[off+1] = u8(hint >> 8);
                const std::string& nm = import_groups_[di].funcs[fi].name;
                for (u32 c = 0; c < u32(nm.size()); c++)
                    sec.data[off + 2 + c] = u8(nm[c]);
                // null terminator already zero
            }
        }

        // ── Emit DLL names ────────────────────────────────────────────────
        for (u32 di = 0; di < ndlls; di++) {
            u32 off = dll_name_off[di];
            const std::string& dn = import_groups_[di].dll;
            for (u32 c = 0; c < u32(dn.size()); c++)
                sec.data[off + c] = u8(dn[c]);
        }
    }

    // ─── Patch .idata: add the section's RVA to all stored offsets ───────────
    void patch_idata_rvas(PESection& sec) {
        u32 base = sec.rva;

        auto add32_at = [&](u32 off) {
            u32 v = u32(sec.data[off])        |
                    u32(sec.data[off+1]) <<  8 |
                    u32(sec.data[off+2]) << 16 |
                    u32(sec.data[off+3]) << 24;
            v += base;
            sec.data[off+0]=u8(v);      sec.data[off+1]=u8(v>>8);
            sec.data[off+2]=u8(v>>16);  sec.data[off+3]=u8(v>>24);
        };
        auto add64_at = [&](u32 off) {
            u64 v = u64(sec.data[off])         |
                    u64(sec.data[off+1]) <<  8  |
                    u64(sec.data[off+2]) << 16  |
                    u64(sec.data[off+3]) << 24  |
                    u64(sec.data[off+4]) << 32  |
                    u64(sec.data[off+5]) << 40  |
                    u64(sec.data[off+6]) << 48  |
                    u64(sec.data[off+7]) << 56;
            v += base;
            sec.data[off+0]=u8(v);      sec.data[off+1]=u8(v>>8);
            sec.data[off+2]=u8(v>>16);  sec.data[off+3]=u8(v>>24);
            sec.data[off+4]=u8(v>>32);  sec.data[off+5]=u8(v>>40);
            sec.data[off+6]=u8(v>>48);  sec.data[off+7]=u8(v>>56);
        };

        u32 ndlls = u32(import_groups_.size());
        for (u32 di = 0; di < ndlls; di++) {
            u32 idt_base = idt_offset_in_idata_ + di * 20;
            add32_at(idt_base +  0); // OriginalFirstThunk (ILT RVA)
            add32_at(idt_base + 12); // Name RVA
            add32_at(idt_base + 16); // FirstThunk (IAT RVA)

            u32 nf = u32(import_groups_[di].funcs.size());
            // Walk the IDT entry we just patched to get ILT/IAT offsets.
            {
                auto rd32 = [&](u32 o) -> u32 {
                    return u32(sec.data[o])       | u32(sec.data[o+1])<<8 |
                           u32(sec.data[o+2])<<16 | u32(sec.data[o+3])<<24;
                };
                u32 ilt_rva = rd32(idt_base +  0) - base; // undo base for offset
                u32 iat_rva = rd32(idt_base + 16) - base;
                for (u32 fi = 0; fi < nf; fi++) {
                    // Patch ILT entry (64-bit, bit63=0 → by-name, lower 32 = HN RVA)
                    add64_at(ilt_rva + fi * 8);
                    add64_at(iat_rva + fi * 8);
                }
            }
        }

        // Update iat_rvas_ from offsets → actual RVAs
        for (auto& kv : iat_rvas_) {
            kv.second += base;
        }
    }
};

// ─── Free function: write PE image to file ────────────────────────────────────
inline void write_pe(const std::string& path, const std::vector<u8>& data) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) throw std::runtime_error("Cannot open output file: " + path);
    f.write(reinterpret_cast<const char*>(data.data()),
            static_cast<std::streamsize>(data.size()));
    if (!f) throw std::runtime_error("Write error: " + path);
}

} // namespace pe
} // namespace mce

// ─── Add unordered_map to types deps ─────────────────────────────────────────
#include <unordered_map>
