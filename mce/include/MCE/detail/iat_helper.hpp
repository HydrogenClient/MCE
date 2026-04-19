#pragma once
/*
 * iat_helper.hpp  ─  Shared Win64 IAT-call patching utilities
 *
 * Include this in any translation unit that needs to:
 *   1. Emit CALL [RIP + IAT_slot] trampolines during code generation
 *   2. Patch those trampolines after the PE builder has fixed IAT RVAs
 *
 * Usage:
 *   mce::IATHelper iat(emitter, pe_builder);
 *   iat.call("kernel32.dll", "ExitProcess");  // emits FF 15 <placeholder>
 *   ...
 *   auto image = peb.build(entry);
 *   iat.patch(image);                          // fix all placeholders
 */

#include "../emitterx64"
#include <vector>
#include <string>
#include <cstdio>

namespace mce {

// ─── IATHelper ───────────────────────────────────────────────────────────────
class IATHelper {
public:
    explicit IATHelper(EmitterX64& e, pe::PEBuilder& peb)
        : e_(e), peb_(peb) {}

    // Emit a CALL QWORD PTR [RIP + disp32] to the named IAT slot.
    // Records a fixup to be applied by patch().
    void call(const std::string& dll, const std::string& func) {
        e_.raw(0xFF); e_.raw(0x15);               // FF /2 ModRM RIP-rel
        fixups_.push_back({ e_.current_offset(), dll, func });
        e_.raw({0,0,0,0});                         // disp32 placeholder
    }

    // Patch all recorded fixups into the PE image byte vector.
    // Call this immediately after pe_builder.build().
    void patch(std::vector<u8>& image) const {
        constexpr u32 text_rva = 0x1000; // MCE always places .text at RVA 0x1000

        // Locate the .text section's raw file offset
        u32 e_lfanew = read_u32(image, 0x3C);
        usize pe = e_lfanew;
        if (pe + 4 > image.size()) return;
        u16 num_secs = read_u16(image, pe + 4 + 2);
        u16 opt_size = read_u16(image, pe + 4 + 16);
        usize st = pe + 4 + 20 + opt_size;

        u32 text_raw = 0;
        for (u16 si = 0; si < num_secs; si++) {
            usize s = st + si * 40;
            if (read_u32(image, s + 12) == text_rva) {
                text_raw = read_u32(image, s + 20);
                break;
            }
        }
        if (!text_raw) {
            fprintf(stderr, "[MCE] IATHelper::patch: .text raw offset not found\n");
            return;
        }

        for (auto& fx : fixups_) {
            u32 iat_rva = peb_.get_iat_rva(fx.dll, fx.func);
            if (!iat_rva) {
                fprintf(stderr, "[MCE] IATHelper::patch: IAT slot not found for %s!%s\n",
                        fx.dll.c_str(), fx.func.c_str());
                continue;
            }
            // disp32 = iat_rva - (text_rva + disp_pos + 4)
            //   because  RIP  = VA of byte after the disp32  =  image_base + text_rva + disp_pos + 4
            //   and      CALL target = image_base + iat_rva
            i32 disp = static_cast<i32>(iat_rva) -
                       static_cast<i32>(text_rva + fx.disp_pos + 4);

            u32 abs = text_raw + static_cast<u32>(fx.disp_pos);
            if (abs + 4 > image.size()) {
                fprintf(stderr, "[MCE] IATHelper::patch: fixup out of bounds\n");
                continue;
            }
            image[abs + 0] = static_cast<u8>( disp        & 0xFF);
            image[abs + 1] = static_cast<u8>((disp >>  8) & 0xFF);
            image[abs + 2] = static_cast<u8>((disp >> 16) & 0xFF);
            image[abs + 3] = static_cast<u8>((disp >> 24) & 0xFF);
        }
    }

    // RIP-relative LEA helper: emits  LEA RDX, [RIP + rel_to_offset]
    // where offset is a byte offset in the .text buffer.
    // Use this to take the address of embedded string/data literals.
    void lea_rip_rdx(u32 data_offset_in_text) {
        // 48 8D 15 <rel32>
        e_.raw({0x48, 0x8D, 0x15});
        patch_rip_rel(data_offset_in_text);
    }
    void lea_rip_rcx(u32 data_offset_in_text) {
        // 48 8D 0D <rel32>
        e_.raw({0x48, 0x8D, 0x0D});
        patch_rip_rel(data_offset_in_text);
    }
    void lea_rip_r8(u32 data_offset_in_text) {
        // 4C 8D 05 <rel32>
        e_.raw({0x4C, 0x8D, 0x05});
        patch_rip_rel(data_offset_in_text);
    }

    // Embed bytes/strings in .text, return their offset
    u32 embed(const void* data, usize size) {
        u32 off = e_.current_offset();
        e_.raw(static_cast<const u8*>(data), size);
        return off;
    }
    u32 embed_str(const char* s) { return embed(s, strlen(s) + 1); }

    // Emit jump-over + data block; returns offset of embedded data
    u32 embed_skipped(const void* data, usize size) {
        auto skip = e_.make_label();
        e_.jmp(skip);
        u32 off = embed(data, size);
        e_.bind(skip);
        return off;
    }
    u32 embed_skipped_str(const char* s) { return embed_skipped(s, strlen(s)); } // no null
    u32 embed_skipped_strz(const char* s) { return embed_skipped(s, strlen(s)+1); }

private:
    struct Fixup {
        usize       disp_pos;           // byte offset of disp32 in .text buffer
        std::string dll, func;
    };

    EmitterX64&      e_;
    pe::PEBuilder&   peb_;
    std::vector<Fixup> fixups_;

    // Patch a RIP-relative disp32: the disp32 slot is at current_offset();
    // data_off is where the target data lives in .text.
    void patch_rip_rel(u32 data_off) {
        u32 dp = e_.current_offset();
        e_.raw({0,0,0,0});
        i32 rel = static_cast<i32>(data_off) - static_cast<i32>(dp + 4);
        auto& buf = const_cast<byte_vec&>(e_.code());
        buf[dp+0] = u8( rel        & 0xFF);
        buf[dp+1] = u8((rel >>  8) & 0xFF);
        buf[dp+2] = u8((rel >> 16) & 0xFF);
        buf[dp+3] = u8((rel >> 24) & 0xFF);
    }

    static u16 read_u16(const std::vector<u8>& v, usize o) {
        return static_cast<u16>(v[o]) | (static_cast<u16>(v[o+1]) << 8);
    }
    static u32 read_u32(const std::vector<u8>& v, usize o) {
        return static_cast<u32>(v[o])        |
              (static_cast<u32>(v[o+1]) << 8) |
              (static_cast<u32>(v[o+2]) << 16)|
              (static_cast<u32>(v[o+3]) << 24);
    }
};

// ─── Standalone WriteFile wrapper to reuse across examples ───────────────
// Emits code that calls WriteFile(handle_in_rbx, ptr, len, &scratch, NULL).
// ptr and len must be in RDX and R8 at call time. handle in RBX. Scratches RAX.
inline void emit_print(EmitterX64& e, IATHelper& iat,
                       Reg64 handle_reg  = Reg64::RBX)
{
    using namespace detail;
    // RCX = handle
    if (handle_reg != Reg64::RCX)
        e.mov(Reg64::RCX, handle_reg);
    // RDX = ptr  (already set by caller)
    // R8  = len  (already set by caller)
    // R9  = &written  (we use a scratch slot: [rsp+32+8] = [rsp+40])
    e.lea(Reg64::R9, qword_ptr(Reg64::RSP, 40));
    e.mov(qword_ptr(Reg64::RSP, 32), static_cast<i32>(0)); // 5th arg = NULL
    iat.call("kernel32.dll", "WriteFile");
}

} // namespace mce
