#pragma once
#include "types.hpp"

namespace mce {
namespace detail {

// ────────────────────────────────────────────────────────────────────────────
//  REX prefix helpers
// ────────────────────────────────────────────────────────────────────────────
// REX = 0100 WRXB
//  W: 64-bit operand size
//  R: extension of ModRM.reg
//  X: extension of SIB.index
//  B: extension of ModRM.rm / SIB.base / opcode reg

inline u8 rex_byte(bool W, bool R, bool X, bool B) {
    return static_cast<u8>(0x40 | (W?8:0) | (R?4:0) | (X?2:0) | (B?1:0));
}

// Returns true if the register index requires a REX extension (r8–r15)
inline bool needs_rex_ext(u8 idx) { return idx >= 8; }
inline u8   reg_lo3(u8 idx)       { return idx & 7; }

// Raw index from Reg64/Reg32/Reg16/Reg8 enum
inline u8 idx(Reg64 r) { return static_cast<u8>(r); }
inline u8 idx(Reg32 r) { return static_cast<u8>(r); }
inline u8 idx(Reg16 r) { return static_cast<u8>(r); }
inline u8 idx(Reg8  r) {
    u8 v = static_cast<u8>(r);
    // SPL/BPL/SIL/DIL encoded as 4-7 in reg field (need REX present)
    if (v == 36) return 4;
    if (v == 37) return 5;
    if (v == 38) return 6;
    if (v == 39) return 7;
    return v;
}
inline u8 idx(RegXMM r) { return static_cast<u8>(r); }
inline u8 idx(RegYMM r) { return static_cast<u8>(r); }

// ────────────────────────────────────────────────────────────────────────────
//  ModRM / SIB
// ────────────────────────────────────────────────────────────────────────────
inline u8 modrm(u8 mod, u8 reg, u8 rm) {
    return static_cast<u8>((mod << 6) | ((reg & 7) << 3) | (rm & 7));
}
inline u8 sib(u8 scale, u8 index, u8 base) {
    return static_cast<u8>((scale << 6) | ((index & 7) << 3) | (base & 7));
}

// ────────────────────────────────────────────────────────────────────────────
//  Immediate helpers (little-endian push)
// ────────────────────────────────────────────────────────────────────────────
inline void emit_u8 (byte_vec& v, u8  x) { v.push_back(x); }
inline void emit_u16(byte_vec& v, u16 x) {
    v.push_back(x & 0xFF);
    v.push_back((x >> 8) & 0xFF);
}
inline void emit_u32(byte_vec& v, u32 x) {
    v.push_back( x        & 0xFF);
    v.push_back((x >>  8) & 0xFF);
    v.push_back((x >> 16) & 0xFF);
    v.push_back((x >> 24) & 0xFF);
}
inline void emit_u64(byte_vec& v, u64 x) {
    emit_u32(v, (u32)(x & 0xFFFFFFFF));
    emit_u32(v, (u32)(x >> 32));
}
inline void emit_i8 (byte_vec& v, i8  x) { emit_u8 (v, (u8)x);  }
inline void emit_i16(byte_vec& v, i16 x) { emit_u16(v, (u16)x); }
inline void emit_i32(byte_vec& v, i32 x) { emit_u32(v, (u32)x); }
inline void emit_i64(byte_vec& v, i64 x) { emit_u64(v, (u64)x); }

// Patch a 32-bit value at position pos inside vec
inline void patch_u32(byte_vec& v, usize pos, u32 x) {
    v[pos+0] = (u8)( x        & 0xFF);
    v[pos+1] = (u8)((x >>  8) & 0xFF);
    v[pos+2] = (u8)((x >> 16) & 0xFF);
    v[pos+3] = (u8)((x >> 24) & 0xFF);
}
inline void patch_i32(byte_vec& v, usize pos, i32 x) { patch_u32(v, pos, (u32)x); }

// ────────────────────────────────────────────────────────────────────────────
//  Disp size helpers
// ────────────────────────────────────────────────────────────────────────────
inline bool fits_i8(i32 d)  { return d >= -128 && d <= 127; }

// ────────────────────────────────────────────────────────────────────────────
//  Emit a memory operand (ModRM + optional SIB + displacement)
//  reg_field: the /r bits (opcode extension or register)
// ────────────────────────────────────────────────────────────────────────────
struct RexInfo {
    bool R = false; // extension of ModRM.reg
    bool X = false; // extension of SIB.index
    bool B = false; // extension of ModRM.rm / base
};

// Emits ModRM[+SIB][+disp] for a memory operand.
// Returns RexInfo so caller can assemble REX byte.
inline RexInfo emit_mem_operand(byte_vec& out, u8 reg_field, const Mem& m) {
    RexInfo ri;
    ri.R = needs_rex_ext(reg_field);

    if (m.riprel) {
        // [RIP + disp32]
        emit_u8(out, modrm(0, reg_field, 5));
        emit_i32(out, m.disp);
        return ri;
    }

    if (!m.has_base && !m.has_index) {
        // Absolute: use SIB with no base (mod=00, rm=100, sib: scale=0, index=4 (none), base=5)
        emit_u8(out, modrm(0, reg_field, 4));
        emit_u8(out, sib(0, 4, 5));
        emit_i32(out, m.disp);
        return ri;
    }

    u8 base_idx  = m.has_base  ? idx(m.base)  : 5;
    u8 index_idx = m.has_index ? idx(m.index) : 4; // 4 = no index
    u8 scale_val = (u8)m.scale;

    ri.B = needs_rex_ext(base_idx);
    ri.X = m.has_index && needs_rex_ext(index_idx);

    bool need_sib = m.has_index ||
                    reg_lo3(base_idx) == 4 || // RSP/R12 as base → always SIB
                    !m.has_base;

    // Determine mod
    u8 mod;
    if (m.disp == 0 && reg_lo3(base_idx) != 5)
        mod = 0;                     // [base]
    else if (fits_i8(m.disp))
        mod = 1;                     // [base + disp8]
    else
        mod = 2;                     // [base + disp32]

    if (need_sib) {
        emit_u8(out, modrm(mod, reg_field, 4));
        emit_u8(out, sib(scale_val, index_idx, base_idx));
    } else {
        emit_u8(out, modrm(mod, reg_field, base_idx));
    }

    if (mod == 1) emit_i8 (out, (i8)m.disp);
    if (mod == 2) emit_i32(out, m.disp);

    return ri;
}

// ────────────────────────────────────────────────────────────────────────────
//  REX prefix emitter (only emits if needed)
// ────────────────────────────────────────────────────────────────────────────
inline void emit_rex(byte_vec& out, bool W, bool R, bool X, bool B, bool force=false) {
    if (W || R || X || B || force)
        out.push_back(rex_byte(W, R, X, B));
}

} // namespace detail
} // namespace mce
