#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <stdexcept>
#include <unordered_map>
#include <functional>
#include <cassert>

namespace mce {

using u8  = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;
using i8  = int8_t;
using i16 = int16_t;
using i32 = int32_t;
using i64 = int64_t;
using usize = std::size_t;
using byte_vec = std::vector<u8>;

// ────────────────────────────────────────────────────────────────────────────
//  Registers
// ────────────────────────────────────────────────────────────────────────────
enum class Reg8  : u8 { AL=0, CL, DL, BL, AH, CH, DH, BH,
                         R8B=8, R9B, R10B, R11B, R12B, R13B, R14B, R15B,
                         SPL=36, BPL, SIL, DIL };
enum class Reg16 : u8 { AX=0, CX, DX, BX, SP, BP, SI, DI,
                         R8W=8, R9W, R10W, R11W, R12W, R13W, R14W, R15W };
enum class Reg32 : u8 { EAX=0, ECX, EDX, EBX, ESP, EBP, ESI, EDI,
                         R8D=8, R9D, R10D, R11D, R12D, R13D, R14D, R15D };
enum class Reg64 : u8 { RAX=0, RCX, RDX, RBX, RSP, RBP, RSI, RDI,
                         R8=8, R9, R10, R11, R12, R13, R14, R15 };

// XMM / YMM
enum class RegXMM : u8 { XMM0=0, XMM1, XMM2, XMM3, XMM4, XMM5, XMM6, XMM7,
                          XMM8, XMM9, XMM10, XMM11, XMM12, XMM13, XMM14, XMM15 };
enum class RegYMM : u8 { YMM0=0, YMM1, YMM2, YMM3, YMM4, YMM5, YMM6, YMM7,
                          YMM8, YMM9, YMM10, YMM11, YMM12, YMM13, YMM14, YMM15 };

// Condition codes (for Jcc / SETcc / CMOVcc)
enum class Cond : u8 {
    O=0, NO, B, NB, E, NE, BE, A,
    S, NS, P, NP, L, GE, LE, G,
    // aliases
    C=B, NC=NB, Z=E, NZ=NE, NAE=B, AE=NB,
    NA=BE, NBE=A, PE=P, PO=NP, NGE=L, NL=GE, NLE=G, NG=LE
};

// Scale for SIB
enum class Scale : u8 { x1=0, x2=1, x4=2, x8=3 };

// ────────────────────────────────────────────────────────────────────────────
//  Memory operand
// ────────────────────────────────────────────────────────────────────────────
struct Mem {
    bool     has_base  = false;
    bool     has_index = false;
    bool     riprel    = false;
    Reg64    base      = Reg64::RAX;
    Reg64    index     = Reg64::RAX;
    Scale    scale     = Scale::x1;
    i32      disp      = 0;
    u8       ptr_size  = 64; // 8 / 16 / 32 / 64 bits

    // e.g. qword_ptr(Reg64::RBP, -8)
    static Mem make(Reg64 b, i32 d=0, u8 sz=64) {
        Mem m; m.has_base=true; m.base=b; m.disp=d; m.ptr_size=sz; return m;
    }
    static Mem make(Reg64 b, Reg64 idx, Scale sc, i32 d=0, u8 sz=64) {
        Mem m; m.has_base=true; m.base=b; m.has_index=true;
        m.index=idx; m.scale=sc; m.disp=d; m.ptr_size=sz; return m;
    }
    static Mem rip(i32 d, u8 sz=64) {
        Mem m; m.riprel=true; m.disp=d; m.ptr_size=sz; return m;
    }
    static Mem abs(u64 addr, u8 sz=64) {
        // encoded as [disp32] with no base (mod=00, rm=101 in 64-bit → RIP+disp)
        // For true absolute we use mov rax,addr trick outside, but we support SIB abs:
        Mem m; m.disp=(i32)addr; m.ptr_size=sz; return m;
    }
};

// Convenience builders
inline Mem byte_ptr (Reg64 b, i32 d=0) { return Mem::make(b,d,8);  }
inline Mem word_ptr (Reg64 b, i32 d=0) { return Mem::make(b,d,16); }
inline Mem dword_ptr(Reg64 b, i32 d=0) { return Mem::make(b,d,32); }
inline Mem qword_ptr(Reg64 b, i32 d=0) { return Mem::make(b,d,64); }
inline Mem byte_ptr (Reg64 b, Reg64 i, Scale s, i32 d=0) { return Mem::make(b,i,s,d,8);  }
inline Mem word_ptr (Reg64 b, Reg64 i, Scale s, i32 d=0) { return Mem::make(b,i,s,d,16); }
inline Mem dword_ptr(Reg64 b, Reg64 i, Scale s, i32 d=0) { return Mem::make(b,i,s,d,32); }
inline Mem qword_ptr(Reg64 b, Reg64 i, Scale s, i32 d=0) { return Mem::make(b,i,s,d,64); }

// ────────────────────────────────────────────────────────────────────────────
//  Label handle
// ────────────────────────────────────────────────────────────────────────────
struct Label {
    u32 id = 0;
    Label() = default;
    explicit Label(u32 id_) : id(id_) {}
};

} // namespace mce
