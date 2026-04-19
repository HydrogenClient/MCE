#pragma once
#include "types.hpp"
#include "encoding.hpp"
#include "pe_writer.hpp"
#include <stdexcept>
#include <unordered_map>
#include <string>
#include <vector>
#include <cassert>
#include <functional>

namespace mce {

using namespace detail;

// ═══════════════════════════════════════════════════════════════════════════
//  EmitterX64 — x86-64 machine code emitter
//
//  Usage:
//    EmitterX64 e;
//    auto lbl = e.make_label();
//    e.mov(Reg64::RCX, Reg64::RAX);
//    e.ret();
//    e.emit("output.exe");
// ═══════════════════════════════════════════════════════════════════════════
class EmitterX64 {
public:
    // ── Construction / reset ─────────────────────────────────────────────
    EmitterX64()  = default;
    ~EmitterX64() = default;

    void reset() {
        buf_.clear();
        labels_.clear();
        fixups_.clear();
        rdata_.clear();
        data_.clear();
        imports_.clear();
    }

    // ── Label API ────────────────────────────────────────────────────────
    Label make_label() {
        u32 id = (u32)labels_.size();
        labels_.push_back({false, 0});
        return Label{id};
    }

    void bind(Label lbl) {
        auto& info = labels_[lbl.id];
        if (info.bound) throw std::logic_error("Label already bound");
        info.bound  = true;
        info.offset = (u32)buf_.size();
        // Patch all pending fixups for this label
        for (auto& fx : fixups_) {
            if (fx.label_id == lbl.id && !fx.patched) {
                patch_fixup(fx);
                fx.patched = true;
            }
        }
    }

    // ── Data sections ────────────────────────────────────────────────────
    // Append bytes to .rdata; returns offset within .rdata
    u32 add_rdata(const void* data, usize size) {
        u32 off = (u32)rdata_.size();
        const u8* p = (const u8*)data;
        rdata_.insert(rdata_.end(), p, p + size);
        if (rdata_.size() & 1) rdata_.push_back(0); // align
        return off;
    }
    u32 add_string(const char* s) {
        return add_rdata(s, std::strlen(s) + 1);
    }

    u32 add_data(const void* data, usize size) {
        u32 off = (u32)data_.size();
        const u8* p = (const u8*)data;
        data_.insert(data_.end(), p, p + size);
        return off;
    }

    // ── Import API ───────────────────────────────────────────────────────
    void add_import(const std::string& dll, const std::string& func, u32 hint = 0) {
        imports_.push_back({dll, func, hint});
    }

    // ── Emit / output ────────────────────────────────────────────────────
    // Get the raw code bytes
    const byte_vec& code() const { return buf_; }
    byte_vec&       code()       { return buf_; }
    usize           size()  const { return buf_.size(); }
    usize           pos()   const { return buf_.size(); }

    // Emit to PE file
    void emit(const std::string& output_path,
              u32 entry_offset = 0,     // offset within .text that is the entry point
              u16 subsystem = 3 /*console*/) {
        resolve_all_fixups();
        pe::PEBuilder pe;
        pe.subsystem = subsystem;

        auto& text = pe.add_section(".text", pe::SEC_CODE);
        text = buf_;

        if (!rdata_.empty()) {
            auto& rd = pe.add_section(".rdata", pe::SEC_RDATA);
            rd = rdata_;
        }
        if (!data_.empty()) {
            auto& dv = pe.add_section(".data", pe::SEC_DATA);
            dv = data_;
        }

        for (auto& imp : imports_)
            pe.add_import(imp.dll, imp.func, imp.hint);

        auto bytes = pe.build(entry_offset);
        pe::write_pe(output_path, bytes);
    }

    // ── Size/position helpers ─────────────────────────────────────────────
    u32 current_offset() const { return (u32)buf_.size(); }

    // Raw byte push (escape hatch)
    void raw(u8 b)                  { buf_.push_back(b); }
    void raw(std::initializer_list<u8> bs) { for(auto b:bs) buf_.push_back(b); }
    void raw(const u8* p, usize n)  { buf_.insert(buf_.end(),p,p+n); }

    // ════════════════════════════════════════════════════════════════════
    //  NOP / HALT / INT3 / UD2
    // ════════════════════════════════════════════════════════════════════
    void nop()  { emit_u8(buf_, 0x90); }
    void nop(int n) { // multi-byte NOP
        static const u8 nops[][9] = {
            {},
            {0x90},
            {0x66,0x90},
            {0x0F,0x1F,0x00},
            {0x0F,0x1F,0x40,0x00},
            {0x0F,0x1F,0x44,0x00,0x00},
            {0x66,0x0F,0x1F,0x44,0x00,0x00},
            {0x0F,0x1F,0x80,0x00,0x00,0x00,0x00},
            {0x0F,0x1F,0x84,0x00,0x00,0x00,0x00,0x00},
            {0x66,0x0F,0x1F,0x84,0x00,0x00,0x00,0x00,0x00},
        };
        while (n > 0) {
            int k = n > 9 ? 9 : n;
            buf_.insert(buf_.end(), nops[k], nops[k]+k);
            n -= k;
        }
    }
    void hlt()  { emit_u8(buf_, 0xF4); }
    void int3() { emit_u8(buf_, 0xCC); }
    void int_(u8 vec) { emit_u8(buf_, 0xCD); emit_u8(buf_, vec); }
    void ud2()  { emit_u8(buf_, 0x0F); emit_u8(buf_, 0x0B); }
    void syscall() { emit_u8(buf_,0x0F); emit_u8(buf_,0x05); }
    void sysret()  { emit_u8(buf_,0x0F); emit_u8(buf_,0x07); }
    void cpuid()   { emit_u8(buf_,0x0F); emit_u8(buf_,0xA2); }
    void pause_()  { emit_u8(buf_,0xF3); emit_u8(buf_,0x90); }
    void mfence()  { raw({0x0F,0xAE,0xF0}); }
    void lfence()  { raw({0x0F,0xAE,0xE8}); }
    void sfence()  { raw({0x0F,0xAE,0xF8}); }
    void cld()  { emit_u8(buf_,0xFC); }
    void std_() { emit_u8(buf_,0xFD); }
    void clc()  { emit_u8(buf_,0xF8); }
    void stc()  { emit_u8(buf_,0xF9); }
    void cmc()  { emit_u8(buf_,0xF5); }
    void pushfq() { emit_u8(buf_,0x9C); }
    void popfq()  { emit_u8(buf_,0x9D); }
    void lahf()   { emit_u8(buf_,0x9F); }
    void sahf()   { emit_u8(buf_,0x9E); }
    void ret()    { emit_u8(buf_,0xC3); }
    void retf()   { emit_u8(buf_,0xCB); }
    void ret(u16 imm) { emit_u8(buf_,0xC2); emit_u16(buf_,imm); }

    // ════════════════════════════════════════════════════════════════════
    //  PUSH / POP  (64-bit only in 64-bit mode)
    // ════════════════════════════════════════════════════════════════════
    void push(Reg64 r) {
        u8 ri = idx(r);
        if (needs_rex_ext(ri)) emit_u8(buf_, rex_byte(0,0,0,1));
        emit_u8(buf_, 0x50 | reg_lo3(ri));
    }
    void pop(Reg64 r) {
        u8 ri = idx(r);
        if (needs_rex_ext(ri)) emit_u8(buf_, rex_byte(0,0,0,1));
        emit_u8(buf_, 0x58 | reg_lo3(ri));
    }
    void push(i32 imm) {
        if (fits_i8(imm)) { emit_u8(buf_,0x6A); emit_i8(buf_,(i8)imm); }
        else               { emit_u8(buf_,0x68); emit_i32(buf_,imm); }
    }
    void push(const Mem& m) { emit_mem_instr_no_rex_w(0xFF, 6, m); } // PUSH r/m64
    void pop (const Mem& m) { emit_mem_instr_no_rex_w(0x8F, 0, m); } // POP  r/m64

    // ════════════════════════════════════════════════════════════════════
    //  MOV
    // ════════════════════════════════════════════════════════════════════

    // --- 64-bit ---
    void mov(Reg64 dst, Reg64 src) {
        emit_rex(buf_, true, needs_rex_ext(idx(src)), false, needs_rex_ext(idx(dst)));
        emit_u8(buf_, 0x89); // MOV r/m64, r64
        emit_u8(buf_, modrm(3, idx(src), idx(dst)));
    }
    void mov(Reg64 dst, i64 imm) {
        u8 ri = idx(dst);
        if ((u64)imm <= 0xFFFFFFFFULL && imm >= 0) {
            // Zero-extended 32-bit → zeroes upper 32 bits
            emit_rex(buf_, false, false, false, needs_rex_ext(ri));
            emit_u8(buf_, 0xB8 | reg_lo3(ri)); // MOV r32, imm32
            emit_u32(buf_, (u32)imm);
        } else if (imm >= -0x80000000LL && imm <= 0x7FFFFFFFLL) {
            // Sign-extended 32-bit
            emit_rex(buf_, true, false, false, needs_rex_ext(ri));
            emit_u8(buf_, 0xC7);
            emit_u8(buf_, modrm(3, 0, ri));
            emit_i32(buf_, (i32)imm);
        } else {
            // Full 64-bit immediate
            emit_rex(buf_, true, false, false, needs_rex_ext(ri));
            emit_u8(buf_, 0xB8 | reg_lo3(ri)); // MOV r64, imm64
            emit_i64(buf_, imm);
        }
    }
    void mov(Reg64 dst, u64 imm) { mov(dst, (i64)imm); }
    void mov(Reg64 dst, const Mem& src) { // MOV r64, r/m64
        u8 ri = idx(dst);
        usize rex_pos = buf_.size();
        buf_.push_back(0); // placeholder
        emit_u8(buf_, 0x8B);
        auto ri_ = emit_mem_operand(buf_, ri, src);
        buf_[rex_pos] = rex_byte(true, ri_.R || needs_rex_ext(ri), ri_.X, ri_.B);
    }
    void mov(const Mem& dst, Reg64 src) { // MOV r/m64, r64
        u8 ri = idx(src);
        usize rex_pos = buf_.size();
        buf_.push_back(0);
        emit_u8(buf_, 0x89);
        auto ri_ = emit_mem_operand(buf_, ri, dst);
        buf_[rex_pos] = rex_byte(true, ri_.R || needs_rex_ext(ri), ri_.X, ri_.B);
    }
    void mov(const Mem& dst, i32 imm) { // MOV r/m64, imm32 (sign-extended)
        emit_rex_prefix_for_mem(dst, true);
        emit_u8(buf_, 0xC7);
        emit_mem_operand(buf_, 0, dst);
        emit_i32(buf_, imm);
    }

    // --- 32-bit ---
    void mov(Reg32 dst, Reg32 src) {
        bool need_rex = needs_rex_ext(idx(src)) || needs_rex_ext(idx(dst));
        if (need_rex) emit_rex(buf_, false, needs_rex_ext(idx(src)), false, needs_rex_ext(idx(dst)));
        emit_u8(buf_, 0x89);
        emit_u8(buf_, modrm(3, idx(src), idx(dst)));
    }
    void mov(Reg32 dst, u32 imm) {
        if (needs_rex_ext(idx(dst))) emit_rex(buf_, false, false, false, true);
        emit_u8(buf_, 0xB8 | reg_lo3(idx(dst)));
        emit_u32(buf_, imm);
    }
    void mov(Reg32 dst, i32 imm) { mov(dst, (u32)imm); }
    void mov(Reg32 dst, const Mem& src) {
        u8 ri = idx(dst);
        usize rx = buf_.size(); buf_.push_back(0);
        emit_u8(buf_, 0x8B);
        auto ri_ = emit_mem_operand(buf_, ri, src);
        bool need = ri_.R || ri_.X || ri_.B || needs_rex_ext(ri);
        if (need) buf_[rx] = rex_byte(false, ri_.R || needs_rex_ext(ri), ri_.X, ri_.B);
        else      buf_.erase(buf_.begin() + rx);
    }
    void mov(const Mem& dst, Reg32 src) {
        u8 ri = idx(src);
        usize rx = buf_.size(); buf_.push_back(0);
        emit_u8(buf_, 0x89);
        auto ri_ = emit_mem_operand(buf_, ri, dst);
        bool need = ri_.R || ri_.X || ri_.B || needs_rex_ext(ri);
        if (need) buf_[rx] = rex_byte(false, ri_.R || needs_rex_ext(ri), ri_.X, ri_.B);
        else      buf_.erase(buf_.begin() + rx);
    }
    void mov(const Mem& dst, u32 imm) { // MOV r/m32, imm32
        emit_rex_prefix_for_mem(dst, false);
        emit_u8(buf_, 0xC7);
        emit_mem_operand(buf_, 0, dst);
        emit_u32(buf_, imm);
    }

    // --- 16-bit ---
    void mov(Reg16 dst, Reg16 src) {
        emit_u8(buf_, 0x66);
        bool need_rex = needs_rex_ext(idx(src)) || needs_rex_ext(idx(dst));
        if (need_rex) emit_rex(buf_, false, needs_rex_ext(idx(src)), false, needs_rex_ext(idx(dst)));
        emit_u8(buf_, 0x89);
        emit_u8(buf_, modrm(3, idx(src), idx(dst)));
    }
    void mov(Reg16 dst, u16 imm) {
        emit_u8(buf_, 0x66);
        if (needs_rex_ext(idx(dst))) emit_rex(buf_, false, false, false, true);
        emit_u8(buf_, 0xB8 | reg_lo3(idx(dst)));
        emit_u16(buf_, imm);
    }
    void mov(Reg16 dst, const Mem& src) {
        emit_u8(buf_, 0x66);
        emit_rex_prefix_for_mem(src, false);
        emit_u8(buf_, 0x8B);
        emit_mem_operand(buf_, idx(dst), src);
    }
    void mov(const Mem& dst, Reg16 src) {
        emit_u8(buf_, 0x66);
        emit_rex_prefix_for_mem(dst, false);
        emit_u8(buf_, 0x89);
        emit_mem_operand(buf_, idx(src), dst);
    }

    // --- 8-bit ---
    void mov(Reg8 dst, Reg8 src) {
        bool need_rex = needs_rex_ext(idx(src)) || needs_rex_ext(idx(dst));
        if (need_rex) emit_rex(buf_, false, needs_rex_ext(idx(src)), false, needs_rex_ext(idx(dst)), true);
        emit_u8(buf_, 0x88);
        emit_u8(buf_, modrm(3, idx(src), idx(dst)));
    }
    void mov(Reg8 dst, u8 imm) {
        bool need_rex = needs_rex_ext(idx(dst));
        if (need_rex) emit_rex(buf_, false, false, false, true);
        emit_u8(buf_, 0xB0 | reg_lo3(idx(dst)));
        emit_u8(buf_, imm);
    }
    void mov(Reg8 dst, const Mem& src) {
        bool need_rex = needs_rex_ext(idx(dst));
        emit_rex_prefix_for_mem(src, false, need_rex, true);
        emit_u8(buf_, 0x8A);
        emit_mem_operand(buf_, idx(dst), src);
    }
    void mov(const Mem& dst, Reg8 src) {
        bool need_rex = needs_rex_ext(idx(src));
        emit_rex_prefix_for_mem(dst, false, need_rex, true);
        emit_u8(buf_, 0x88);
        emit_mem_operand(buf_, idx(src), dst);
    }
    void mov(const Mem& dst, u8 imm) {
        emit_mem_imm8(0xC6, 0, dst, imm);
    }

    // ════════════════════════════════════════════════════════════════════
    //  MOVSX / MOVZX
    // ════════════════════════════════════════════════════════════════════
    void movsx(Reg64 dst, Reg32 src) { // sign-extend 32→64
        emit_rex(buf_,true,needs_rex_ext(idx(dst)),false,needs_rex_ext(idx(src)));
        emit_u8(buf_,0x63);
        emit_u8(buf_,modrm(3,idx(dst),idx(src)));
    }
    void movsx(Reg64 dst, Reg16 src) {
        emit_rex(buf_,true,needs_rex_ext(idx(dst)),false,needs_rex_ext(idx(src)));
        emit_u8(buf_,0x0F); emit_u8(buf_,0xBF);
        emit_u8(buf_,modrm(3,idx(dst),idx(src)));
    }
    void movsx(Reg64 dst, Reg8 src) {
        emit_rex(buf_,true,needs_rex_ext(idx(dst)),false,needs_rex_ext(idx(src)),true);
        emit_u8(buf_,0x0F); emit_u8(buf_,0xBE);
        emit_u8(buf_,modrm(3,idx(dst),idx(src)));
    }
    void movsx(Reg32 dst, Reg16 src) {
        bool rex = needs_rex_ext(idx(dst))||needs_rex_ext(idx(src));
        if(rex) emit_rex(buf_,false,needs_rex_ext(idx(dst)),false,needs_rex_ext(idx(src)));
        emit_u8(buf_,0x0F); emit_u8(buf_,0xBF);
        emit_u8(buf_,modrm(3,idx(dst),idx(src)));
    }
    void movsx(Reg32 dst, Reg8 src) {
        bool rex = needs_rex_ext(idx(dst))||needs_rex_ext(idx(src));
        if(rex) emit_rex(buf_,false,needs_rex_ext(idx(dst)),false,needs_rex_ext(idx(src)),true);
        emit_u8(buf_,0x0F); emit_u8(buf_,0xBE);
        emit_u8(buf_,modrm(3,idx(dst),idx(src)));
    }
    void movzx(Reg64 dst, Reg16 src) {
        emit_rex(buf_,true,needs_rex_ext(idx(dst)),false,needs_rex_ext(idx(src)));
        emit_u8(buf_,0x0F); emit_u8(buf_,0xB7);
        emit_u8(buf_,modrm(3,idx(dst),idx(src)));
    }
    void movzx(Reg64 dst, Reg8 src) {
        emit_rex(buf_,true,needs_rex_ext(idx(dst)),false,needs_rex_ext(idx(src)),true);
        emit_u8(buf_,0x0F); emit_u8(buf_,0xB6);
        emit_u8(buf_,modrm(3,idx(dst),idx(src)));
    }
    void movzx(Reg32 dst, Reg16 src) {
        bool rex = needs_rex_ext(idx(dst))||needs_rex_ext(idx(src));
        if(rex) emit_rex(buf_,false,needs_rex_ext(idx(dst)),false,needs_rex_ext(idx(src)));
        emit_u8(buf_,0x0F); emit_u8(buf_,0xB7);
        emit_u8(buf_,modrm(3,idx(dst),idx(src)));
    }
    void movzx(Reg32 dst, Reg8 src) {
        bool rex = needs_rex_ext(idx(dst))||needs_rex_ext(idx(src));
        if(rex) emit_rex(buf_,false,needs_rex_ext(idx(dst)),false,needs_rex_ext(idx(src)),true);
        emit_u8(buf_,0x0F); emit_u8(buf_,0xB6);
        emit_u8(buf_,modrm(3,idx(dst),idx(src)));
    }

    // ════════════════════════════════════════════════════════════════════
    //  LEA
    // ════════════════════════════════════════════════════════════════════
    void lea(Reg64 dst, const Mem& src) {
        u8 ri = idx(dst);
        usize rx = buf_.size(); buf_.push_back(0);
        emit_u8(buf_, 0x8D);
        auto ri_ = emit_mem_operand(buf_, ri, src);
        buf_[rx] = rex_byte(true, ri_.R || needs_rex_ext(ri), ri_.X, ri_.B);
    }
    void lea(Reg32 dst, const Mem& src) {
        u8 ri = idx(dst);
        usize rx = buf_.size(); buf_.push_back(0);
        emit_u8(buf_, 0x8D);
        auto ri_ = emit_mem_operand(buf_, ri, src);
        bool need = ri_.R || ri_.X || ri_.B || needs_rex_ext(ri);
        if (need) buf_[rx] = rex_byte(false, ri_.R || needs_rex_ext(ri), ri_.X, ri_.B);
        else      buf_.erase(buf_.begin() + rx);
    }

    // ════════════════════════════════════════════════════════════════════
    //  ADD / SUB / AND / OR / XOR / CMP / ADC / SBB
    // ════════════════════════════════════════════════════════════════════
#define MCE_ARITH(name, opc_rr_src, opc_rr_dst, opc_rm, opc_mr, opc_imm_ext, opc_imm8_ext) \
    void name(Reg64 dst, Reg64 src) { \
        emit_rex(buf_,true,needs_rex_ext(idx(src)),false,needs_rex_ext(idx(dst))); \
        emit_u8(buf_, opc_rr_src); \
        emit_u8(buf_, modrm(3,idx(src),idx(dst))); \
    } \
    void name(Reg32 dst, Reg32 src) { \
        bool rex=needs_rex_ext(idx(src))||needs_rex_ext(idx(dst)); \
        if(rex) emit_rex(buf_,false,needs_rex_ext(idx(src)),false,needs_rex_ext(idx(dst))); \
        emit_u8(buf_, opc_rr_src); \
        emit_u8(buf_, modrm(3,idx(src),idx(dst))); \
    } \
    void name(Reg64 dst, i32 imm) { \
        emit_rex(buf_,true,false,false,needs_rex_ext(idx(dst))); \
        if(fits_i8(imm)){emit_u8(buf_,0x83);emit_u8(buf_,modrm(3,opc_imm8_ext,idx(dst)));emit_i8(buf_,(i8)imm);} \
        else             {emit_u8(buf_,0x81);emit_u8(buf_,modrm(3,opc_imm_ext,idx(dst)));emit_i32(buf_,imm);} \
    } \
    void name(Reg32 dst, i32 imm) { \
        bool rex=needs_rex_ext(idx(dst)); if(rex) emit_rex(buf_,false,false,false,true); \
        if(fits_i8(imm)){emit_u8(buf_,0x83);emit_u8(buf_,modrm(3,opc_imm8_ext,idx(dst)));emit_i8(buf_,(i8)imm);} \
        else             {emit_u8(buf_,0x81);emit_u8(buf_,modrm(3,opc_imm_ext,idx(dst)));emit_i32(buf_,imm);} \
    } \
    void name(Reg64 dst, const Mem& src) { emit_rr_mem(opc_rr_dst, idx(dst), src, true);  } \
    void name(const Mem& dst, Reg64 src) { emit_rr_mem(opc_mr, idx(src), dst, true);       } \
    void name(const Mem& dst, i32 imm)   { emit_mem_imm32(0x81, opc_imm_ext, 0x83, opc_imm8_ext, dst, imm, true); }

    MCE_ARITH(add, 0x01, 0x03, 0x03, 0x01, 0, 0)
    MCE_ARITH(sub, 0x29, 0x2B, 0x2B, 0x29, 5, 5)
    MCE_ARITH(and_, 0x21, 0x23, 0x23, 0x21, 4, 4)
    MCE_ARITH(or_,  0x09, 0x0B, 0x0B, 0x09, 1, 1)
    MCE_ARITH(xor_, 0x31, 0x33, 0x33, 0x31, 6, 6)
    MCE_ARITH(cmp,  0x39, 0x3B, 0x3B, 0x39, 7, 7)
    MCE_ARITH(adc,  0x11, 0x13, 0x13, 0x11, 2, 2)
    MCE_ARITH(sbb,  0x19, 0x1B, 0x1B, 0x19, 3, 3)
#undef MCE_ARITH

    // ── 8-bit arith ──
    void add(Reg8 dst, u8 imm) {
        if (dst == Reg8::AL) { emit_u8(buf_, 0x04); emit_u8(buf_, imm); }
        else { emit_rex_prefix_for_reg8(dst); emit_u8(buf_, 0x80); emit_u8(buf_, modrm(3, 0, idx(dst))); emit_u8(buf_, imm); }
    }
    void xor_(Reg8 dst, Reg8 src) {
        bool rex = needs_rex_ext(idx(src)) || needs_rex_ext(idx(dst)) || (u8)dst >= 36 || (u8)src >= 36;
        if (rex) emit_rex(buf_, false, needs_rex_ext(idx(src)), false, needs_rex_ext(idx(dst)), true);
        emit_u8(buf_, 0x30); emit_u8(buf_, modrm(3, idx(src), idx(dst)));
    }
    void cmp(Reg8 dst, u8 imm) {
        if (dst == Reg8::AL) { emit_u8(buf_, 0x3C); emit_u8(buf_, imm); }
        else { emit_rex_prefix_for_reg8(dst); emit_u8(buf_, 0x80); emit_u8(buf_, modrm(3, 7, idx(dst))); emit_u8(buf_, imm); }
    }

    // TEST
    void test(Reg64 a, Reg64 b) {
        emit_rex(buf_,true,needs_rex_ext(idx(b)),false,needs_rex_ext(idx(a)));
        emit_u8(buf_,0x85); emit_u8(buf_,modrm(3,idx(b),idx(a)));
    }
    void test(Reg32 a, Reg32 b) {
        bool rex=needs_rex_ext(idx(b))||needs_rex_ext(idx(a));
        if(rex) emit_rex(buf_,false,needs_rex_ext(idx(b)),false,needs_rex_ext(idx(a)));
        emit_u8(buf_,0x85); emit_u8(buf_,modrm(3,idx(b),idx(a)));
    }
    void test(Reg64 r, i32 imm) {
        emit_rex(buf_,true,false,false,needs_rex_ext(idx(r)));
        emit_u8(buf_,0xF7); emit_u8(buf_,modrm(3,0,idx(r))); emit_i32(buf_,imm);
    }
    void test(Reg32 r, i32 imm) {
        bool rex=needs_rex_ext(idx(r)); if(rex) emit_rex(buf_,false,false,false,true);
        emit_u8(buf_,0xF7); emit_u8(buf_,modrm(3,0,idx(r))); emit_i32(buf_,imm);
    }

    // ════════════════════════════════════════════════════════════════════
    //  Unary: NOT / NEG / INC / DEC / MUL / IMUL / DIV / IDIV
    // ════════════════════════════════════════════════════════════════════
    void not_(Reg64 r)  { emit_unary64(0xF7, 2, r); }
    void neg (Reg64 r)  { emit_unary64(0xF7, 3, r); }
    void inc (Reg64 r)  { emit_unary64(0xFF, 0, r); }
    void dec (Reg64 r)  { emit_unary64(0xFF, 1, r); }
    void not_(Reg32 r)  { emit_unary32(0xF7, 2, r); }
    void neg (Reg32 r)  { emit_unary32(0xF7, 3, r); }
    void inc (Reg32 r)  { emit_unary32(0xFF, 0, r); }
    void dec (Reg32 r)  { emit_unary32(0xFF, 1, r); }

    void mul (Reg64 r)  { emit_unary64(0xF7, 4, r); } // RDX:RAX = RAX * r
    void imul(Reg64 r)  { emit_unary64(0xF7, 5, r); }
    void div_(Reg64 r)  { emit_unary64(0xF7, 6, r); } // RAX = RDX:RAX / r
    void idiv(Reg64 r)  { emit_unary64(0xF7, 7, r); }
    void mul (Reg32 r)  { emit_unary32(0xF7, 4, r); }
    void imul(Reg32 r)  { emit_unary32(0xF7, 5, r); }
    void div_(Reg32 r)  { emit_unary32(0xF7, 6, r); }
    void idiv(Reg32 r)  { emit_unary32(0xF7, 7, r); }

    // IMUL 2-operand: dst *= src
    void imul(Reg64 dst, Reg64 src) {
        emit_rex(buf_,true,needs_rex_ext(idx(dst)),false,needs_rex_ext(idx(src)));
        emit_u8(buf_,0x0F); emit_u8(buf_,0xAF);
        emit_u8(buf_,modrm(3,idx(dst),idx(src)));
    }
    // IMUL 3-operand: dst = src * imm
    void imul(Reg64 dst, Reg64 src, i32 imm) {
        emit_rex(buf_,true,needs_rex_ext(idx(dst)),false,needs_rex_ext(idx(src)));
        if(fits_i8(imm)) {
            emit_u8(buf_,0x6B); emit_u8(buf_,modrm(3,idx(dst),idx(src))); emit_i8(buf_,(i8)imm);
        } else {
            emit_u8(buf_,0x69); emit_u8(buf_,modrm(3,idx(dst),idx(src))); emit_i32(buf_,imm);
        }
    }

    // CDQ / CQO (sign-extend)
    void cdq() { emit_u8(buf_,0x99); }      // EAX→EDX:EAX
    void cqo() { emit_rex(buf_,true,false,false,false); emit_u8(buf_,0x99); } // RAX→RDX:RAX
    void cbw() { emit_u8(buf_,0x66); emit_u8(buf_,0x98); }
    void cwde(){ emit_u8(buf_,0x98); }

    // ════════════════════════════════════════════════════════════════════
    //  Shifts: SHL / SHR / SAR / ROL / ROR / RCL / RCR
    // ════════════════════════════════════════════════════════════════════
#define MCE_SHIFT(name, ext) \
    void name(Reg64 r, u8 imm) { emit_shift64(ext, r, imm); } \
    void name(Reg32 r, u8 imm) { emit_shift32(ext, r, imm); } \
    void name##_cl(Reg64 r) { emit_shift64_cl(ext, r); } \
    void name##_cl(Reg32 r) { emit_shift32_cl(ext, r); }

    MCE_SHIFT(shl, 4)
    MCE_SHIFT(shr, 5)
    MCE_SHIFT(sar, 7)
    MCE_SHIFT(rol, 0)
    MCE_SHIFT(ror, 1)
    MCE_SHIFT(rcl, 2)
    MCE_SHIFT(rcr, 3)
#undef MCE_SHIFT

    // ════════════════════════════════════════════════════════════════════
    //  Bit manipulation: BT / BTS / BTR / BTC / BSF / BSR / POPCNT / LZCNT / TZCNT
    // ════════════════════════════════════════════════════════════════════
    void bt (Reg64 r, u8 bit) { emit_bit_imm(0xBA, 4, r, bit); }
    void bts(Reg64 r, u8 bit) { emit_bit_imm(0xBA, 5, r, bit); }
    void btr(Reg64 r, u8 bit) { emit_bit_imm(0xBA, 6, r, bit); }
    void btc(Reg64 r, u8 bit) { emit_bit_imm(0xBA, 7, r, bit); }
    void bt (Reg64 r, Reg64 bit) { emit_bit_reg(0xA3, r, bit); }
    void bts(Reg64 r, Reg64 bit) { emit_bit_reg(0xAB, r, bit); }
    void btr(Reg64 r, Reg64 bit) { emit_bit_reg(0xB3, r, bit); }
    void btc(Reg64 r, Reg64 bit) { emit_bit_reg(0xBB, r, bit); }

    void bsf(Reg64 dst, Reg64 src) {
        emit_rex(buf_,true,needs_rex_ext(idx(dst)),false,needs_rex_ext(idx(src)));
        emit_u8(buf_,0x0F); emit_u8(buf_,0xBC);
        emit_u8(buf_,modrm(3,idx(dst),idx(src)));
    }
    void bsr(Reg64 dst, Reg64 src) {
        emit_rex(buf_,true,needs_rex_ext(idx(dst)),false,needs_rex_ext(idx(src)));
        emit_u8(buf_,0x0F); emit_u8(buf_,0xBD);
        emit_u8(buf_,modrm(3,idx(dst),idx(src)));
    }
    void popcnt(Reg64 dst, Reg64 src) {
        emit_u8(buf_,0xF3);
        emit_rex(buf_,true,needs_rex_ext(idx(dst)),false,needs_rex_ext(idx(src)));
        emit_u8(buf_,0x0F); emit_u8(buf_,0xB8);
        emit_u8(buf_,modrm(3,idx(dst),idx(src)));
    }
    void lzcnt(Reg64 dst, Reg64 src) {
        emit_u8(buf_,0xF3);
        emit_rex(buf_,true,needs_rex_ext(idx(dst)),false,needs_rex_ext(idx(src)));
        emit_u8(buf_,0x0F); emit_u8(buf_,0xBD);
        emit_u8(buf_,modrm(3,idx(dst),idx(src)));
    }
    void tzcnt(Reg64 dst, Reg64 src) {
        emit_u8(buf_,0xF3);
        emit_rex(buf_,true,needs_rex_ext(idx(dst)),false,needs_rex_ext(idx(src)));
        emit_u8(buf_,0x0F); emit_u8(buf_,0xBC);
        emit_u8(buf_,modrm(3,idx(dst),idx(src)));
    }

    // ════════════════════════════════════════════════════════════════════
    //  JMP / CALL
    // ════════════════════════════════════════════════════════════════════
    void jmp(Label lbl) {
        emit_u8(buf_, 0xE9);
        emit_rel32(lbl);
    }
    void jmp_short(Label lbl) {
        emit_u8(buf_, 0xEB);
        emit_rel8(lbl);
    }
    void jmp(Reg64 r) { // JMP r/m64
        if (needs_rex_ext(idx(r))) emit_rex(buf_,false,false,false,true);
        emit_u8(buf_,0xFF); emit_u8(buf_,modrm(3,4,idx(r)));
    }
    void jmp(const Mem& m) { // JMP r/m64
        emit_rex_prefix_for_mem(m, false);
        emit_u8(buf_,0xFF);
        emit_mem_operand(buf_, 4, m);
    }
    void call(Label lbl) {
        emit_u8(buf_, 0xE8);
        emit_rel32(lbl);
    }
    void call(Reg64 r) {
        if (needs_rex_ext(idx(r))) emit_rex(buf_,false,false,false,true);
        emit_u8(buf_,0xFF); emit_u8(buf_,modrm(3,2,idx(r)));
    }
    void call(const Mem& m) {
        emit_rex_prefix_for_mem(m, false);
        emit_u8(buf_,0xFF); emit_mem_operand(buf_,2,m);
    }

    // ════════════════════════════════════════════════════════════════════
    //  Jcc – conditional jumps
    // ════════════════════════════════════════════════════════════════════
    void jcc(Cond c, Label lbl) {
        emit_u8(buf_, 0x0F);
        emit_u8(buf_, 0x80 | (u8)c);
        emit_rel32(lbl);
    }
    void jcc_short(Cond c, Label lbl) {
        emit_u8(buf_, 0x70 | (u8)c);
        emit_rel8(lbl);
    }
    // Named aliases
    void jo   (Label l){jcc(Cond::O,  l);}  void jno (Label l){jcc(Cond::NO, l);}
    void jb   (Label l){jcc(Cond::B,  l);}  void jnb (Label l){jcc(Cond::NB, l);}
    void je   (Label l){jcc(Cond::E,  l);}  void jne (Label l){jcc(Cond::NE, l);}
    void jbe  (Label l){jcc(Cond::BE, l);}  void ja  (Label l){jcc(Cond::A,  l);}
    void js   (Label l){jcc(Cond::S,  l);}  void jns (Label l){jcc(Cond::NS, l);}
    void jp   (Label l){jcc(Cond::P,  l);}  void jnp (Label l){jcc(Cond::NP, l);}
    void jl   (Label l){jcc(Cond::L,  l);}  void jge (Label l){jcc(Cond::GE, l);}
    void jle  (Label l){jcc(Cond::LE, l);}  void jg  (Label l){jcc(Cond::G,  l);}
    void jz   (Label l){je(l);}              void jnz (Label l){jne(l);}
    void jc   (Label l){jb(l);}              void jnc (Label l){jnb(l);}
    void jae  (Label l){jnb(l);}             void jnae(Label l){jb(l);}
    void jpe  (Label l){jp(l);}              void jpo (Label l){jnp(l);}

    // ════════════════════════════════════════════════════════════════════
    //  SETcc / CMOVcc
    // ════════════════════════════════════════════════════════════════════
    void setcc(Cond c, Reg8 dst) {
        bool rex = needs_rex_ext(idx(dst)) || (u8)dst >= 36;
        if (rex) emit_rex(buf_,false,false,false,needs_rex_ext(idx(dst)),true);
        emit_u8(buf_,0x0F); emit_u8(buf_,0x90|(u8)c);
        emit_u8(buf_,modrm(3,0,idx(dst)));
    }
    void cmovcc(Cond c, Reg64 dst, Reg64 src) {
        emit_rex(buf_,true,needs_rex_ext(idx(dst)),false,needs_rex_ext(idx(src)));
        emit_u8(buf_,0x0F); emit_u8(buf_,0x40|(u8)c);
        emit_u8(buf_,modrm(3,idx(dst),idx(src)));
    }
    void cmovcc(Cond c, Reg32 dst, Reg32 src) {
        bool rex=needs_rex_ext(idx(dst))||needs_rex_ext(idx(src));
        if(rex) emit_rex(buf_,false,needs_rex_ext(idx(dst)),false,needs_rex_ext(idx(src)));
        emit_u8(buf_,0x0F); emit_u8(buf_,0x40|(u8)c);
        emit_u8(buf_,modrm(3,idx(dst),idx(src)));
    }

    // ════════════════════════════════════════════════════════════════════
    //  XCHG / BSWAP / XADD / CMPXCHG
    // ════════════════════════════════════════════════════════════════════
    void xchg(Reg64 a, Reg64 b) {
        if (a == Reg64::RAX) { // short form
            if (needs_rex_ext(idx(b))) emit_rex(buf_,true,false,false,true);
            else emit_rex(buf_,true,false,false,false);
            emit_u8(buf_,0x90|reg_lo3(idx(b))); return;
        }
        emit_rex(buf_,true,needs_rex_ext(idx(b)),false,needs_rex_ext(idx(a)));
        emit_u8(buf_,0x87); emit_u8(buf_,modrm(3,idx(b),idx(a)));
    }
    void bswap(Reg64 r) {
        emit_rex(buf_,true,false,false,needs_rex_ext(idx(r)));
        emit_u8(buf_,0x0F); emit_u8(buf_,0xC8|reg_lo3(idx(r)));
    }
    void bswap(Reg32 r) {
        if(needs_rex_ext(idx(r))) emit_rex(buf_,false,false,false,true);
        emit_u8(buf_,0x0F); emit_u8(buf_,0xC8|reg_lo3(idx(r)));
    }
    void xadd(Reg64 dst, Reg64 src) {
        emit_rex(buf_,true,needs_rex_ext(idx(src)),false,needs_rex_ext(idx(dst)));
        emit_u8(buf_,0x0F); emit_u8(buf_,0xC1);
        emit_u8(buf_,modrm(3,idx(src),idx(dst)));
    }
    void cmpxchg(Reg64 dst, Reg64 src) {
        emit_rex(buf_,true,needs_rex_ext(idx(src)),false,needs_rex_ext(idx(dst)));
        emit_u8(buf_,0x0F); emit_u8(buf_,0xB1);
        emit_u8(buf_,modrm(3,idx(src),idx(dst)));
    }

    // ════════════════════════════════════════════════════════════════════
    //  SSE2 – MOVD/MOVQ, arithmetic (scalar & packed double/single)
    // ════════════════════════════════════════════════════════════════════

    // MOVD / MOVQ xmm, r/m
    void movd(RegXMM dst, Reg32 src) {
        emit_u8(buf_,0x66);
        if(needs_rex_ext(idx(dst))||needs_rex_ext(idx(src)))
            emit_rex(buf_,false,needs_rex_ext(idx(dst)),false,needs_rex_ext(idx(src)));
        emit_u8(buf_,0x0F); emit_u8(buf_,0x6E);
        emit_u8(buf_,modrm(3,idx(dst),idx(src)));
    }
    void movq(RegXMM dst, Reg64 src) {
        emit_u8(buf_,0x66);
        emit_rex(buf_,true,needs_rex_ext(idx(dst)),false,needs_rex_ext(idx(src)));
        emit_u8(buf_,0x0F); emit_u8(buf_,0x6E);
        emit_u8(buf_,modrm(3,idx(dst),idx(src)));
    }
    void movd(Reg32 dst, RegXMM src) {
        emit_u8(buf_,0x66);
        if(needs_rex_ext(idx(src))||needs_rex_ext(idx(dst)))
            emit_rex(buf_,false,needs_rex_ext(idx(src)),false,needs_rex_ext(idx(dst)));
        emit_u8(buf_,0x0F); emit_u8(buf_,0x7E);
        emit_u8(buf_,modrm(3,idx(src),idx(dst)));
    }
    void movq(Reg64 dst, RegXMM src) {
        emit_u8(buf_,0x66);
        emit_rex(buf_,true,needs_rex_ext(idx(src)),false,needs_rex_ext(idx(dst)));
        emit_u8(buf_,0x0F); emit_u8(buf_,0x7E);
        emit_u8(buf_,modrm(3,idx(src),idx(dst)));
    }
    void movss(RegXMM dst, RegXMM src) { sse_rr(0xF3,0x10,dst,src); }
    void movsd(RegXMM dst, RegXMM src) { sse_rr(0xF2,0x10,dst,src); }
    void movaps(RegXMM dst, RegXMM src) {
        // 0F 28 /r  (no mandatory prefix)
        if (needs_rex_ext(idx(dst)) || needs_rex_ext(idx(src)))
            emit_rex(buf_, false, needs_rex_ext(idx(dst)), false, needs_rex_ext(idx(src)));
        emit_u8(buf_, 0x0F); emit_u8(buf_, 0x28);
        emit_u8(buf_, modrm(3, idx(dst), idx(src)));
    }

    // Scalar SSE2 arithmetic
#define MCE_SSE_SCALAR_F64(fn, opc) \
    void fn(RegXMM d, RegXMM s) { sse_rr(0xF2, opc, d, s); } \
    void fn(RegXMM d, const Mem& s) { \
        emit_u8(buf_, 0xF2); \
        emit_rex_prefix_for_mem(s, false, needs_rex_ext(idx(d))); \
        emit_u8(buf_, 0x0F); emit_u8(buf_, opc); \
        emit_mem_operand(buf_, idx(d), s); \
    }

#define MCE_SSE_SCALAR_F32(fn, opc) \
    void fn(RegXMM d, RegXMM s) { sse_rr(0xF3, opc, d, s); } \
    void fn(RegXMM d, const Mem& s) { \
        emit_u8(buf_, 0xF3); \
        emit_rex_prefix_for_mem(s, false, needs_rex_ext(idx(d))); \
        emit_u8(buf_, 0x0F); emit_u8(buf_, opc); \
        emit_mem_operand(buf_, idx(d), s); \
    }
    MCE_SSE_SCALAR_F64(addsd,  0x58) MCE_SSE_SCALAR_F64(subsd,  0x5C)
    MCE_SSE_SCALAR_F64(mulsd,  0x59) MCE_SSE_SCALAR_F64(divsd,  0x5E)
    MCE_SSE_SCALAR_F64(sqrtsd, 0x51) MCE_SSE_SCALAR_F64(minsd,  0x5D)
    MCE_SSE_SCALAR_F64(maxsd,  0x5F) MCE_SSE_SCALAR_F64(comisd, 0x2F)
    MCE_SSE_SCALAR_F64(ucomisd,0x2E) MCE_SSE_SCALAR_F64(andpd,  0x54)
    MCE_SSE_SCALAR_F32(addss,  0x58) MCE_SSE_SCALAR_F32(subss,  0x5C)
    MCE_SSE_SCALAR_F32(mulss,  0x59) MCE_SSE_SCALAR_F32(divss,  0x5E)
    MCE_SSE_SCALAR_F32(sqrtss, 0x51) MCE_SSE_SCALAR_F32(minss,  0x5D)
    MCE_SSE_SCALAR_F32(maxss,  0x5F) MCE_SSE_SCALAR_F32(comiss, 0x2F)
    MCE_SSE_SCALAR_F32(ucomiss,0x2E)
#undef MCE_SSE_SCALAR_F64
#undef MCE_SSE_SCALAR_F32

    // Conversions
    void cvtsi2sd(RegXMM dst, Reg64 src){
        emit_u8(buf_,0xF2);
        emit_rex(buf_,true,needs_rex_ext(idx(dst)),false,needs_rex_ext(idx(src)));
        emit_u8(buf_,0x0F); emit_u8(buf_,0x2A);
        emit_u8(buf_,modrm(3,idx(dst),idx(src)));
    }
    void cvtsi2ss(RegXMM dst, Reg64 src){
        emit_u8(buf_,0xF3);
        emit_rex(buf_,true,needs_rex_ext(idx(dst)),false,needs_rex_ext(idx(src)));
        emit_u8(buf_,0x0F); emit_u8(buf_,0x2A);
        emit_u8(buf_,modrm(3,idx(dst),idx(src)));
    }
    void cvtsd2si(Reg64 dst, RegXMM src){
        emit_u8(buf_,0xF2);
        emit_rex(buf_,true,needs_rex_ext(idx(dst)),false,needs_rex_ext(idx(src)));
        emit_u8(buf_,0x0F); emit_u8(buf_,0x2D);
        emit_u8(buf_,modrm(3,idx(dst),idx(src)));
    }
    void cvttsd2si(Reg64 dst, RegXMM src){
        emit_u8(buf_,0xF2);
        emit_rex(buf_,true,needs_rex_ext(idx(dst)),false,needs_rex_ext(idx(src)));
        emit_u8(buf_,0x0F); emit_u8(buf_,0x2C);
        emit_u8(buf_,modrm(3,idx(dst),idx(src)));
    }
    void cvtsd2ss(RegXMM dst, RegXMM src){sse_rr(0xF2,0x5A,dst,src);}
    void cvtss2sd(RegXMM dst, RegXMM src){sse_rr(0xF3,0x5A,dst,src);}

    // ════════════════════════════════════════════════════════════════════
    //  Stack frame helpers
    // ════════════════════════════════════════════════════════════════════
    void prolog(u32 locals = 0) {
        push(Reg64::RBP);
        mov(Reg64::RBP, Reg64::RSP);
        if (locals) sub(Reg64::RSP, (i32)locals);
    }
    void epilog() {
        mov(Reg64::RSP, Reg64::RBP);
        pop(Reg64::RBP);
        ret();
    }

    // ════════════════════════════════════════════════════════════════════
    //  Windows x64 ABI: shadow space + align
    // ════════════════════════════════════════════════════════════════════
    void win64_prolog(u32 locals = 0) {
        push(Reg64::RBP);
        mov(Reg64::RBP, Reg64::RSP);
        // Align stack + shadow space (32 bytes) + locals
        u32 frame = 32 + locals;
        frame = (frame + 15) & ~15u; // 16-byte align
        sub(Reg64::RSP, (i32)frame);
    }
    void win64_epilog() {
        mov(Reg64::RSP, Reg64::RBP);
        pop(Reg64::RBP);
        ret();
    }

    // ════════════════════════════════════════════════════════════════════
    //  XORPS zero helper — fast float register zero
    // ════════════════════════════════════════════════════════════════════
    void xorps(RegXMM r, RegXMM s) {
        if(needs_rex_ext(idx(r))||needs_rex_ext(idx(s)))
            emit_rex(buf_,false,needs_rex_ext(idx(r)),false,needs_rex_ext(idx(s)));
        emit_u8(buf_,0x0F); emit_u8(buf_,0x57);
        emit_u8(buf_,modrm(3,idx(r),idx(s)));
    }
    void xorpd(RegXMM r, RegXMM s) { sse_rr_66(0x57,r,s); }
    void pxor (RegXMM r, RegXMM s) { sse_rr_66(0xEF,r,s); }

    // ════════════════════════════════════════════════════════════════════
    //  Inline helpers for common patterns
    // ════════════════════════════════════════════════════════════════════
    // Zero a register
    void zero(Reg64 r) { xor_(Reg32( (u8)r & 15u ), Reg32( (u8)r & 15u )); } // xor r32,r32
    void zero(Reg32 r) { xor_(r, r); }
    void zero(RegXMM r){ xorps(r, r); }

    // ════════════════════════════════════════════════════════════════════
    //  LODSB/LODSQ/STOSB/STOSQ/MOVSB/MOVSQ REP prefixed
    // ════════════════════════════════════════════════════════════════════
    void lodsb()  { emit_u8(buf_,0xAC); }
    void lodsq()  { emit_rex(buf_,true,false,false,false); emit_u8(buf_,0xAD); }
    void stosb()  { emit_u8(buf_,0xAA); }
    void stosq()  { emit_rex(buf_,true,false,false,false); emit_u8(buf_,0xAB); }
    void movsb()  { emit_u8(buf_,0xA4); }
    void movsq()  { emit_rex(buf_,true,false,false,false); emit_u8(buf_,0xA5); }
    void rep_stosb(){ emit_u8(buf_,0xF3); stosb(); }
    void rep_stosq(){ emit_u8(buf_,0xF3); stosq(); }
    void rep_movsb(){ emit_u8(buf_,0xF3); movsb(); }
    void rep_movsq(){ emit_u8(buf_,0xF3); movsq(); }
    void scasb()  { emit_u8(buf_,0xAE); }
    void repe_scasb(){ emit_u8(buf_,0xF3); scasb(); }
    void repne_scasb(){ emit_u8(buf_,0xF2); scasb(); }

    // ════════════════════════════════════════════════════════════════════
    //  RDTSC / RDTSCP / RDRAND
    // ════════════════════════════════════════════════════════════════════
    void rdtsc()   { emit_u8(buf_,0x0F); emit_u8(buf_,0x31); }
    void rdtscp()  { emit_u8(buf_,0x0F); emit_u8(buf_,0x01); emit_u8(buf_,0xF9); }
    void rdrand(Reg64 r){
        emit_rex(buf_,true,false,false,needs_rex_ext(idx(r)));
        emit_u8(buf_,0x0F); emit_u8(buf_,0xC7);
        emit_u8(buf_,modrm(3,6,idx(r)));
    }

    // ════════════════════════════════════════════════════════════════════
    //  LOCK prefix
    // ════════════════════════════════════════════════════════════════════
    EmitterX64& lock() { emit_u8(buf_,0xF0); return *this; }

    // ════════════════════════════════════════════════════════════════════
    //  Align code to boundary
    // ════════════════════════════════════════════════════════════════════
    void align(u32 boundary) {
        usize rem = buf_.size() % boundary;
        if (rem) nop((int)(boundary - rem));
    }

private:
    // ─── Internal state ──────────────────────────────────────────────────
    byte_vec buf_;
    struct LabelInfo { bool bound; u32 offset; };
    std::vector<LabelInfo> labels_;

    struct Fixup {
        u32  label_id;
        u32  fix_offset;  // position of the 4-byte slot in buf_
        u32  instr_end;   // offset after the instruction (for rel calc)
        bool is_8bit;     // true → 1-byte rel8 fixup
        bool patched;
    };
    std::vector<Fixup> fixups_;

    struct RdataSection { byte_vec data; };

    byte_vec rdata_;
    byte_vec data_;

    struct ImpEntry { std::string dll, func; u32 hint; };
    std::vector<ImpEntry> imports_;

    // ─── Fixup helpers ───────────────────────────────────────────────────
    void emit_rel32(Label lbl) {
        u32 fix = (u32)buf_.size();
        emit_u32(buf_, 0); // placeholder
        u32 end = (u32)buf_.size();
        if (labels_[lbl.id].bound) {
            i32 rel = (i32)labels_[lbl.id].offset - (i32)end;
            patch_i32(buf_, fix, rel);
        } else {
            fixups_.push_back({lbl.id, fix, end, false, false});
        }
    }
    void emit_rel8(Label lbl) {
        u32 fix = (u32)buf_.size();
        emit_u8(buf_, 0); // placeholder
        u32 end = (u32)buf_.size();
        if (labels_[lbl.id].bound) {
            i32 rel = (i32)labels_[lbl.id].offset - (i32)end;
            if (!fits_i8(rel)) throw std::overflow_error("rel8 target out of range");
            buf_[fix] = (i8)rel;
        } else {
            fixups_.push_back({lbl.id, fix, end, true, false});
        }
    }
    void patch_fixup(Fixup& fx) {
        i32 rel = (i32)labels_[fx.label_id].offset - (i32)fx.instr_end;
        if (fx.is_8bit) {
            if (!fits_i8(rel)) throw std::overflow_error("rel8 target out of range");
            buf_[fx.fix_offset] = (u8)(i8)rel;
        } else {
            patch_i32(buf_, fx.fix_offset, rel);
        }
    }
    void resolve_all_fixups() {
        for (auto& fx : fixups_) {
            if (!fx.patched) {
                if (!labels_[fx.label_id].bound)
                    throw std::logic_error("Unbound label referenced in code");
                patch_fixup(fx);
                fx.patched = true;
            }
        }
    }

    // ─── Instruction helpers ─────────────────────────────────────────────
    void emit_unary64(u8 opc, u8 ext, Reg64 r) {
        emit_rex(buf_,true,false,false,needs_rex_ext(idx(r)));
        emit_u8(buf_,opc); emit_u8(buf_,modrm(3,ext,idx(r)));
    }
    void emit_unary32(u8 opc, u8 ext, Reg32 r) {
        if(needs_rex_ext(idx(r))) emit_rex(buf_,false,false,false,true);
        emit_u8(buf_,opc); emit_u8(buf_,modrm(3,ext,idx(r)));
    }
    void emit_shift64(u8 ext, Reg64 r, u8 imm) {
        emit_rex(buf_,true,false,false,needs_rex_ext(idx(r)));
        if(imm==1){emit_u8(buf_,0xD1);emit_u8(buf_,modrm(3,ext,idx(r)));}
        else       {emit_u8(buf_,0xC1);emit_u8(buf_,modrm(3,ext,idx(r)));emit_u8(buf_,imm);}
    }
    void emit_shift32(u8 ext, Reg32 r, u8 imm) {
        if(needs_rex_ext(idx(r))) emit_rex(buf_,false,false,false,true);
        if(imm==1){emit_u8(buf_,0xD1);emit_u8(buf_,modrm(3,ext,idx(r)));}
        else       {emit_u8(buf_,0xC1);emit_u8(buf_,modrm(3,ext,idx(r)));emit_u8(buf_,imm);}
    }
    void emit_shift64_cl(u8 ext, Reg64 r) {
        emit_rex(buf_,true,false,false,needs_rex_ext(idx(r)));
        emit_u8(buf_,0xD3); emit_u8(buf_,modrm(3,ext,idx(r)));
    }
    void emit_shift32_cl(u8 ext, Reg32 r) {
        if(needs_rex_ext(idx(r))) emit_rex(buf_,false,false,false,true);
        emit_u8(buf_,0xD3); emit_u8(buf_,modrm(3,ext,idx(r)));
    }
    void emit_bit_imm(u8 opc, u8 ext, Reg64 r, u8 bit) {
        emit_rex(buf_,true,false,false,needs_rex_ext(idx(r)));
        emit_u8(buf_,0x0F); emit_u8(buf_,opc);
        emit_u8(buf_,modrm(3,ext,idx(r))); emit_u8(buf_,bit);
    }
    void emit_bit_reg(u8 opc, Reg64 rm, Reg64 reg_) {
        emit_rex(buf_,true,needs_rex_ext(idx(reg_)),false,needs_rex_ext(idx(rm)));
        emit_u8(buf_,0x0F); emit_u8(buf_,opc);
        emit_u8(buf_,modrm(3,idx(reg_),idx(rm)));
    }
    // Emit: [optional REX] opc mem
    void emit_rr_mem(u8 opc, u8 ri, const Mem& m, bool W) {
        usize rx = buf_.size(); buf_.push_back(0);
        emit_u8(buf_,opc);
        auto ri_ = emit_mem_operand(buf_,ri,m);
        buf_[rx] = rex_byte(W, ri_.R||needs_rex_ext(ri), ri_.X, ri_.B);
    }
    void emit_mem_instr_no_rex_w(u8 opc, u8 ext, const Mem& m) {
        usize rx = buf_.size(); buf_.push_back(0);
        emit_u8(buf_,opc);
        auto ri_=emit_mem_operand(buf_,ext,m);
        bool need=ri_.R||ri_.X||ri_.B;
        if(need) buf_[rx]=rex_byte(false,ri_.R,ri_.X,ri_.B);
        else     buf_.erase(buf_.begin()+rx);
    }
    void emit_mem_imm32(u8 opc81, u8 ext, u8 opc83, u8 ext8, const Mem& m, i32 imm, bool W) {
        if(fits_i8(imm)) {
            usize rx=buf_.size(); buf_.push_back(0);
            emit_u8(buf_,opc83);
            auto ri_=emit_mem_operand(buf_,ext8,m);
            buf_[rx]=rex_byte(W,ri_.R,ri_.X,ri_.B);
            emit_i8(buf_,(i8)imm);
        } else {
            usize rx=buf_.size(); buf_.push_back(0);
            emit_u8(buf_,opc81);
            auto ri_=emit_mem_operand(buf_,ext,m);
            buf_[rx]=rex_byte(W,ri_.R,ri_.X,ri_.B);
            emit_i32(buf_,imm);
        }
    }
    void emit_mem_imm8(u8 opc, u8 ext, const Mem& m, u8 imm) {
        usize rx=buf_.size(); buf_.push_back(0);
        emit_u8(buf_,opc);
        auto ri_=emit_mem_operand(buf_,ext,m);
        bool need=ri_.R||ri_.X||ri_.B;
        if(need) buf_[rx]=rex_byte(false,ri_.R,ri_.X,ri_.B);
        else     buf_.erase(buf_.begin()+rx);
        emit_u8(buf_,imm);
    }
    void emit_rex_prefix_for_mem(const Mem& m, bool W, bool R = false, bool force = false) {
        bool B = m.has_base  && needs_rex_ext(idx(m.base));
        bool X = m.has_index && needs_rex_ext(idx(m.index));
        if (W || R || X || B || force)
            emit_rex(buf_, W, R, X, B, force);
    }
    void emit_rex_prefix_for_reg8(Reg8 r) {
        bool rex = needs_rex_ext(idx(r)) || (u8)r >= 36;
        if (rex) emit_rex(buf_, false, false, false, needs_rex_ext(idx(r)), true);
    }

    // SSE helpers
    void sse_rr(u8 prefix, u8 opc, RegXMM dst, RegXMM src, bool rexify=true) {
        if(prefix) emit_u8(buf_,prefix);
        if(rexify&&(needs_rex_ext(idx(dst))||needs_rex_ext(idx(src))))
            emit_rex(buf_,false,needs_rex_ext(idx(dst)),false,needs_rex_ext(idx(src)));
        emit_u8(buf_,0x0F); emit_u8(buf_,opc);
        emit_u8(buf_,modrm(3,idx(dst),idx(src)));
    }
    void sse_rr_66(u8 opc, RegXMM dst, RegXMM src) {
        emit_u8(buf_,0x66);
        if(needs_rex_ext(idx(dst))||needs_rex_ext(idx(src)))
            emit_rex(buf_,false,needs_rex_ext(idx(dst)),false,needs_rex_ext(idx(src)));
        emit_u8(buf_,0x0F); emit_u8(buf_,opc);
        emit_u8(buf_,modrm(3,idx(dst),idx(src)));
    }
};

} // namespace mce
