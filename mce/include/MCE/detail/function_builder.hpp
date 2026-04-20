#pragma once
#include "emitter_core.hpp"
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>

/*
 * FunctionBuilder – a higher-level wrapper over EmitterX64.
 *
 * Manages:
 *   - Prologue/epilogue generation (Windows x64 ABI)
 *   - Named local variables (RBP-based)
 *   - Named labels
 *   - Function call helpers (up to 4 args → Win64 ABI)
 *   - Return value via RAX / XMM0
 */

namespace mce {

// ─── Variable descriptor ────────────────────────────────────────────────────
struct LocalVar {
    i32  rbp_offset; // negative — [RBP - n]
    u8   size_bytes; // 1 / 2 / 4 / 8
};

class FunctionBuilder {
public:
    explicit FunctionBuilder(EmitterX64& e, u32 local_bytes = 128)
        : e_(e), local_bytes_(local_bytes)
    {
        // Round up to 16-byte alignment (Win64 ABI)
        local_bytes_ = (local_bytes_ + 15) & ~15u;
        entry_offset_ = e_.current_offset();
    }

    // ── Entry point offset (for PE .emit()) ────────────────────────────
    u32 entry_offset() const { return entry_offset_; }

    // ── Emit prologue (call at start of function) ───────────────────────
    void prologue() {
        e_.push(Reg64::RBP);
        e_.mov(Reg64::RBP, Reg64::RSP);
        // shadow space (32) + locals, 16-aligned
        u32 frame = 32 + local_bytes_;
        frame = (frame + 15) & ~15u;
        e_.sub(Reg64::RSP, (i32)frame);
        frame_size_ = frame;
    }

    // ── Emit epilogue + ret ─────────────────────────────────────────────
    void epilogue() {
        e_.mov(Reg64::RSP, Reg64::RBP);
        e_.pop(Reg64::RBP);
        e_.ret();
    }

    // ── Local variable allocation ────────────────────────────────────────
    // Allocate a named local variable; returns reference to its descriptor
    LocalVar& alloc(const std::string& name, u8 size = 8) {
        rbp_cur_ -= (i32)size;
        // align to size
        rbp_cur_ = (rbp_cur_ / (i32)size) * (i32)size;
        locals_[name] = {rbp_cur_, size};
        return locals_[name];
    }

    LocalVar& var(const std::string& name) {
        auto it = locals_.find(name);
        if (it == locals_.end()) throw std::runtime_error("Unknown local: " + name);
        return it->second;
    }

    // Convenience: get Mem operand for a local
    Mem local_mem(const std::string& name) {
        auto& v = var(name);
        switch (v.size_bytes) {
            case 1: return byte_ptr (Reg64::RBP, v.rbp_offset);
            case 2: return word_ptr (Reg64::RBP, v.rbp_offset);
            case 4: return dword_ptr(Reg64::RBP, v.rbp_offset);
            default: return qword_ptr(Reg64::RBP, v.rbp_offset);
        }
    }

    // ── Named labels ─────────────────────────────────────────────────────
    Label make_label(const std::string& name = "") {
        Label l = e_.make_label();
        if (!name.empty()) named_labels_[name] = l;
        return l;
    }
    void bind(Label l)                      { e_.bind(l); }
    void bind(const std::string& name)      { e_.bind(named_label(name)); }
    Label named_label(const std::string& n) {
        auto it = named_labels_.find(n);
        if (it == named_labels_.end()) throw std::runtime_error("Unknown label: "+n);
        return it->second;
    }

    // ── Win64 call helpers (up to 4 args) ────────────────────────────────
    // Integer args: RCX, RDX, R8, R9
    // Float   args: XMM0, XMM1, XMM2, XMM3
    void call_win64_int(Reg64 target,
                        std::initializer_list<i64> int_args = {}) {
        static const Reg64 iregs[] = {Reg64::RCX,Reg64::RDX,Reg64::R8,Reg64::R9};
        int i = 0;
        for (auto a : int_args) {
            if (i >= 4) break;
            e_.mov(iregs[i++], a);
        }
        e_.call(target);
    }
    void call_win64_reg(Reg64 target,
                        std::initializer_list<Reg64> regs = {}) {
        static const Reg64 iregs[] = {Reg64::RCX,Reg64::RDX,Reg64::R8,Reg64::R9};
        int i = 0;
        for (auto r : regs) {
            if (i >= 4) break;
            if (iregs[i] != r) e_.mov(iregs[i], r);
            i++;
        }
        e_.call(target);
    }

    // ── Diagnostics ──────────────────────────────────────────────────────
    const std::unordered_map<std::string, LocalVar>& locals() const { return locals_; }

    // ── Raw emitter access ───────────────────────────────────────────────
    EmitterX64& emitter() { return e_; }

private:
    EmitterX64& e_;
    u32 local_bytes_;
    u32 frame_size_  = 0;
    u32 entry_offset_ = 0;
    i32 rbp_cur_     = 0;
    std::unordered_map<std::string, LocalVar> locals_;
    std::unordered_map<std::string, Label>    named_labels_;
};

} // namespace mce
