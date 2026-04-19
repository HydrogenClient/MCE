#pragma once
#include "emitter_core.hpp"
#include <string>
#include <vector>
#include <stdexcept>
#include <cstring>

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#endif

/*
 * CodeBuffer – a named, position-tracked byte buffer with:
 *   - Multiple named sections (code / data / rdata)
 *   - Import table management
 *   - Convenience emit() that serialises to a PE64 .exe
 *
 * This is the top-level object a user interacts with.
 */

namespace mce {

class CodeBuffer {
public:
    CodeBuffer()  = default;
    ~CodeBuffer() = default;

    EmitterX64& text() { return text_; }

    // ── Add a Win32 import ───────────────────────────────────────────────
    CodeBuffer& import(const std::string& dll, const std::string& func, u32 hint = 0) {
        text_.add_import(dll, func, hint);
        return *this;
    }

    // ── Add to .rdata section ────────────────────────────────────────────
    u32 rdata(const void* data, usize n) { return text_.add_rdata(data, n); }
    u32 rdata(const char* str)           { return text_.add_string(str); }
    u32 rdata(const std::string& str)    { return text_.add_string(str.c_str()); }

    template<typename T>
    u32 rdata(const T& val) { return text_.add_rdata(&val, sizeof(T)); }

    // ── Add to .data section ─────────────────────────────────────────────
    u32 data(const void* d, usize n) { return text_.add_data(d, n); }

    template<typename T>
    u32 data(const T& val) { return text_.add_data(&val, sizeof(T)); }

    // ── Emit to PE ───────────────────────────────────────────────────────
    void emit(const std::string& path,
              u32  entry_offset = 0,
              bool console      = true) {
        text_.emit(path, entry_offset, console ? 3u : 2u);
    }

    // Overload for emitter.emit(entry, "path.exe") style
    void emit(u32 entry_offset, const std::string& path) {
        emit(path, entry_offset, true);
    }

    // ── Build and immediately run in memory (JIT-style) ──────────────────
    //   Returns the exit code of the executed function.
    //   The function must match:  int64_t (*)()
#if defined(_WIN32)
    i64 run(u32 entry_offset = 0) {
        // Allocate executable memory
        const byte_vec& code = text_.code();
        void* mem = VirtualAlloc(nullptr, code.size(),
                                 MEM_COMMIT | MEM_RESERVE,
                                 PAGE_EXECUTE_READWRITE);
        if (!mem) throw std::runtime_error("VirtualAlloc failed");
        std::memcpy(mem, code.data(), code.size());
        using Fn = i64(*)();
        auto fn = reinterpret_cast<Fn>(static_cast<u8*>(mem) + entry_offset);
        i64 result = fn();
        VirtualFree(mem, 0, MEM_RELEASE);
        return result;
    }
#endif

    // ── Reset ────────────────────────────────────────────────────────────
    void reset() { text_.reset(); }

    // ── Raw code access ──────────────────────────────────────────────────
    const byte_vec& raw_code() const { return text_.code(); }

private:
    EmitterX64 text_;
};

// ─── Global convenience instance ─────────────────────────────────────────────
// Matches the usage pattern:   emitter.emit(entry, "output.exe")
inline CodeBuffer& get_emitter() {
    static CodeBuffer instance;
    return instance;
}

#define emitter (get_emitter())

} // namespace mce
