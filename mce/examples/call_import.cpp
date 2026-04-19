/*
 * call_import.cpp
 * ───────────────
 * Demonstrates FunctionBuilder and calling imported functions.
 */
#include <MCE/emitterx64>
#include <cstdio>

using namespace mce;
using namespace mce::reg;

int main() {
    pe::PEBuilder peb;
    peb.import("kernel32.dll", "GetStdHandle")
       .import("kernel32.dll", "WriteFile")
       .import("kernel32.dll", "ExitProcess");

    EmitterX64& e = emitter.text();
    IATHelper iat(e, peb);

    // Entry
    u32 entry = e.current_offset();

    FunctionBuilder fn(e, 32); // 32 bytes for locals

    fn.prologue();

    // GetStdHandle(-11)
    e.mov(rcx, (i64)-11);
    iat.call("kernel32.dll", "GetStdHandle");
    e.mov(rbx, rax); // handle in rbx

    // Message
    u32 m_off = iat.embed_skipped_str("FunctionBuilder demo: loop 1-5\r\n");
    e.mov(rcx, rbx);
    iat.lea_rip_rdx(m_off);
    e.mov(r8, (i64)31);
    e.lea(r9, qword_ptr(rsp, 40)); 
    e.mov(qword_ptr(rsp, 32), (i32)0);
    iat.call("kernel32.dll", "WriteFile");

    // Loop 1..5
    e.mov(rsi, (i64)1);
    auto lp = e.make_label();
    e.bind(lp);
    
    // Just print a dot for each iteration
    u32 dot_off = iat.embed_skipped_str(".");
    e.mov(rcx, rbx);
    iat.lea_rip_rdx(dot_off);
    e.mov(r8, (i64)1);
    e.lea(r9, qword_ptr(rsp, 40));
    e.mov(qword_ptr(rsp, 32), (i32)0);
    iat.call("kernel32.dll", "WriteFile");

    e.inc(rsi);
    e.cmp(rsi, (i32)5);
    e.jle(lp);

    u32 nl_off = iat.embed_skipped_str("\r\nDone!\r\n");
    e.mov(rcx, rbx);
    iat.lea_rip_rdx(nl_off);
    e.mov(r8, (i64)9);
    e.lea(r9, qword_ptr(rsp, 40));
    e.mov(qword_ptr(rsp, 32), (i32)0);
    iat.call("kernel32.dll", "WriteFile");

    e.xor_(ecx, ecx);
    iat.call("kernel32.dll", "ExitProcess");

    fn.epilogue();

    peb.subsystem = 3;
    auto& txt = peb.add_section(".text", pe::SEC_CODE);
    txt = e.code();
    auto img = peb.build(entry);
    iat.patch(img);
    pe::write_pe("call_import.exe", img);

    printf("[MCE] Generated call_import.exe\n");
    return 0;
}
