/* #include <MCE/emitterx64>
#include <cstdio>

using namespace mce;
using namespace mce::reg;

int main() {
    // 1. Setup PE structure
    pe::PEBuilder peb;
    peb.import("kernel32.dll", "GetStdHandle")
       .import("kernel32.dll", "WriteFile")
       .import("kernel32.dll", "ExitProcess");

    EmitterX64& e = emitter.text();
    IATHelper iat(e, peb);

    // 2. Entry point
    u32 entry = e.current_offset();

    // Prologue (Win64 ABI)
    e.push(rbp);
    e.mov(rbp, rsp);
    e.sub(rsp, 48);

    // Embed string
    u32 msg_off = iat.embed_skipped_str("Hello from MCE-generated machine code!\r\n");
    u32 msg_len = 40;

    // GetStdHandle(-11)
    e.mov(rcx, (i64)-11);
    iat.call("kernel32.dll", "GetStdHandle");
    e.mov(rbx, rax);

    // WriteFile(handle, msg, len, &written, NULL)
    e.mov(rcx, rbx);
    iat.lea_rip_rdx(msg_off);
    e.mov(r8, (i64)msg_len);
    e.lea(r9, qword_ptr(rsp, 40));
    e.mov(qword_ptr(rsp, 32), (i32)0);
    iat.call("kernel32.dll", "WriteFile");

    // ExitProcess(0)
    e.xor_(ecx, ecx);
    iat.call("kernel32.dll", "ExitProcess");

    // 3. Build and Patch
    peb.subsystem = 3;
    auto& text = peb.add_section(".text", pe::SEC_CODE);
    text = e.code();
    
    auto image = peb.build(entry);
    iat.patch(image);
    pe::write_pe("hello.exe", image);

    printf("[MCE] Generated hello.exe\n");
    return 0;
}
 */

#include <MCE/emitterx64>
#include <cstdio>

using namespace mce;
using namespace mce::reg;

int main() {
    // -------------------------
    // PE SETUP
    // -------------------------
    pe::PEBuilder peb;
    peb.import("kernel32.dll", "GetStdHandle")
       .import("kernel32.dll", "WriteFile")
       .import("kernel32.dll", "ExitProcess");

    EmitterX64& e = emitter.text();
    IATHelper iat(e, peb);

    u32 entry = e.current_offset();

    // -------------------------
    // PROLOGUE (Win64 ABI)
    // -------------------------
    e.push(rbp);
    e.mov(rbp, rsp);
    e.sub(rsp, 64);

    // -------------------------
    // STRINGS
    // -------------------------
    u32 hdr  = iat.embed_skipped_str("[MCE demo]\r\n");
    u32 iter = iat.embed_skipped_str("Iteration: ");
    u32 done = iat.embed_skipped_str("Done.\r\n");

    // -------------------------
    // STDOUT HANDLE
    // -------------------------
    e.mov(rcx, (i64)-11);
    iat.call("kernel32.dll", "GetStdHandle");
    e.mov(rbx, rax);

    // -------------------------
    // PRINT HEADER
    // -------------------------
    e.mov(rcx, rbx);
    iat.lea_rip_rdx(hdr);
    e.mov(r8, (i64)13);
    e.lea(r9, qword_ptr(rsp, 48));
    e.mov(qword_ptr(rsp, 32), (i32)0);
    iat.call("kernel32.dll", "WriteFile");

    // -------------------------
    // COUNTER = 0
    // -------------------------
    e.xor_(ecx, ecx);

    // -------------------------
    // LOOP
    // -------------------------
    Label loop_start;

    // NOTE:
    // DO NOT bind loop_start manually.
    // Your jl(Label) system handles resolution.

    // print "Iteration: "
    e.mov(rcx, rbx);
    iat.lea_rip_rdx(iter);
    e.mov(r8, (i64)11);
    e.lea(r9, qword_ptr(rsp, 48));
    e.mov(qword_ptr(rsp, 32), (i32)0);
    iat.call("kernel32.dll", "WriteFile");

    // convert counter → ASCII (0–9 only)
    e.mov(eax, ecx);
    e.add(al, '0');
    e.mov(byte_ptr(rsp, 0), al);
    e.mov(byte_ptr(rsp, 1), '\r');
    e.mov(byte_ptr(rsp, 2), '\n');

    // print number
    e.mov(rcx, rbx);
    e.lea(rdx, qword_ptr(rsp, 0));
    e.mov(r8, (i64)3);
    e.lea(r9, qword_ptr(rsp, 48));
    e.mov(qword_ptr(rsp, 32), (i32)0);
    iat.call("kernel32.dll", "WriteFile");

    // counter++
    e.inc(ecx);

    // loop condition
    e.cmp(ecx, 10);
    e.jl(loop_start);

    // -------------------------
    // DONE
    // -------------------------
    e.mov(rcx, rbx);
    iat.lea_rip_rdx(done);
    e.mov(r8, (i64)7);
    e.lea(r9, qword_ptr(rsp, 48));
    e.mov(qword_ptr(rsp, 32), (i32)0);
    iat.call("kernel32.dll", "WriteFile");

    // exit
    e.xor_(ecx, ecx);
    iat.call("kernel32.dll", "ExitProcess");

    // -------------------------
    // BUILD PE
    // -------------------------
    peb.subsystem = 3;
    auto& text = peb.add_section(".text", pe::SEC_CODE);
    text = e.code();

    auto image = peb.build(entry);
    iat.patch(image);
    pe::write_pe("hello_world.exe", image);

    printf("[MCE] Generated hello_world.exe\n");
    return 0;
}