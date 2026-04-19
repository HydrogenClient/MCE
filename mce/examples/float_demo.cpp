/*
 * float_demo.cpp
 * ──────────────
 * Demonstrates SSE2 floating-point: (10.5 + 4.5) / 3.0 = 5.0
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

    // Embed doubles
    double da = 10.5, db = 4.5, dc = 3.0;
    u32 da_off = iat.embed_skipped(&da, 8);
    u32 db_off = iat.embed_skipped(&db, 8);
    u32 dc_off = iat.embed_skipped(&dc, 8);

    u32 entry = e.current_offset();
    e.push(rbp); e.mov(rbp, rsp);
    e.sub(rsp, 64);

    // Use my new SSE helpers with RIP-relative patching
    auto load_sd = [&](RegXMM dst, u32 off) {
        e.raw(0xF2);
        if (idx(dst) >= 8) emit_rex(e.code(), false, true, false, false);
        e.raw(0x0F); e.raw(0x10);
        e.raw((u8)(0x05 | ((idx(dst)&7)<<3)));
        u32 p = e.current_offset(); e.raw({0,0,0,0});
        i32 r = (i32)off - (i32)(p + 4);
        auto& b = e.code();
        b[p+0]=u8(r); b[p+1]=u8(r>>8); b[p+2]=u8(r>>16); b[p+3]=u8(r>>24);
    };

    load_sd(xmm0, da_off);
    load_sd(xmm1, db_off);
    load_sd(xmm2, dc_off);

    e.addsd(xmm0, xmm1);
    e.divsd(xmm0, xmm2);

    // Result in xmm0 should be 5.0. 
    // Convert to int and print.
    e.raw({0xF2, 0x0F, 0x2C, 0xC0}); // cvttsd2si eax, xmm0
    e.mov(rbx, rax);

    // GetStd
    e.mov(rcx, (i64)-11);
    iat.call("kernel32.dll", "GetStdHandle");
    e.mov(rdi, rax);

    // Print "Result: "
    u32 res_msg = iat.embed_skipped_str("Result: ");
    e.mov(rcx, rdi);
    iat.lea_rip_rdx(res_msg);
    e.mov(r8, (i64)8);
    e.lea(r9, qword_ptr(rsp, 40));
    e.mov(qword_ptr(rsp, 32), (i32)0);
    iat.call("kernel32.dll", "WriteFile");

    // Print digit
    e.add(bl, (u8)'0');
    e.mov(byte_ptr(rsp, 32), bl);
    e.mov(rcx, rdi);
    e.lea(rdx, qword_ptr(rsp, 32));
    e.mov(r8, (i64)1);
    e.lea(r9, qword_ptr(rsp, 40));
    e.mov(qword_ptr(rsp, 32), (i32)0); // Wait, I used [rsp+32] for both!
    // Let's use [rsp+48] for the digit
    e.mov(byte_ptr(rsp, 48), bl);
    e.lea(rdx, qword_ptr(rsp, 48));
    e.mov(r8, (i64)1);
    e.lea(r9, qword_ptr(rsp, 56));
    e.mov(qword_ptr(rsp, 32), (i32)0);
    iat.call("kernel32.dll", "WriteFile");

    u32 nl = iat.embed_skipped_str("\r\n");
    e.mov(rcx, rdi);
    iat.lea_rip_rdx(nl);
    e.mov(r8, (i64)2);
    e.lea(r9, qword_ptr(rsp, 56));
    e.mov(qword_ptr(rsp, 32), (i32)0);
    iat.call("kernel32.dll", "WriteFile");

    e.xor_(ecx, ecx);
    iat.call("kernel32.dll", "ExitProcess");

    peb.subsystem = 3;
    auto& txt = peb.add_section(".text", pe::SEC_CODE);
    txt = e.code();
    auto img = peb.build(entry);
    iat.patch(img);
    pe::write_pe("float_demo.exe", img);

    printf("[MCE] Generated float_demo.exe\n");
    return 0;
}
