#include <MCE/emitterx64>
#include <cstdio>

using namespace mce;
using namespace mce::reg;

//  int64_t fib(int64_t n) {
//    if (n <= 1) return n;
//    return fib(n-1) + fib(n-2);
//  }
u32 emit_fib(EmitterX64& e) {
    auto base = e.make_label();
    auto rec = e.make_label();
    u32 start = e.current_offset();

    e.push(rbp); e.mov(rbp, rsp);
    e.sub(rsp, 32); 

    e.cmp(rcx, (i32)1);
    e.jg(rec);
    // Base case
    e.mov(rax, rcx);
    e.jmp(base);

    e.bind(rec);
    e.push(rcx); 
    e.dec(rcx);
    // call fib
    {
        u32 call_site = e.current_offset(); e.raw(0xE8); u32 d=e.current_offset(); e.raw({0,0,0,0});
        i32 rel = (i32)start - (i32)(d + 4);
        auto& b = e.code();
        b[d+0]=u8(rel); b[d+1]=u8(rel>>8); b[d+2]=u8(rel>>16); b[d+3]=u8(rel>>24);
    }
    e.pop(rcx);
    e.push(rax); // Save fib(n-1)
    e.sub(rcx, (i32)2);
    // call fib
    {
        u32 call_site = e.current_offset(); e.raw(0xE8); u32 d=e.current_offset(); e.raw({0,0,0,0});
        i32 rel = (i32)start - (i32)(d + 4);
        auto& b = e.code();
        b[d+0]=u8(rel); b[d+1]=u8(rel>>8); b[d+2]=u8(rel>>16); b[d+3]=u8(rel>>24);
    }
    e.pop(rcx); // Load fib(n-1) into RCX
    e.add(rax, rcx);

    e.bind(base);
    e.mov(rsp, rbp); e.pop(rbp);
    e.ret();
    return start;
}

int main() {
    pe::PEBuilder peb;
    peb.import("kernel32.dll", "GetStdHandle")
       .import("kernel32.dll", "WriteFile")
       .import("kernel32.dll", "ExitProcess");

    EmitterX64& e = emitter.text();
    IATHelper iat(e, peb);

    u32 fib_off = emit_fib(e);
    u32 entry = e.current_offset();

    e.push(rbp); e.mov(rbp, rsp);
    e.sub(rsp, 64);
    e.push(rbx); e.push(rdi); e.push(rsi);

    // Call fib(40)
    e.mov(rcx, (i64)40);
    {
        u32 call_ptr = e.current_offset(); e.raw(0xE8); u32 d=e.current_offset(); e.raw({0,0,0,0});
        i32 rel = (i32)fib_off - (i32)(d + 4);
        auto& b = e.code();
        b[d+0]=u8(rel); b[d+1]=u8(rel>>8); b[d+2]=u8(rel>>16); b[d+3]=u8(rel>>24);
    }
    e.mov(rbx, rax);

    // GetStd
    e.mov(rcx, (i64)-11);
    iat.call("kernel32.dll", "GetStdHandle");
    e.mov(rdi, rax);

    // itoa minimal
    e.lea(rsi, qword_ptr(rsp, 32));
    e.mov(rax, rbx);
    e.mov(byte_ptr(rsi, 15), (u8)'\n');
    e.mov(byte_ptr(rsi, 14), (u8)'\r');
    e.mov(rbx, (i64)13);
    auto lp = e.make_label();
    e.bind(lp);
    e.xor_(edx, edx); e.mov(r10, (i64)10); e.div_(r10);
    e.add(dl, (u8)'0'); e.mov(byte_ptr(rsi, rbx, Scale::x1), dl);
    e.dec(rbx);
    e.test(rax, rax);
    e.jnz(lp);

    e.inc(rbx);
    e.lea(rdx, qword_ptr(rsi, rbx, Scale::x1));
    e.mov(r8, (i64)16); e.sub(r8, rbx);
    e.mov(rcx, rdi);
    e.lea(r9, qword_ptr(rsp, 56));
    e.mov(qword_ptr(rsp, 32), (i32)0);
    iat.call("kernel32.dll", "WriteFile");

    e.xor_(ecx, ecx);
    iat.call("kernel32.dll", "ExitProcess");

    peb.subsystem = 3;
    auto& txt = peb.add_section(".text", pe::SEC_CODE);
    txt = e.code();
    auto image = peb.build(entry);
    iat.patch(image);
    pe::write_pe("fibonacci.exe", image);
    printf("[MCE] Generated fibonacci.exe\n");
    return 0;
}
