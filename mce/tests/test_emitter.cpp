/*
 * test_emitter.cpp
 * ────────────────
 * Unit tests for the MCE x86-64 emitter.
 *
 * Each test verifies the exact byte sequence produced by the emitter against
 * the canonical x86-64 encoding from the Intel SDM.
 *
 * Tests are self-contained — no external test framework needed.
 * Exit code 0 = all passed.  Non-zero = number of failures.
 */
#include <MCE/emitterx64>
#include <cstdio>
#include <cstring>
#include <vector>
#include <string>
#include <functional>
#include <initializer_list>

using namespace mce;
using namespace mce::detail;

// ─── Minimal test harness ────────────────────────────────────────────────────
static int g_total = 0;
static int g_failed = 0;

static void check(const char* name,
                  const byte_vec& got,
                  std::initializer_list<u8> expected_list)
{
    ++g_total;
    std::vector<u8> expected(expected_list);
    if (got.size() == expected.size() &&
        std::memcmp(got.data(), expected.data(), got.size()) == 0)
    {
        printf("  [PASS] %s\n", name);
        return;
    }
    ++g_failed;
    printf("  [FAIL] %s\n", name);
    printf("         expected: ");
    for (u8 b : expected) printf("%02X ", b);
    printf("\n");
    printf("         got:      ");
    for (u8 b : got)      printf("%02X ", b);
    printf("\n");
}

// Helper: run a lambda that emits into a fresh EmitterX64 and return the bytes
static byte_vec E(std::function<void(EmitterX64&)> fn) {
    EmitterX64 e; fn(e); return e.code();
}

// ─── Test groups ─────────────────────────────────────────────────────────────

// ── NOP / HALT ────────────────────────────────────────────────────────────────
static void test_misc() {
    printf("\n[misc]\n");
    check("nop",         E([](auto& e){ e.nop();  }), {0x90});
    check("hlt",         E([](auto& e){ e.hlt();  }), {0xF4});
    check("int3",        E([](auto& e){ e.int3(); }), {0xCC});
    check("int 0x80",    E([](auto& e){ e.int_(0x80); }), {0xCD,0x80});
    check("ud2",         E([](auto& e){ e.ud2(); }),  {0x0F,0x0B});
    check("ret",         E([](auto& e){ e.ret(); }),  {0xC3});
    check("ret 8",       E([](auto& e){ e.ret(8); }), {0xC2,0x08,0x00});
    check("syscall",     E([](auto& e){ e.syscall(); }), {0x0F,0x05});
    check("cpuid",       E([](auto& e){ e.cpuid(); }),  {0x0F,0xA2});
    check("nop-3",       E([](auto& e){ e.nop(3); }),   {0x0F,0x1F,0x00});
    check("pushfq",      E([](auto& e){ e.pushfq(); }), {0x9C});
    check("popfq",       E([](auto& e){ e.popfq(); }),  {0x9D});
    check("cld",         E([](auto& e){ e.cld(); }),    {0xFC});
    check("clc",         E([](auto& e){ e.clc(); }),    {0xF8});
    check("mfence",      E([](auto& e){ e.mfence(); }), {0x0F,0xAE,0xF0});
    check("rdtsc",       E([](auto& e){ e.rdtsc(); }),  {0x0F,0x31});
}

// ── PUSH / POP ────────────────────────────────────────────────────────────────
static void test_push_pop() {
    printf("\n[push/pop]\n");
    // push rax  = 50
    check("push rax",   E([](auto& e){ e.push(Reg64::RAX); }), {0x50});
    // push rbx  = 53
    check("push rbx",   E([](auto& e){ e.push(Reg64::RBX); }), {0x53});
    // push r8   = 41 50  (REX.B + 50+0)
    check("push r8",    E([](auto& e){ e.push(Reg64::R8);  }), {0x41,0x50});
    // push r15  = 41 57
    check("push r15",   E([](auto& e){ e.push(Reg64::R15); }), {0x41,0x57});
    // pop  rcx  = 59
    check("pop rcx",    E([](auto& e){ e.pop(Reg64::RCX); }), {0x59});
    // pop  r14  = 41 5E
    check("pop r14",    E([](auto& e){ e.pop(Reg64::R14); }), {0x41,0x5E});
    // push imm8 = 6A <imm>
    check("push imm8",  E([](auto& e){ e.push((i32)42); }), {0x6A,0x2A});
    // push imm32 = 68 xx xx xx xx
    check("push imm32", E([](auto& e){ e.push((i32)0x12345); }),
          {0x68,0x45,0x23,0x01,0x00});
}

// ── MOV ───────────────────────────────────────────────────────────────────────
static void test_mov() {
    printf("\n[mov]\n");
    // mov rax, rcx  =  48 89 C8  (MOV r/m64, r64 ; src=rcx=1, dst=rax=0)
    check("mov r64,r64",
          E([](auto& e){ e.mov(Reg64::RAX, Reg64::RCX); }),
          {0x48,0x89,0xC8});

    // mov rdx, r8   =  4C 89 C2  (REX.R | REX.W ; src=r8=8)
    check("mov rdx,r8",
          E([](auto& e){ e.mov(Reg64::RDX, Reg64::R8); }),
          {0x4C,0x89,0xC2});

    // mov r9, rsp   =  49 89 E1  (REX.W|REX.B ; dst=r9=9, src=rsp=4)
    check("mov r9,rsp",
          E([](auto& e){ e.mov(Reg64::R9, Reg64::RSP); }),
          {0x49,0x89,0xE1});

    // mov rax, 0 (using xor trick via mov r32,0 → zero-extend)
    // actually mov rax, 0 → MOV EAX,0 = B8 00000000
    check("mov rax,0",
          E([](auto& e){ e.mov(Reg64::RAX, (i64)0); }),
          {0xB8,0x00,0x00,0x00,0x00});

    // mov rax, 42  → B8 2A 00 00 00  (fits in u32, uses mov r32 form)
    check("mov rax,42",
          E([](auto& e){ e.mov(Reg64::RAX, (i64)42); }),
          {0xB8,0x2A,0x00,0x00,0x00});

    // mov rax, -1  → 48 C7 C0 FF FF FF FF  (sign-ext i32)
    check("mov rax,-1",
          E([](auto& e){ e.mov(Reg64::RAX, (i64)-1); }),
          {0x48,0xC7,0xC0,0xFF,0xFF,0xFF,0xFF});

    // mov rax, 0x1_0000_0000  → 48 B8 00 00 00 00 01 00 00 00  (full i64)
    check("mov rax,0x100000000",
          E([](auto& e){ e.mov(Reg64::RAX, (i64)0x100000000LL); }),
          {0x48,0xB8,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00});

    // mov r11, imm64   = 49 BB ...
    check("mov r11,imm64",
          E([](auto& e){ e.mov(Reg64::R11, (i64)0xDEADBEEFCAFELL); }),
          {0x49,0xBB,0xFE,0xCA,0xEF,0xBE,0xAD,0xDE,0x00,0x00});

    // mov eax, ecx  = 89 C8
    check("mov r32,r32",
          E([](auto& e){ e.mov(Reg32::EAX, Reg32::ECX); }),
          {0x89,0xC8});

    // mov eax, 0x10  = B8 10 00 00 00
    check("mov r32,imm32",
          E([](auto& e){ e.mov(Reg32::EAX, (u32)0x10); }),
          {0xB8,0x10,0x00,0x00,0x00});

    // mov ax, cx  = 66 89 C8
    check("mov r16,r16",
          E([](auto& e){ e.mov(Reg16::AX, Reg16::CX); }),
          {0x66,0x89,0xC8});

    // mov al, 0x42  = B0 42
    check("mov r8,imm8",
          E([](auto& e){ e.mov(Reg8::AL, (u8)0x42); }),
          {0xB0,0x42});

    // mov [rax], rcx  = 48 89 08
    check("mov [rax],rcx",
          E([](auto& e){ e.mov(qword_ptr(Reg64::RAX), Reg64::RCX); }),
          {0x48,0x89,0x08});

    // mov [rbp-8], rax = 48 89 45 F8
    check("mov [rbp-8],rax",
          E([](auto& e){ e.mov(qword_ptr(Reg64::RBP,-8), Reg64::RAX); }),
          {0x48,0x89,0x45,0xF8});

    // mov rax, [rcx]  = 48 8B 01
    check("mov rax,[rcx]",
          E([](auto& e){ e.mov(Reg64::RAX, qword_ptr(Reg64::RCX)); }),
          {0x48,0x8B,0x01});

    // mov rax, [rsp]  = 48 8B 04 24  (RSP base → SIB required)
    check("mov rax,[rsp]",
          E([](auto& e){ e.mov(Reg64::RAX, qword_ptr(Reg64::RSP)); }),
          {0x48,0x8B,0x04,0x24});

    // mov rax, [rsp+8]  = 48 8B 44 24 08
    check("mov rax,[rsp+8]",
          E([](auto& e){ e.mov(Reg64::RAX, qword_ptr(Reg64::RSP,8)); }),
          {0x48,0x8B,0x44,0x24,0x08});

    // mov [rbp-8], 42  = 48 C7 45 F8 2A 00 00 00
    check("mov [rbp-8],imm32",
          E([](auto& e){ e.mov(qword_ptr(Reg64::RBP,-8), (i32)42); }),
          {0x48,0xC7,0x45,0xF8,0x2A,0x00,0x00,0x00});
}

// ── LEA ───────────────────────────────────────────────────────────────────────
static void test_lea() {
    printf("\n[lea]\n");
    // lea rax, [rbp-8]  = 48 8D 45 F8
    check("lea rax,[rbp-8]",
          E([](auto& e){ e.lea(Reg64::RAX, qword_ptr(Reg64::RBP,-8)); }),
          {0x48,0x8D,0x45,0xF8});

    // lea rcx, [rsp+32]  = 48 8D 4C 24 20
    check("lea rcx,[rsp+32]",
          E([](auto& e){ e.lea(Reg64::RCX, qword_ptr(Reg64::RSP,32)); }),
          {0x48,0x8D,0x4C,0x24,0x20});

    // lea r8, [rbx+rcx*4]  = 4C 8D 04 8B
    check("lea r8,[rbx+rcx*4]",
          E([](auto& e){ e.lea(Reg64::R8, Mem::make(Reg64::RBX,Reg64::RCX,Scale::x4)); }),
          {0x4C,0x8D,0x04,0x8B});
}

// ── Arithmetic ────────────────────────────────────────────────────────────────
static void test_arith() {
    printf("\n[arith]\n");
    // add rax, rcx  = 48 01 C8
    check("add r64,r64",
          E([](auto& e){ e.add(Reg64::RAX, Reg64::RCX); }),
          {0x48,0x01,0xC8});

    // add rax, 1  = 48 83 C0 01  (imm8 form)
    check("add r64,imm8",
          E([](auto& e){ e.add(Reg64::RAX,(i32)1); }),
          {0x48,0x83,0xC0,0x01});

    // add rax, 0x1234  = 48 81 C0 34 12 00 00
    check("add r64,imm32",
          E([](auto& e){ e.add(Reg64::RAX,(i32)0x1234); }),
          {0x48,0x81,0xC0,0x34,0x12,0x00,0x00});

    // sub rsp, 32  = 48 83 EC 20
    check("sub rsp,32",
          E([](auto& e){ e.sub(Reg64::RSP,(i32)32); }),
          {0x48,0x83,0xEC,0x20});

    // xor eax, eax = 31 C0  (zero-idiom: no REX needed, 32-bit operands)
    check("xor eax,eax",
          E([](auto& e){ e.xor_(Reg32::EAX,Reg32::EAX); }),
          {0x31,0xC0});

    // and rax, rcx  = 48 21 C8
    check("and r64,r64",
          E([](auto& e){ e.and_(Reg64::RAX,Reg64::RCX); }),
          {0x48,0x21,0xC8});

    // or rax, rdx  = 48 09 D0
    check("or r64,r64",
          E([](auto& e){ e.or_(Reg64::RAX,Reg64::RDX); }),
          {0x48,0x09,0xD0});

    // cmp rax, 0   = 48 83 F8 00
    check("cmp rax,0",
          E([](auto& e){ e.cmp(Reg64::RAX,(i32)0); }),
          {0x48,0x83,0xF8,0x00});

    // test rax, rax  = 48 85 C0
    check("test rax,rax",
          E([](auto& e){ e.test(Reg64::RAX,Reg64::RAX); }),
          {0x48,0x85,0xC0});

    // inc rax  = 48 FF C0
    check("inc rax",
          E([](auto& e){ e.inc(Reg64::RAX); }),
          {0x48,0xFF,0xC0});

    // dec rcx  = 48 FF C9
    check("dec rcx",
          E([](auto& e){ e.dec(Reg64::RCX); }),
          {0x48,0xFF,0xC9});

    // neg rax  = 48 F7 D8
    check("neg rax",
          E([](auto& e){ e.neg(Reg64::RAX); }),
          {0x48,0xF7,0xD8});

    // not rax  = 48 F7 D0
    check("not rax",
          E([](auto& e){ e.not_(Reg64::RAX); }),
          {0x48,0xF7,0xD0});

    // imul rax, rcx, 3  = 48 6B C1 03
    check("imul r64,r64,imm8",
          E([](auto& e){ e.imul(Reg64::RAX,Reg64::RCX,(i32)3); }),
          {0x48,0x6B,0xC1,0x03});

    // imul rax, rcx, 0x400  = 48 69 C1 00 04 00 00
    check("imul r64,r64,imm32",
          E([](auto& e){ e.imul(Reg64::RAX,Reg64::RCX,(i32)0x400); }),
          {0x48,0x69,0xC1,0x00,0x04,0x00,0x00});

    // cqo  = 48 99
    check("cqo",
          E([](auto& e){ e.cqo(); }),
          {0x48,0x99});

    // cdq  = 99
    check("cdq",
          E([](auto& e){ e.cdq(); }),
          {0x99});
}

// ── Shifts ───────────────────────────────────────────────────────────────────
static void test_shifts() {
    printf("\n[shifts]\n");
    // shl rax, 1  = 48 D1 E0
    check("shl rax,1",
          E([](auto& e){ e.shl(Reg64::RAX,(u8)1); }),
          {0x48,0xD1,0xE0});

    // shl rax, 3  = 48 C1 E0 03
    check("shl rax,3",
          E([](auto& e){ e.shl(Reg64::RAX,(u8)3); }),
          {0x48,0xC1,0xE0,0x03});

    // shr rax, 7  = 48 C1 E8 07
    check("shr rax,7",
          E([](auto& e){ e.shr(Reg64::RAX,(u8)7); }),
          {0x48,0xC1,0xE8,0x07});

    // sar rax, 1  = 48 D1 F8
    check("sar rax,1",
          E([](auto& e){ e.sar(Reg64::RAX,(u8)1); }),
          {0x48,0xD1,0xF8});

    // sar rcx, 4  = 48 C1 F9 04
    check("sar rcx,4",
          E([](auto& e){ e.sar(Reg64::RCX,(u8)4); }),
          {0x48,0xC1,0xF9,0x04});

    // rol eax, 1  = D1 C0
    check("rol eax,1",
          E([](auto& e){ e.rol(Reg32::EAX,(u8)1); }),
          {0xD1,0xC0});

    // ror eax, 8  = C1 C8 08
    check("ror eax,8",
          E([](auto& e){ e.ror(Reg32::EAX,(u8)8); }),
          {0xC1,0xC8,0x08});

    // shl_cl rax  = 48 D3 E0
    check("shl rax,cl",
          E([](auto& e){ e.shl_cl(Reg64::RAX); }),
          {0x48,0xD3,0xE0});
}

// ── MOVSX / MOVZX ─────────────────────────────────────────────────────────────
static void test_movext() {
    printf("\n[movsx/movzx]\n");
    // movsx rax, ecx  = 48 63 C1
    check("movsx rax,ecx",
          E([](auto& e){ e.movsx(Reg64::RAX, Reg32::ECX); }),
          {0x48,0x63,0xC1});

    // movsx rax, cx   = 48 0F BF C1
    check("movsx rax,cx",
          E([](auto& e){ e.movsx(Reg64::RAX, Reg16::CX); }),
          {0x48,0x0F,0xBF,0xC1});

    // movsx rax, cl   = 48 0F BE C1
    check("movsx rax,cl",
          E([](auto& e){ e.movsx(Reg64::RAX, Reg8::CL); }),
          {0x48,0x0F,0xBE,0xC1});

    // movzx eax, cx   = 0F B7 C1
    check("movzx eax,cx",
          E([](auto& e){ e.movzx(Reg32::EAX, Reg16::CX); }),
          {0x0F,0xB7,0xC1});

    // movzx eax, cl   = 0F B6 C1
    check("movzx eax,cl",
          E([](auto& e){ e.movzx(Reg32::EAX, Reg8::CL); }),
          {0x0F,0xB6,0xC1});
}

// ── Jumps & Calls ─────────────────────────────────────────────────────────────
static void test_jmp_call() {
    printf("\n[jmp/call]\n");

    // Forward jmp: E9 <rel32>  — label after 2 bytes of code
    {
        byte_vec got = E([](auto& e){
            auto lbl = e.make_label();
            e.jmp(lbl);    // 5 bytes: E9 xx xx xx xx
            e.nop();       // 1 byte
            e.bind(lbl);
        });
        // rel = 1  (target is 1 byte past the instruction end)
        std::vector<u8> expected = {0xE9,0x01,0x00,0x00,0x00, 0x90};
        g_total++;
        if (got == expected) printf("  [PASS] fwd jmp rel32\n");
        else {
            g_failed++;
            printf("  [FAIL] fwd jmp rel32: got ");
            for (auto b:got) { printf("%02X ",b); } printf("\n");
        }
    }

    // Backward jmp: target before the jump
    {
        byte_vec got = E([](auto& e){
            auto lbl = e.make_label();
            e.bind(lbl);
            e.nop();       // 1 byte
            e.jmp(lbl);    // 5 bytes, rel = -(5+1) = -6
        });
        // Encoding: 90  E9 FA FF FF FF
        std::vector<u8> expected = {0x90, 0xE9,0xFA,0xFF,0xFF,0xFF};
        g_total++;
        if (got == expected) printf("  [PASS] bwd jmp rel32\n");
        else {
            g_failed++;
            printf("  [FAIL] bwd jmp rel32: got ");
            for (auto b:got) { printf("%02X ",b); } printf("\n");
        }
    }

    // je forward  = 0F 84 <rel32>
    {
        byte_vec got = E([](auto& e){
            auto lbl = e.make_label();
            e.je(lbl);    // 6 bytes: 0F 84 xx xx xx xx
            e.nop(); e.nop();
            e.bind(lbl);
        });
        std::vector<u8> expected = {0x0F,0x84,0x02,0x00,0x00,0x00, 0x90,0x90};
        g_total++;
        if (got == expected) printf("  [PASS] je rel32\n");
        else {
            g_failed++;
            printf("  [FAIL] je rel32: got ");
            for (auto b:got) { printf("%02X ",b); } printf("\n");
        }
    }

    // jmp rax  = FF E0
    check("jmp rax",
          E([](auto& e){ e.jmp(Reg64::RAX); }),
          {0xFF,0xE0});

    // jmp r11  = 41 FF E3
    check("jmp r11",
          E([](auto& e){ e.jmp(Reg64::R11); }),
          {0x41,0xFF,0xE3});

    // call rax  = FF D0
    check("call rax",
          E([](auto& e){ e.call(Reg64::RAX); }),
          {0xFF,0xD0});

    // call r9   = 41 FF D1
    check("call r9",
          E([](auto& e){ e.call(Reg64::R9); }),
          {0x41,0xFF,0xD1});
}

// ── Bit operations ────────────────────────────────────────────────────────────
static void test_bit_ops() {
    printf("\n[bit-ops]\n");
    // bsf rax, rcx  = 48 0F BC C1
    check("bsf rax,rcx",
          E([](auto& e){ e.bsf(Reg64::RAX,Reg64::RCX); }),
          {0x48,0x0F,0xBC,0xC1});

    // bsr rax, rcx  = 48 0F BD C1
    check("bsr rax,rcx",
          E([](auto& e){ e.bsr(Reg64::RAX,Reg64::RCX); }),
          {0x48,0x0F,0xBD,0xC1});

    // bswap rax  = 48 0F C8
    check("bswap rax",
          E([](auto& e){ e.bswap(Reg64::RAX); }),
          {0x48,0x0F,0xC8});

    // bswap eax  = 0F C8
    check("bswap eax",
          E([](auto& e){ e.bswap(Reg32::EAX); }),
          {0x0F,0xC8});

    // bt rax, 3  = 48 0F BA E0 03
    check("bt rax,3",
          E([](auto& e){ e.bt(Reg64::RAX,(u8)3); }),
          {0x48,0x0F,0xBA,0xE0,0x03});

    // popcnt rax, rcx  = F3 48 0F B8 C1
    check("popcnt rax,rcx",
          E([](auto& e){ e.popcnt(Reg64::RAX,Reg64::RCX); }),
          {0xF3,0x48,0x0F,0xB8,0xC1});

    // tzcnt rax, rcx  = F3 48 0F BC C1
    check("tzcnt rax,rcx",
          E([](auto& e){ e.tzcnt(Reg64::RAX,Reg64::RCX); }),
          {0xF3,0x48,0x0F,0xBC,0xC1});

    // lzcnt rax, rcx  = F3 48 0F BD C1
    check("lzcnt rax,rcx",
          E([](auto& e){ e.lzcnt(Reg64::RAX,Reg64::RCX); }),
          {0xF3,0x48,0x0F,0xBD,0xC1});
}

// ── XCHG / BSWAP ──────────────────────────────────────────────────────────────
static void test_xchg() {
    printf("\n[xchg]\n");
    // xchg rax, rcx  = 48 87 C8  (no short form — rax is dst not src in SDM)
    // Actually: XCHG r/m64, r64 = 87 /r  → 48 87 C8 when rax=rm, rcx=r
    // Short form: XCHG rAX, r/m64 = REX.W + 90+r (only when rax is first)
    // Our impl uses short form when a==RAX.
    check("xchg rax,rcx (short)",
          E([](auto& e){ e.xchg(Reg64::RAX,Reg64::RCX); }),
          {0x48,0x91});  // REX.W 90+1

    check("xchg rbx,rcx",
          E([](auto& e){ e.xchg(Reg64::RBX,Reg64::RCX); }),
          {0x48,0x87,0xCB});
}

// ── SETcc ─────────────────────────────────────────────────────────────────────
static void test_setcc() {
    printf("\n[setcc]\n");
    // sete al  = 0F 94 C0
    check("sete al",
          E([](auto& e){ e.setcc(Cond::E, Reg8::AL); }),
          {0x0F,0x94,0xC0});

    // setne dl  = 0F 95 C2
    check("setne dl",
          E([](auto& e){ e.setcc(Cond::NE, Reg8::DL); }),
          {0x0F,0x95,0xC2});

    // setg cl  = 0F 9F C1
    check("setg cl",
          E([](auto& e){ e.setcc(Cond::G, Reg8::CL); }),
          {0x0F,0x9F,0xC1});
}

// ── CMOVcc ────────────────────────────────────────────────────────────────────
static void test_cmovcc() {
    printf("\n[cmovcc]\n");
    // cmove rax, rcx  = 48 0F 44 C1
    check("cmove rax,rcx",
          E([](auto& e){ e.cmovcc(Cond::E, Reg64::RAX, Reg64::RCX); }),
          {0x48,0x0F,0x44,0xC1});

    // cmovne rax, rdx  = 48 0F 45 C2
    check("cmovne rax,rdx",
          E([](auto& e){ e.cmovcc(Cond::NE, Reg64::RAX, Reg64::RDX); }),
          {0x48,0x0F,0x45,0xC2});
}

// ── SSE2 ──────────────────────────────────────────────────────────────────────
static void test_sse2() {
    printf("\n[sse2]\n");
    // movsd xmm0, xmm1  = F2 0F 10 C1
    check("movsd xmm0,xmm1",
          E([](auto& e){ e.movsd(RegXMM::XMM0, RegXMM::XMM1); }),
          {0xF2,0x0F,0x10,0xC1});

    // addsd xmm0, xmm2  = F2 0F 58 C2
    check("addsd xmm0,xmm2",
          E([](auto& e){ e.addsd(RegXMM::XMM0, RegXMM::XMM2); }),
          {0xF2,0x0F,0x58,0xC2});

    // mulsd xmm1, xmm3  = F2 0F 59 CB
    check("mulsd xmm1,xmm3",
          E([](auto& e){ e.mulsd(RegXMM::XMM1, RegXMM::XMM3); }),
          {0xF2,0x0F,0x59,0xCB});

    // subsd xmm0, xmm1  = F2 0F 5C C1
    check("subsd xmm0,xmm1",
          E([](auto& e){ e.subsd(RegXMM::XMM0, RegXMM::XMM1); }),
          {0xF2,0x0F,0x5C,0xC1});

    // divsd xmm0, xmm1  = F2 0F 5E C1
    check("divsd xmm0,xmm1",
          E([](auto& e){ e.divsd(RegXMM::XMM0, RegXMM::XMM1); }),
          {0xF2,0x0F,0x5E,0xC1});

    // sqrtsd xmm0, xmm0  = F2 0F 51 C0
    check("sqrtsd xmm0,xmm0",
          E([](auto& e){ e.sqrtsd(RegXMM::XMM0, RegXMM::XMM0); }),
          {0xF2,0x0F,0x51,0xC0});

    // cvtsi2sd xmm0, rax  = F2 48 0F 2A C0
    check("cvtsi2sd xmm0,rax",
          E([](auto& e){ e.cvtsi2sd(RegXMM::XMM0, Reg64::RAX); }),
          {0xF2,0x48,0x0F,0x2A,0xC0});

    // cvttsd2si rax, xmm0  = F2 48 0F 2C C0
    check("cvttsd2si rax,xmm0",
          E([](auto& e){ e.cvttsd2si(Reg64::RAX, RegXMM::XMM0); }),
          {0xF2,0x48,0x0F,0x2C,0xC0});

    // xorpd xmm0, xmm0  = 66 0F 57 C0
    check("xorpd xmm0,xmm0",
          E([](auto& e){ e.xorpd(RegXMM::XMM0, RegXMM::XMM0); }),
          {0x66,0x0F,0x57,0xC0});

    // addss xmm0, xmm1  = F3 0F 58 C1
    check("addss xmm0,xmm1",
          E([](auto& e){ e.addss(RegXMM::XMM0, RegXMM::XMM1); }),
          {0xF3,0x0F,0x58,0xC1});
}

// ── String instructions ───────────────────────────────────────────────────────
static void test_string_ops() {
    printf("\n[string-ops]\n");
    // rep stosb  = F3 AA
    check("rep stosb",
          E([](auto& e){ e.rep_stosb(); }),
          {0xF3,0xAA});

    // rep movsb  = F3 A4
    check("rep movsb",
          E([](auto& e){ e.rep_movsb(); }),
          {0xF3,0xA4});

    // rep stosq  = F3 48 AB
    check("rep stosq",
          E([](auto& e){ e.rep_stosq(); }),
          {0xF3,0x48,0xAB});

    // scasb  = AE
    check("scasb",
          E([](auto& e){ e.scasb(); }),
          {0xAE});
}

// ── Prolog/Epilog helpers ─────────────────────────────────────────────────────
static void test_frame() {
    printf("\n[frame]\n");
    // prolog(0)  = push rbp ; mov rbp,rsp
    check("prolog(0)",
          E([](auto& e){ e.prolog(0); }),
          {0x55,           // push rbp
           0x48,0x89,0xE5  // mov rbp,rsp
          });

    // epilog  = mov rsp,rbp ; pop rbp ; ret
    check("epilog",
          E([](auto& e){ e.epilog(); }),
          {0x48,0x89,0xEC, // mov rsp,rbp
           0x5D,           // pop rbp
           0xC3            // ret
          });
}

// ── PE builder sanity ─────────────────────────────────────────────────────────
static void test_pe_builder() {
    printf("\n[pe-builder]\n");
    g_total++;

    pe::PEBuilder peb;
    peb.subsystem = pe::SUBSYSTEM_CONSOLE;
    auto& text = peb.add_section(".text", pe::SEC_CODE);
    // Minimal code: xor eax,eax ; ret
    text = {0x31,0xC0, 0xC3};
    peb.add_import("kernel32.dll","ExitProcess",0);
    auto img = peb.build(0);

    bool ok = true;
    // Check MZ signature
    if (img.size() < 64 || img[0]!=0x4D || img[1]!=0x5A) ok=false;
    // Check PE sig at e_lfanew=0x40
    if (ok && img.size() > 0x44) {
        u32 pesig = u32(img[0x40])|u32(img[0x41])<<8|u32(img[0x42])<<16|u32(img[0x43])<<24;
        if (pesig != 0x00004550) ok = false;
    }
    // Check machine = AMD64 (0x8664)
    if (ok) {
        u16 mach = u16(img[0x44])|u16(img[0x45])<<8;
        if (mach != 0x8664) ok = false;
    }
    // IAT slot RVA must be non-zero
    u32 iat_rva = peb.get_iat_rva("kernel32.dll","ExitProcess");
    if (iat_rva == 0) ok = false;

    if (ok) printf("  [PASS] pe_builder basic structure\n");
    else { ++g_failed; printf("  [FAIL] pe_builder basic structure\n"); }
}

// ─── Main ─────────────────────────────────────────────────────────────────────
int main() {
    printf("=== MCE x86-64 Emitter Tests ===\n");

    test_misc();
    test_push_pop();
    test_mov();
    test_lea();
    test_arith();
    test_shifts();
    test_movext();
    test_jmp_call();
    test_bit_ops();
    test_xchg();
    test_setcc();
    test_cmovcc();
    test_sse2();
    test_string_ops();
    test_frame();
    test_pe_builder();

    printf("\n");
    printf("=== Results: %d/%d passed", g_total - g_failed, g_total);
    if (g_failed) printf("  (%d FAILED)", g_failed);
    printf(" ===\n\n");

    return g_failed;
}
