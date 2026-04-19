# MCE — Machine Code Emitter (x86-64)

A **header-only**, from-scratch x86-64 machine code emitter written in pure C++17.
No LLVM. No libc. No external dependencies.

---

## Features

| Category | Details |
|---|---|
| **Registers** | `Reg8/16/32/64`, `RegXMM`, `RegYMM` — all 16 GPRs, all 16 XMM regs |
| **Instructions** | MOV · LEA · ADD/SUB/AND/OR/XOR/CMP/ADC/SBB · TEST · NOT/NEG/INC/DEC · MUL/IMUL/DIV/IDIV · SHL/SHR/SAR/ROL/ROR/RCL/RCR · BT/BTS/BTR/BTC · BSF/BSR · BSWAP · XCHG · XADD · CMPXCHG · POPCNT · LZCNT · TZCNT · MOVSX/MOVZX · PUSH/POP · JMP/CALL/RET · Jcc (all 16 conditions) · SETcc · CMOVcc · REP MOVS/STOS/SCAS · SSE2 scalar/packed FP · CVT conversions · RDTSC · CPUID · SYSCALL |
| **Memory operands** | `[base]` · `[base+disp8/32]` · `[base+index*scale+disp]` · `[RIP+disp32]` · SIB encoding for RSP/R12 base · automatic REX prefix generation |
| **Labels** | Forward- and back-patching rel8/rel32 fixups |
| **Sections** | `.text` (code) · `.rdata` (read-only data) · `.data` (read-write data) |
| **Import table** | Full `.idata` section with IDT + ILT + IAT + HintName + DLL name strings |
| **Output** | Valid **Windows PE64 / PE32+** executables (console or GUI subsystem) |
| **JIT** | Optional in-memory execution via `VirtualAlloc` (Windows) |
| **Helpers** | `FunctionBuilder` — named locals, Win64 ABI prologue/epilogue |
|            | `IATHelper` — deduplicated `CALL [RIP+IAT]` trampolines + patching |
|            | `CodeBuffer` — global `emitter` object |

---

## Quick-start

```cpp
#include <MCE/emitterx64>
using namespace mce;

int main() {
    EmitterX64 e;

    // Simple function: returns 42
    e.prolog();
    e.mov(Reg64::RAX, (i64)42);
    e.epilog(); // mov rsp,rbp  pop rbp  ret

    e.emit("answer.exe");   // → valid Windows PE64 exe (exit code not set, demo)
}
```

---

## Project layout

```
MCE/
├── MCE/
│   ├── emitterx64              ← single public include (no extension)
│   └── detail/
│       ├── types.hpp           ← type aliases, register enums, Mem struct, Label
│       ├── encoding.hpp        ← REX, ModRM, SIB, disp helpers
│       ├── pe_writer.hpp       ← PE32+ writer (IDT/ILT/IAT/HintName)
│       ├── emitter_core.hpp    ← EmitterX64 — all instruction emitters
│       ├── function_builder.hpp← FunctionBuilder — named locals / labels
│       ├── code_buffer.hpp     ← CodeBuffer + global `emitter` instance
│       └── iat_helper.hpp      ← IATHelper — CALL [RIP+IAT] trampolines
├── examples/
│   ├── hello_world.cpp         ← WriteConsoleA + GetStdHandle + ExitProcess
│   ├── fibonacci.cpp           ← loop, labels, BSR, 64-bit arithmetic
│   ├── float_demo.cpp          ← SSE2 addsd/divsd, cvttsd2si
│   └── call_import.cpp         ← table printer, uitoa, FunctionBuilder
├── tests/
│   └── test_emitter.cpp        ← 70+ byte-exact encoding unit tests
└── CMakeLists.txt
```

---

## Building

### Requirements
- CMake ≥ 3.16
- MSVC 2019+ **or** GCC 9+ **or** Clang 10+
- Windows target (for PE output and JIT runner)

### Configure & build

```powershell
# From the repo root
cmake -B build -DMCE_BUILD_EXAMPLES=ON -DMCE_BUILD_TESTS=ON
cmake --build build --config Release
```

### Run tests

```powershell
cd build
ctest -C Release --output-on-failure
# or directly:
.\tests\Release\test_emitter.exe
```

### Run an example

```powershell
.\build\examples\Release\hello_world.exe   # generates hello.exe
.\hello.exe
```

---

## API reference

### `EmitterX64`

```cpp
EmitterX64 e;

// ── Labels ────────────────────────────────────────────────────────────────
auto lbl = e.make_label();
e.bind(lbl);

// ── Data sections ─────────────────────────────────────────────────────────
u32 off = e.add_rdata("hello\r\n", 7);   // returns offset in .rdata
u32 off = e.add_string("hello");          // null-terminates
u32 off = e.add_data(&myStruct, sizeof(myStruct));

// ── Imports ───────────────────────────────────────────────────────────────
e.add_import("kernel32.dll", "ExitProcess", /*hint=*/0);

// ── Emit to file ──────────────────────────────────────────────────────────
e.emit("out.exe", entry_offset, /*console=*/true);

// ── JIT (Windows only) ────────────────────────────────────────────────────
// [declared in CodeBuffer, not EmitterX64 directly]

// ── Raw escape hatch ──────────────────────────────────────────────────────
e.raw(0x0F);
e.raw({0x0F, 0xAE, 0xF0}); // mfence
```

### Selected instruction signatures

```cpp
// MOV
e.mov(Reg64, Reg64);           e.mov(Reg64, i64);
e.mov(Reg64, const Mem&);      e.mov(const Mem&, Reg64);
e.mov(const Mem&, i32);        // sign-extended store
e.mov(Reg32, Reg32);           e.mov(Reg32, u32);
e.mov(Reg16, u16);             e.mov(Reg8,  u8);

// LEA
e.lea(Reg64, const Mem&);      e.lea(Reg32, const Mem&);

// Arithmetic (same pattern for add/sub/and/or/xor/cmp/adc/sbb)
e.add(Reg64, Reg64);  e.add(Reg64, i32);  e.add(Reg64, const Mem&);
e.add(const Mem&, Reg64);  e.add(const Mem&, i32);

// Shifts (same pattern for shl/shr/sar/rol/ror/rcl/rcr)
e.shl(Reg64, u8 /*imm*/);      e.shl_cl(Reg64); // shift by CL

// Jumps
e.jmp(Label);    e.jmp(Reg64);    e.jmp(const Mem&);
e.call(Label);   e.call(Reg64);   e.call(const Mem&);
e.je(Label);     e.jne(Label);    e.jl(Label); // etc.
e.jcc(Cond::G, Label);           // generic conditional jump

// SSE2
e.addsd(RegXMM, RegXMM);         e.mulsd(RegXMM, RegXMM);
e.cvtsi2sd(RegXMM, Reg64);       e.cvttsd2si(Reg64, RegXMM);

// Frame helpers
e.prolog(local_bytes);           e.epilog();
e.win64_prolog(local_bytes);     e.win64_epilog();
```

### `Mem` operand builders

```cpp
qword_ptr(Reg64::RBP, -8)                       // [rbp-8]
dword_ptr(Reg64::RSP, 32)                        // [rsp+32]
byte_ptr (Reg64::RAX)                            // [rax]
Mem::make(Reg64::RBX, Reg64::RCX, Scale::x4)    // [rbx+rcx*4]
Mem::rip(disp32)                                 // [rip + disp32]
```

### `IATHelper`

```cpp
pe::PEBuilder peb;
peb.add_import("kernel32.dll", "WriteConsoleA");
peb.add_import("kernel32.dll", "ExitProcess");

EmitterX64 e;
IATHelper iat(e, peb);

u32 entry = e.current_offset();
e.mov(Reg64::RCX, (i64)-11);
iat.call("kernel32.dll", "GetStdHandle"); // emits FF 15 <placeholder>

auto image = peb.build(entry);
iat.patch(image);                          // fills all rel32 slots
pe::write_pe("out.exe", image);
```

### `FunctionBuilder`

```cpp
EmitterX64 e;
FunctionBuilder fn(e, /*local_bytes=*/64);

fn.prologue();
fn.alloc("counter", 8);         // allocates [rbp-8]
e.mov(fn.local_mem("counter"), (i32)0);
// ...
fn.epilogue();
```

---

## Encoding reference

| Prefix | Purpose | When emitted |
|---|---|---|
| `REX.W` (0x48+) | 64-bit operand size | All 64-bit instructions |
| `REX.R` | Extend ModRM.reg | dst/src register ≥ r8 |
| `REX.X` | Extend SIB.index | index register ≥ r8 |
| `REX.B` | Extend ModRM.rm / SIB.base / opcode reg | base/rm register ≥ r8 |
| `0x66` | 16-bit operand override | 16-bit instructions |
| `0xF2` | SSE2 scalar double prefix | `addsd`, `subsd`, `mulsd`, etc. |
| `0xF3` | SSE scalar single / REP prefix | `addss`, `rep stosb`, etc. |
| `0xF0` | LOCK prefix | `e.lock().add(...)` |

---

## Licence

MIT. See [LICENSE](LICENSE).
