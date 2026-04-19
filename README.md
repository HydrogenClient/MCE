# Tiny++ (T++) & MCE (Machine Code Emitter)

A header-only, from-scratch x86-64 machine code emitter and a lightweight C-like compiler frontend (T++), written in pure C++ for Windows.

---

## Project Structure

The project is divided into two main components:

### 1. [MCE (Machine Code Emitter)](mce/)
A powerful, header-only backend for emitting x64 machine code and generating valid Windows PE executables.

- **Registers**: Full support for GP registers (`RAX`-`R15`) and SSE (`XMM0`-`XMM15`).
- **Instructions**: MOV, LEA, Arithmetic, Shifts, SSE2, Logic, Control Flow, etc.
- **PE Generation**: Automated construction of `.idata` sections (IDT, ILT, IAT) and PE header layout.
- **Helpers**: 
  - `FunctionBuilder`: Manages stack frames and named local variables.
  - `IATHelper`: Handles cross-section patching and Win64 API calls.

### 2. [T++ Compiler (Tiny++)](tpp/)
A lightweight C-like frontend that demonstrates the power of MCE.

- **Types**: 64-bit integers (`int`).
- **Control Flow**: `if`, `else`, `while`, `return`.
- **Built-in Functions**: `print_int(n)`, `print_str("text")`, `exit(code)`.
- **Diagnostics**: User-friendly, `g++`-style error reporting with code snippets and "did you mean?" suggestions.

---

## Getting Started

### Prerequisites
- **CMake** ≥ 3.16
- **GCC (MinGW)**, **Clang**, or **MSVC**
- **Windows** (Target OS for the generated binaries)

### Installation & Build

```powershell
# Clone the repository
git clone https://github.com/HydrogenClient/MCE.git
cd MCE

# Configure and Build
cmake -B build
cmake --build build --config Release
```

The build process will generate:
- `build/tpp/tpp.exe`: The T++ Compiler.
- `build/mce/examples/`: MCE library usage examples.
- `build/mce/tests/`: Unit tests for the emitter.

### Compiling T++ Code
Create a file named `sample.tpp`:
```cpp
int main() {
    print_str("Counting to 5...\n");
    int i = 1;
    while (i < 6) {
        print_int(i);
        i = i + 1;
    }
    return 0;
}
```

Compile it using T++:
```powershell
.\build\tpp\tpp.exe sample.tpp -o app.exe
.\app.exe
```

---

## Directory Organization

- `mce/`: Core backend and library.
  - `include/MCE/`: Header-only sources for `EmitterX64`, `PEBuilder`, etc.
  - `examples/`: Raw MCE usage (manual machine code generation).
  - `tests/`: 114+ unit tests for byte-exact instruction encoding.
- `tpp/`: Frontend compiler.
  - `lexer.cpp`, `parser.cpp`, `codegen.cpp`: Compiler implementation.
  - `main.cpp`: CLI interface.
  - `errors.cpp`: Colorized diagnostics engine.

---

## License
MIT. See [LICENSE](LICENSE) for details.
