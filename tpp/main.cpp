#include "lexer.hpp"
#include "parser.hpp"
#include "codegen.hpp"
#include <iostream>
#include <fstream>
#include <sstream>

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cout << "Tiny++ Compiler (T++) v1.0\n";
        std::cout << "Usage: tpp <source.tpp> [-o <output.exe>]\n";
        return 1;
    }

    std::string input_file = argv[1];
    std::string output_file = "a.exe";
    for (int i = 2; i < argc; i++) {
        if (std::string(argv[i]) == "-o" && i + 1 < argc) {
            output_file = argv[i+1];
        }
    }

    std::ifstream f(input_file);
    if (!f) {
        std::cerr << "Error: Could not open input file " << input_file << "\n";
        return 1;
    }

    std::stringstream ss;
    ss << f.rdbuf();
    std::string source = ss.str();

    try {
        tpp::Lexer lexer(source);
        auto tokens = lexer.tokenize();

        tpp::Parser parser(tokens);
        auto program = parser.parse();

        tpp::Codegen codegen(program);
        unsigned int entry;
        auto image = codegen.compile(entry);

        std::ofstream out(output_file, std::ios::binary);
        out.write(reinterpret_cast<const char*>(image.data()), image.size());
        
        std::cout << "Successfully compiled " << input_file << " to " << output_file << "\n";
    }
    catch (const std::exception& e) {
        std::cerr << "Compiler Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
