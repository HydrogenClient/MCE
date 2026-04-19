#pragma once
#include "parser.hpp"
#include <MCE/emitterx64>
#include <map>

namespace tpp {

class Codegen {
public:
    explicit Codegen(const std::vector<std::unique_ptr<Function>>& program)
        : program_(program) {}

    std::vector<unsigned char> compile(unsigned int& entry_offset);

private:
    void gen_function(const Function& fn);
    void gen_stmt(const Stmt& stmt);
    void gen_expr(const Expr& expr);

    const std::vector<std::unique_ptr<Function>>& program_;
    
    mce::pe::PEBuilder peb_;
    mce::EmitterX64 emitter_;
    mce::IATHelper* iat_ = nullptr;
    mce::FunctionBuilder* current_fn_ = nullptr;
    
    std::map<std::string, mce::LocalVar> locals_;
    std::map<std::string, unsigned int> function_offsets_;
};

} // namespace tpp
