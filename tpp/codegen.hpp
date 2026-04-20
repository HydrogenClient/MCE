#pragma once
#include "parser.hpp"
#include <MCE/emitterx64>
#include <map>
#include <set>

namespace tpp {

class Codegen {
public:
    explicit Codegen(const std::vector<std::unique_ptr<Decl>>& program)
        : program_(program) {}

    std::vector<unsigned char> compile(unsigned int& entry_offset);

private:
    void gen_function(const Function& fn);
    void gen_decl(const Decl& decl, std::string prefix);
    void collect_decls(const std::vector<std::unique_ptr<Decl>>& decls, std::string prefix);
    void gen_stmt(const Stmt& stmt, std::string prefix);
    void gen_expr(const Expr& expr);
    long long eval_const_expr(const Expr& expr);

    const std::vector<std::unique_ptr<Decl>>& program_;
    
    std::map<std::string, std::map<std::string, long long>> enum_values_;
    std::map<std::string, long long> global_vars_;
    
    mce::pe::PEBuilder peb_;
    mce::EmitterX64 emitter_;
    mce::IATHelper* iat_ = nullptr;
    mce::FunctionBuilder* current_fn_ = nullptr;
    
    std::map<std::string, mce::LocalVar> locals_;
    std::map<std::string, unsigned int> function_offsets_;
    std::set<std::string> declared_functions_;
};

} // namespace tpp
