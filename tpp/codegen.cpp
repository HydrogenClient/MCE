#include "codegen.hpp"
#include "errors.hpp"
#include <stdexcept>
#include <set>

namespace tpp {

using namespace mce;
using namespace mce::reg;

std::vector<unsigned char> Codegen::compile(unsigned int& entry_offset) {
    peb_.import("kernel32.dll", "GetStdHandle")
        .import("kernel32.dll", "WriteFile")
        .import("kernel32.dll", "ExitProcess");

    iat_ = new mce::IATHelper(emitter_, peb_);

    declared_functions_.clear();
    collect_decls(program_, "");

    for (auto& decl : program_) {
        gen_decl(*decl, "");
    }

    auto it = function_offsets_.find("main");
    if (it == function_offsets_.end()) {
         ErrorReporter::error(1, "main function not found");
         throw std::runtime_error("semantic error");
    }
    entry_offset = it->second;

    peb_.subsystem = 3;
    auto& text = peb_.add_section(".text", mce::pe::SEC_CODE);
    text = emitter_.code();

    auto img = peb_.build(entry_offset);
    iat_->patch(img);
    
    delete iat_;
    return img;
}

void Codegen::gen_decl(const Decl& decl, std::string prefix) {
    if (auto fn = dynamic_cast<const Function*>(&decl)) {
        if (!fn->is_extern) {
            std::string full_name = prefix.empty() ? fn->name : (prefix + "::" + fn->name);
            function_offsets_[full_name] = emitter_.current_offset();
            gen_function(*fn);
        }
    }
    else if (auto sd = dynamic_cast<const StmtDecl*>(&decl)) {
        gen_stmt(*sd->stmt, prefix);
    }
    else if (auto nd = dynamic_cast<const NamespaceDecl*>(&decl)) {
        std::string new_prefix = prefix.empty() ? nd->name : (prefix + "::" + nd->name);
        for (auto& member : nd->members) {
            gen_decl(*member, new_prefix);
        }
    }
}

void Codegen::collect_decls(const std::vector<std::unique_ptr<Decl>>& decls, std::string prefix) {
    for (auto& decl : decls) {
        if (auto fn = dynamic_cast<const Function*>(decl.get())) {
            std::string full_name = prefix.empty() ? fn->name : (prefix + "::" + fn->name);
            declared_functions_.insert(full_name);
        } else if (auto nd = dynamic_cast<const NamespaceDecl*>(decl.get())) {
            std::string sub = prefix.empty() ? nd->name : (prefix + "::" + nd->name);
            collect_decls(nd->members, sub);
        }
    }
}

void Codegen::gen_function(const Function& fn) {
    current_fn_ = new mce::FunctionBuilder(emitter_, 256); 
    locals_.clear();

    current_fn_->prologue();

    static const mce::Reg64 arg_regs[] = {rcx, rdx, r8, r9};
    for (size_t i = 0; i < fn.params.size() && i < 4; i++) {
        current_fn_->alloc(fn.params[i], 8);
        emitter_.mov(current_fn_->local_mem(fn.params[i]), arg_regs[i]);
    }

    if (fn.body) {
        for (auto& stmt : fn.body->statements) {
            gen_stmt(*stmt, "");
        }
    }

    current_fn_->epilogue();
    delete current_fn_;
    current_fn_ = nullptr;
}

void Codegen::gen_stmt(const Stmt& stmt, std::string prefix) {
    if (auto s = dynamic_cast<const VarDeclStmt*>(&stmt)) {
        if (current_fn_) {
            current_fn_->alloc(s->name, 8);
            if (s->init) {
                gen_expr(*s->init);
                emitter_.mov(current_fn_->local_mem(s->name), rax);
            }
        } else {
            // Global!
            std::string full_name = prefix.empty() ? s->name : (prefix + "::" + s->name);
            if (s->init) {
                global_vars_[full_name] = eval_const_expr(*s->init);
            } else {
                global_vars_[full_name] = 0;
            }
        }
    }
    else if (auto s = dynamic_cast<const AssignStmt*>(&stmt)) {
        gen_expr(*s->value);
        if (current_fn_) {
            try {
                emitter_.mov(current_fn_->local_mem(s->name), rax);
            } catch (...) {
                std::vector<std::string> sug;
                for (auto const& x : current_fn_->locals()) sug.push_back(x.first);
                ErrorReporter::error(stmt.line, "undefined variable '" + s->name + "'", s->name, sug);
                throw std::runtime_error("semantic error");
            }
        }
    }
    else if (auto s = dynamic_cast<const ReturnStmt*>(&stmt)) {
        gen_expr(*s->value);
        current_fn_->epilogue();
    }
    else if (auto s = dynamic_cast<const WhileStmt*>(&stmt)) {
        auto start = emitter_.make_label();
        auto end = emitter_.make_label();
        emitter_.bind(start);
        gen_expr(*s->cond);
        emitter_.test(rax, rax);
        emitter_.jz(end);
        gen_stmt(*s->body, prefix);
        emitter_.jmp(start);
        emitter_.bind(end);
    }
    else if (auto s = dynamic_cast<const IfStmt*>(&stmt)) {
        auto else_lbl = emitter_.make_label();
        auto end_lbl = emitter_.make_label();
        gen_expr(*s->cond);
        emitter_.test(rax, rax);
        emitter_.jz(else_lbl);
        gen_stmt(*s->then_branch, prefix);
        emitter_.jmp(end_lbl);
        emitter_.bind(else_lbl);
        if (s->else_branch) gen_stmt(*s->else_branch, prefix);
        emitter_.bind(end_lbl);
    }
    else if (auto s = dynamic_cast<const BlockStmt*>(&stmt)) {
        for (auto& sub : s->statements) gen_stmt(*sub, prefix);
    }
    else if (auto s = dynamic_cast<const ExprStmt*>(&stmt)) {
        gen_expr(*s->expr);
    }
    else if (auto s = dynamic_cast<const StaticAssertStmt*>(&stmt)) {
        // Compile-time evaluation
        auto val = eval_const_expr(*s->cond);
        if (val == 0) {
            ErrorReporter::error(s->line, "static_assert failed: " + s->message);
            throw std::runtime_error("semantic error");
        }
    }
    else if (auto s = dynamic_cast<const EnumStmt*>(&stmt)) {
        std::map<std::string, long long> vals;
        for (auto& p : s->values) vals[p.first] = p.second;
        std::string full_name = prefix.empty() ? s->name : (prefix + "::" + s->name);
        enum_values_[full_name] = vals;
    }
    else if (auto s = dynamic_cast<const TypeAliasStmt*>(&stmt)) {
        // No-op in this simple compiler as all types are functionally the same
    }
}

void Codegen::gen_expr(const Expr& expr) {
    if (auto e = dynamic_cast<const IntExpr*>(&expr)) {
        emitter_.mov(rax, (long long)e->value);
    }
    else if (auto e = dynamic_cast<const VarExpr*>(&expr)) {
        try {
            emitter_.mov(rax, current_fn_->local_mem(e->name));
        } catch (...) {
            std::vector<std::string> sug;
            for (auto const& x : current_fn_->locals()) sug.push_back(x.first);
            ErrorReporter::error(expr.line, "undefined variable '" + e->name + "'", e->name, sug);
            throw std::runtime_error("semantic error");
        }
    }
    else if (auto e = dynamic_cast<const ScopedVarExpr*>(&expr)) {
        std::string full_name = e->scope + "::" + e->name;
        if (e->scope == "std" && e->name == "cout") {
            if (global_vars_.count(full_name)) {
                emitter_.mov(rax, (i64)-42); // magic cout id
            } else {
                ErrorReporter::error(expr.line, "undefined scoped member 'std::cout'. Did you forget '#include <io.h>'?");
                throw std::runtime_error("semantic error");
            }
        }
        else if (global_vars_.count(full_name)) {
            emitter_.mov(rax, global_vars_[full_name]);
        }
        else if (enum_values_.count(e->scope) && enum_values_[e->scope].count(e->name)) {
            emitter_.mov(rax, enum_values_[e->scope][e->name]);
        } else {
            ErrorReporter::error(expr.line, "undefined scoped member '" + e->scope + "::" + e->name + "'");
            throw std::runtime_error("semantic error");
        }
    }
    else if (auto e = dynamic_cast<const NullExpr*>(&expr)) {
        emitter_.mov(rax, (long long)0);
    }
    else if (auto e = dynamic_cast<const BinaryExpr*>(&expr)) {
        if (e->op == TokenType::LSH) {
            gen_expr(*e->left);
            emitter_.cmp(rax, (i64)-42);
            auto not_cout = emitter_.make_label();
            emitter_.jne(not_cout);
            
            // It IS cout!
            // Right side evaluates to value to print
            // We need to check if it's a string or int? 
            // In T++ strings are handled by print_str and ints by print_int.
            // Let's assume right side is either.
            
            // This is tricky because T++ doesn't have runtime types.
            // But we can check if it's a StrExpr.
            if (auto str = dynamic_cast<const StrExpr*>(e->right.get())) {
                // Call print_str logic (simulated by helper)
                u32 off = iat_->embed_skipped_str(str->value.c_str());
                emitter_.mov(rcx, (i64)-11);
                iat_->call("kernel32.dll", "GetStdHandle");
                emitter_.mov(rbx, rax);
                emitter_.mov(rcx, rbx);
                iat_->lea_rip_rdx(off);
                emitter_.mov(r8, (i64)str->value.size());
                emitter_.lea(r9, mce::qword_ptr(rsp, 40));
                emitter_.mov(mce::qword_ptr(rsp, 32), (i32)0);
                iat_->call("kernel32.dll", "WriteFile");
            } else {
                // Assume it's an int
                gen_expr(*e->right);
                emitter_.push(rax); // value to print
                emitter_.mov(rcx, (i64)-11); 
                iat_->call("kernel32.dll", "GetStdHandle");
                emitter_.mov(rbx, rax); 
                emitter_.pop(rax); 
                emitter_.lea(rsi, mce::qword_ptr(rsp, 64)); 
                emitter_.mov(byte_ptr(rsi, 15), (u8)'\n');
                emitter_.mov(byte_ptr(rsi, 14), (u8)'\r');
                emitter_.mov(rdi, (i64)13);
                auto lp = emitter_.make_label();
                emitter_.bind(lp);
                emitter_.xor_(edx, edx); emitter_.mov(r10, (i64)10); emitter_.idiv(r10);
                emitter_.add(dl, (u8)'0'); emitter_.mov(mce::byte_ptr(rsi, rdi, mce::Scale::x1), dl);
                emitter_.dec(rdi);
                emitter_.test(rax, rax);
                emitter_.jnz(lp);
                emitter_.inc(rdi);
                emitter_.mov(rcx, rbx);
                emitter_.lea(rdx, mce::qword_ptr(rsi, rdi, mce::Scale::x1));
                emitter_.mov(r8, (i64)16); emitter_.sub(r8, rdi);
                emitter_.lea(r9, mce::qword_ptr(rsp, 100)); 
                emitter_.mov(mce::qword_ptr(rsp, 32), (i32)0);
                iat_->call("kernel32.dll", "WriteFile");
            }
            
            emitter_.mov(rax, (i64)-42); // Return cout again
            auto end_lbl = emitter_.make_label();
            emitter_.jmp(end_lbl);
            
            emitter_.bind(not_cout);
            // Normal shift logic if we had it, but we don't really support it yet
            // Just returning 0 for now if not cout
            emitter_.xor_(rax, rax);
            
            emitter_.bind(end_lbl);
            return;
        }

        gen_expr(*e->right);
        emitter_.push(rax);
        gen_expr(*e->left);
        emitter_.pop(rcx); 
        
        switch (e->op) {
            case TokenType::PLUS:  emitter_.add(rax, rcx); break;
            case TokenType::MINUS: emitter_.sub(rax, rcx); break;
            case TokenType::STAR:  emitter_.imul(rax, rcx); break;
            case TokenType::SLASH: emitter_.xor_(rdx, rdx); emitter_.idiv(rcx); break;
            case TokenType::LT:
            case TokenType::GT:
            case TokenType::EQEQ:
            case TokenType::NEQ: {
                emitter_.cmp(rax, rcx);
                mce::Cond cond;
                if (e->op == TokenType::LT) cond = mce::Cond::L;
                else if (e->op == TokenType::GT) cond = mce::Cond::G;
                else if (e->op == TokenType::EQEQ) cond = mce::Cond::E;
                else cond = mce::Cond::NE;
                
                emitter_.setcc(cond, al);
                emitter_.movzx(rax, al);
                break;
            }
            default: break;
        }
    }
    else if (auto e = dynamic_cast<const CallExpr*>(&expr)) {
        bool is_declared = declared_functions_.count(e->callee) > 0;
        
        if (e->callee == "print_int" || e->callee == "print_str" || e->callee == "exit") {
            if (!is_declared) {
                ErrorReporter::error(expr.line, "undefined reference to '" + e->callee + "'", e->callee);
                std::cerr << "\033[1;36mnote: \033[0mDid you mean '\033[1;32m#include <io.h>\033[0m'?\n";
                throw std::runtime_error("semantic error");
            }
            
            if (e->callee == "print_int") {
                gen_expr(*e->args[0]); 
                emitter_.push(rax); 
                emitter_.mov(rcx, (i64)-11); 
                iat_->call("kernel32.dll", "GetStdHandle");
                emitter_.mov(rbx, rax); 
                emitter_.pop(rax); 
                emitter_.lea(rsi, mce::qword_ptr(rsp, 64)); 
                emitter_.mov(byte_ptr(rsi, 15), (u8)'\n');
                emitter_.mov(byte_ptr(rsi, 14), (u8)'\r');
                emitter_.mov(rdi, (i64)13);
                auto lp = emitter_.make_label();
                emitter_.bind(lp);
                emitter_.xor_(edx, edx); emitter_.mov(r10, (i64)10); emitter_.idiv(r10);
                emitter_.add(dl, (u8)'0'); emitter_.mov(mce::byte_ptr(rsi, rdi, mce::Scale::x1), dl);
                emitter_.dec(rdi);
                emitter_.test(rax, rax);
                emitter_.jnz(lp);
                emitter_.inc(rdi);
                emitter_.mov(rcx, rbx);
                emitter_.lea(rdx, mce::qword_ptr(rsi, rdi, mce::Scale::x1));
                emitter_.mov(r8, (i64)16); emitter_.sub(r8, rdi);
                emitter_.lea(r9, mce::qword_ptr(rsp, 100)); 
                emitter_.mov(mce::qword_ptr(rsp, 32), (i32)0);
                iat_->call("kernel32.dll", "WriteFile");
                emitter_.mov(rax, (i64)0);
            }
            else if (e->callee == "print_str") {
                auto s = dynamic_cast<const StrExpr*>(e->args[0].get());
                u32 off = iat_->embed_skipped_str(s->value.c_str());
                emitter_.mov(rcx, (i64)-11);
                iat_->call("kernel32.dll", "GetStdHandle");
                emitter_.mov(rbx, rax);
                emitter_.mov(rcx, rbx);
                iat_->lea_rip_rdx(off);
                emitter_.mov(r8, (i64)s->value.size());
                emitter_.lea(r9, mce::qword_ptr(rsp, 40));
                emitter_.mov(mce::qword_ptr(rsp, 32), (i32)0);
                iat_->call("kernel32.dll", "WriteFile");
                emitter_.mov(rax, (i64)0);
            }
            else if (e->callee == "exit") {
                gen_expr(*e->args[0]);
                emitter_.mov(rcx, rax);
                iat_->call("kernel32.dll", "ExitProcess");
            }
        }
        else {
            auto it = function_offsets_.find(e->callee);
            if (it != function_offsets_.end()) {
                static const mce::Reg64 arg_regs[] = {rcx, rdx, r8, r9};
                for (size_t i = 0; i < e->args.size() && i < 4; i++) {
                    gen_expr(*e->args[i]);
                    emitter_.mov(arg_regs[i], rax);
                }
                unsigned int target = it->second;
                unsigned int cur = emitter_.current_offset();
                emitter_.raw(0xE8); 
                emitter_.raw({0,0,0,0});
                int rel = (int)target - (int)(cur + 5);
                auto& b = emitter_.code();
                b[cur+1]=u8(rel); b[cur+2]=u8(rel>>8); b[cur+3]=u8(rel>>16); b[cur+4]=u8(rel>>24);
            } else {
                std::vector<std::string> sug = {"print_int", "print_str", "exit"};
                for (auto const& x : function_offsets_) sug.push_back(x.first);
                ErrorReporter::error(expr.line, "undefined function '" + e->callee + "'", e->callee, sug);
                throw std::runtime_error("semantic error");
            }
        }
    }
}

long long Codegen::eval_const_expr(const Expr& expr) {
    if (auto e = dynamic_cast<const IntExpr*>(&expr)) return e->value;
    if (auto e = dynamic_cast<const BinaryExpr*>(&expr)) {
        long long l = eval_const_expr(*e->left);
        long long r = eval_const_expr(*e->right);
        switch (e->op) {
            case TokenType::PLUS: return l + r;
            case TokenType::MINUS: return l - r;
            case TokenType::STAR: return l * r;
            case TokenType::SLASH: return r != 0 ? l / r : 0;
            case TokenType::LT: return l < r;
            case TokenType::GT: return l > r;
            case TokenType::EQEQ: return l == r;
            case TokenType::NEQ: return l != r;
            default: return 0;
        }
    }
    if (auto e = dynamic_cast<const ScopedVarExpr*>(&expr)) {
        if (enum_values_.count(e->scope) && enum_values_[e->scope].count(e->name)) {
            return enum_values_[e->scope][e->name];
        }
    }
    return 0;
}

} // namespace tpp
