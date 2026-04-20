#pragma once
#include "lexer.hpp"
#include <memory>
#include <vector>
#include <string>
#include <set>

namespace tpp {

struct Expr {
    int line = 0;
    virtual ~Expr() = default;
};

struct IntExpr : Expr {
    long long value;
    explicit IntExpr(long long v) : value(v) {}
};

struct StrExpr : Expr {
    std::string value;
    explicit StrExpr(std::string v) : value(v) {}
};

struct VarExpr : Expr {
    std::string name;
    explicit VarExpr(std::string n) : name(n) {}
};

struct ScopedVarExpr : Expr {
    std::string scope;
    std::string name;
    ScopedVarExpr(std::string s, std::string n) : scope(s), name(n) {}
};

struct NullExpr : Expr {
    NullExpr() = default;
};

struct BinaryExpr : Expr {
    TokenType op;
    std::unique_ptr<Expr> left, right;
    BinaryExpr(TokenType o, std::unique_ptr<Expr> l, std::unique_ptr<Expr> r)
        : op(o), left(std::move(l)), right(std::move(r)) {}
};

struct CallExpr : Expr {
    std::string callee;
    std::vector<std::unique_ptr<Expr>> args;
    CallExpr(std::string c, std::vector<std::unique_ptr<Expr>> a)
        : callee(c), args(std::move(a)) {}
};

struct Stmt {
    int line = 0;
    virtual ~Stmt() = default;
};

struct VarDeclStmt : Stmt {
    std::string name;
    std::unique_ptr<Expr> init;
    VarDeclStmt(std::string n, std::unique_ptr<Expr> i)
        : name(n), init(std::move(i)) {}
};

struct AssignStmt : Stmt {
    std::string name;
    std::unique_ptr<Expr> value;
    AssignStmt(std::string n, std::unique_ptr<Expr> v)
        : name(n), value(std::move(v)) {}
};

struct IfStmt : Stmt {
    std::unique_ptr<Expr> cond;
    std::unique_ptr<Stmt> then_branch;
    std::unique_ptr<Stmt> else_branch;
    IfStmt(std::unique_ptr<Expr> c, std::unique_ptr<Stmt> t, std::unique_ptr<Stmt> e)
        : cond(std::move(c)), then_branch(std::move(t)), else_branch(std::move(e)) {}
};

struct WhileStmt : Stmt {
    std::unique_ptr<Expr> cond;
    std::unique_ptr<Stmt> body;
    WhileStmt(std::unique_ptr<Expr> c, std::unique_ptr<Stmt> b)
        : cond(std::move(c)), body(std::move(b)) {}
};

struct BlockStmt : Stmt {
    std::vector<std::unique_ptr<Stmt>> statements;
    explicit BlockStmt(std::vector<std::unique_ptr<Stmt>> s) : statements(std::move(s)) {}
};

struct ExprStmt : Stmt {
    std::unique_ptr<Expr> expr;
    explicit ExprStmt(std::unique_ptr<Expr> e) : expr(std::move(e)) {}
};

struct ReturnStmt : Stmt {
    std::unique_ptr<Expr> value;
    explicit ReturnStmt(std::unique_ptr<Expr> v) : value(std::move(v)) {}
};

struct StaticAssertStmt : Stmt {
    std::unique_ptr<Expr> cond;
    std::string message;
    StaticAssertStmt(std::unique_ptr<Expr> c, std::string m)
        : cond(std::move(c)), message(std::move(m)) {}
};

struct TypeAliasStmt : Stmt {
    std::string name;
    TypeAliasStmt(std::string n) : name(n) {}
};

struct EnumStmt : Stmt {
    std::string name;
    std::vector<std::pair<std::string, long long>> values;
    EnumStmt(std::string n, std::vector<std::pair<std::string, long long>> v)
        : name(n), values(std::move(v)) {}
};

struct Decl {
    virtual ~Decl() = default;
};

struct Function : Decl {
    std::string name;
    std::vector<std::string> params;
    std::unique_ptr<BlockStmt> body;
    bool is_extern = false;
    int line = 0;
};

struct StmtDecl : Decl {
    std::unique_ptr<Stmt> stmt;
    explicit StmtDecl(std::unique_ptr<Stmt> s) : stmt(std::move(s)) {}
};

struct NamespaceDecl : Decl {
    std::string name;
    std::vector<std::unique_ptr<Decl>> members;
    NamespaceDecl(std::string n, std::vector<std::unique_ptr<Decl>> m)
        : name(n), members(std::move(m)) {}
};

class Parser {
public:
    explicit Parser(const std::vector<Token>& tokens) : tokens_(tokens) {}
    std::vector<std::unique_ptr<Decl>> parse();

private:
    std::unique_ptr<Decl> parse_decl();
    std::unique_ptr<Function> parse_function();
    std::unique_ptr<BlockStmt> parse_block();
    std::unique_ptr<Stmt> parse_statement();
    std::unique_ptr<Expr> parse_expression();
    std::unique_ptr<Expr> parse_equality();
    std::unique_ptr<Expr> parse_comparison();
    std::unique_ptr<Expr> parse_shift();
    std::unique_ptr<Expr> parse_term();
    std::unique_ptr<Expr> parse_factor();
    std::unique_ptr<Expr> parse_primary();

    const Token& peek() const { return tokens_[pos_]; }
    const Token& advance() { if (!is_at_end()) pos_++; return tokens_[pos_-1]; }
    bool check(TokenType type) const { return !is_at_end() && peek().type == type; }
    bool match(TokenType type) { if (check(type)) { advance(); return true; } return false; }
    bool is_at_end() const { return peek().type == TokenType::EOF_TOKEN; }

    std::vector<Token> tokens_;
    size_t pos_ = 0;
    std::set<std::string> types_ = {"int", "auto", "long long"};
};

} // namespace tpp
