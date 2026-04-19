#include "parser.hpp"
#include <stdexcept>

namespace tpp {

std::vector<std::unique_ptr<Function>> Parser::parse() {
    std::vector<std::unique_ptr<Function>> program;
    while (!is_at_end()) {
        program.push_back(parse_function());
    }
    return program;
}

std::unique_ptr<Function> Parser::parse_function() {
    bool is_ext = match(TokenType::EXTERN);
    match(TokenType::INT); // return type (always int for now)
    
    std::string name = advance().text;
    match(TokenType::LPAREN);
    std::vector<std::string> params;
    if (!check(TokenType::RPAREN)) {
        do {
            match(TokenType::INT);
            params.push_back(advance().text);
        } while (match(TokenType::COMMA));
    }
    match(TokenType::RPAREN);
    
    auto fn = std::unique_ptr<Function>(new Function());
    fn->name = name;
    fn->params = params;
    fn->is_extern = is_ext;

    if (is_ext) {
        match(TokenType::SEMICOLON);
        fn->body = nullptr;
    } else {
        fn->body = parse_block();
    }
    return fn;
}

std::unique_ptr<BlockStmt> Parser::parse_block() {
    match(TokenType::LBRACE);
    std::vector<std::unique_ptr<Stmt>> statements;
    while (!check(TokenType::RBRACE) && !is_at_end()) {
        statements.push_back(parse_statement());
    }
    match(TokenType::RBRACE);
    return std::unique_ptr<BlockStmt>(new BlockStmt(std::move(statements)));
}

std::unique_ptr<Stmt> Parser::parse_statement() {
    if (match(TokenType::INT)) {
        std::string name = advance().text;
        std::unique_ptr<Expr> init = nullptr;
        if (match(TokenType::ASSIGN)) init = parse_expression();
        match(TokenType::SEMICOLON);
        return std::unique_ptr<Stmt>(new VarDeclStmt(name, std::move(init)));
    }
    if (match(TokenType::WHILE)) {
        match(TokenType::LPAREN);
        auto cond = parse_expression();
        match(TokenType::RPAREN);
        auto body = parse_statement();
        return std::unique_ptr<Stmt>(new WhileStmt(std::move(cond), std::move(body)));
    }
    if (match(TokenType::IF)) {
        match(TokenType::LPAREN);
        auto cond = parse_expression();
        match(TokenType::RPAREN);
        auto then_b = parse_statement();
        std::unique_ptr<Stmt> else_b = nullptr;
        if (match(TokenType::ELSE)) else_b = parse_statement();
        return std::unique_ptr<Stmt>(new IfStmt(std::move(cond), std::move(then_b), std::move(else_b)));
    }
    if (match(TokenType::RETURN)) {
        auto val = parse_expression();
        match(TokenType::SEMICOLON);
        return std::unique_ptr<Stmt>(new ReturnStmt(std::move(val)));
    }
    if (peek().type == TokenType::IDENTIFIER && tokens_[pos_+1].type == TokenType::ASSIGN) {
        std::string name = advance().text;
        advance(); // skip =
        auto val = parse_expression();
        match(TokenType::SEMICOLON);
        return std::unique_ptr<Stmt>(new AssignStmt(name, std::move(val)));
    }
    if (check(TokenType::LBRACE)) return parse_block();

    auto expr = parse_expression();
    match(TokenType::SEMICOLON);
    return std::unique_ptr<Stmt>(new ExprStmt(std::move(expr)));
}

std::unique_ptr<Expr> Parser::parse_expression() {
    return parse_equality();
}

std::unique_ptr<Expr> Parser::parse_equality() {
    auto left = parse_comparison();
    while (match(TokenType::EQEQ) || match(TokenType::NEQ)) {
        TokenType op = tokens_[pos_-1].type;
        auto right = parse_comparison();
        left = std::unique_ptr<Expr>(new BinaryExpr(op, std::move(left), std::move(right)));
    }
    return left;
}

std::unique_ptr<Expr> Parser::parse_comparison() {
    auto left = parse_term();
    while (match(TokenType::LT) || match(TokenType::GT)) {
        TokenType op = tokens_[pos_-1].type;
        auto right = parse_term();
        left = std::unique_ptr<Expr>(new BinaryExpr(op, std::move(left), std::move(right)));
    }
    return left;
}

std::unique_ptr<Expr> Parser::parse_term() {
    auto left = parse_factor();
    while (match(TokenType::PLUS) || match(TokenType::MINUS)) {
        TokenType op = tokens_[pos_-1].type;
        auto right = parse_factor();
        left = std::unique_ptr<Expr>(new BinaryExpr(op, std::move(left), std::move(right)));
    }
    return left;
}

std::unique_ptr<Expr> Parser::parse_factor() {
    auto left = parse_primary();
    while (match(TokenType::STAR) || match(TokenType::SLASH)) {
        TokenType op = tokens_[pos_-1].type;
        auto right = parse_primary();
        left = std::unique_ptr<Expr>(new BinaryExpr(op, std::move(left), std::move(right)));
    }
    return left;
}

std::unique_ptr<Expr> Parser::parse_primary() {
    if (match(TokenType::NUMBER)) return std::unique_ptr<Expr>(new IntExpr(std::stoll(tokens_[pos_-1].text)));
    if (match(TokenType::STRING)) return std::unique_ptr<Expr>(new StrExpr(tokens_[pos_-1].text));
    if (match(TokenType::IDENTIFIER)) {
        std::string name = tokens_[pos_-1].text;
        if (match(TokenType::LPAREN)) {
            std::vector<std::unique_ptr<Expr>> args;
            if (!check(TokenType::RPAREN)) {
                do {
                    args.push_back(parse_expression());
                } while (match(TokenType::COMMA));
            }
            match(TokenType::RPAREN);
            return std::unique_ptr<Expr>(new CallExpr(name, std::move(args)));
        }
        return std::unique_ptr<Expr>(new VarExpr(name));
    }
    if (match(TokenType::LPAREN)) {
        auto expr = parse_expression();
        match(TokenType::RPAREN);
        return expr;
    }
    throw std::runtime_error("Unexpected token: " + peek().text);
}

} // namespace tpp
