#include "parser.hpp"
#include "errors.hpp"
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
    int line = peek().line;
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
    fn->line = line;

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
    int line = peek().line;
    std::unique_ptr<Stmt> res;

    if (match(TokenType::INT)) {
        std::string name = advance().text;
        std::unique_ptr<Expr> init = nullptr;
        if (match(TokenType::ASSIGN)) init = parse_expression();
        match(TokenType::SEMICOLON);
        res.reset(new VarDeclStmt(name, std::move(init)));
    }
    else if (match(TokenType::WHILE)) {
        match(TokenType::LPAREN);
        auto cond = parse_expression();
        match(TokenType::RPAREN);
        auto body = parse_statement();
        res.reset(new WhileStmt(std::move(cond), std::move(body)));
    }
    else if (match(TokenType::IF)) {
        match(TokenType::LPAREN);
        auto cond = parse_expression();
        match(TokenType::RPAREN);
        auto then_b = parse_statement();
        std::unique_ptr<Stmt> else_b = nullptr;
        if (match(TokenType::ELSE)) else_b = parse_statement();
        res.reset(new IfStmt(std::move(cond), std::move(then_b), std::move(else_b)));
    }
    else if (match(TokenType::RETURN)) {
        auto val = parse_expression();
        match(TokenType::SEMICOLON);
        res.reset(new ReturnStmt(std::move(val)));
    }
    else if (peek().type == TokenType::IDENTIFIER && tokens_[pos_+1].type == TokenType::ASSIGN) {
        std::string name = advance().text;
        advance(); // skip =
        auto val = parse_expression();
        match(TokenType::SEMICOLON);
        res.reset(new AssignStmt(name, std::move(val)));
    }
    else if (check(TokenType::LBRACE)) return parse_block();
    else if (peek().type == TokenType::IDENTIFIER && tokens_[pos_+1].type == TokenType::IDENTIFIER) {
        std::string name = peek().text;
        std::vector<std::string> suggestions = {"int", "while", "if", "return", "extern"};
        ErrorReporter::error(peek().line, "'" + name + "' does not name a type", name, suggestions);
        throw std::runtime_error("syntax error");
    }
    else {
        auto expr = parse_expression();
        match(TokenType::SEMICOLON);
        res.reset(new ExprStmt(std::move(expr)));
    }
    
    if (res) res->line = line;
    return res;
}

std::unique_ptr<Expr> Parser::parse_expression() {
    return parse_equality();
}

std::unique_ptr<Expr> Parser::parse_equality() {
    int line = peek().line;
    auto left = parse_comparison();
    while (match(TokenType::EQEQ) || match(TokenType::NEQ)) {
        TokenType op = tokens_[pos_-1].type;
        auto right = parse_comparison();
        auto next = std::unique_ptr<BinaryExpr>(new BinaryExpr(op, std::move(left), std::move(right)));
        next->line = line;
        left = std::move(next);
    }
    return left;
}

std::unique_ptr<Expr> Parser::parse_comparison() {
    int line = peek().line;
    auto left = parse_term();
    while (match(TokenType::LT) || match(TokenType::GT)) {
        TokenType op = tokens_[pos_-1].type;
        auto right = parse_term();
        auto next = std::unique_ptr<BinaryExpr>(new BinaryExpr(op, std::move(left), std::move(right)));
        next->line = line;
        left = std::move(next);
    }
    return left;
}

std::unique_ptr<Expr> Parser::parse_term() {
    int line = peek().line;
    auto left = parse_factor();
    while (match(TokenType::PLUS) || match(TokenType::MINUS)) {
        TokenType op = tokens_[pos_-1].type;
        auto right = parse_factor();
        auto next = std::unique_ptr<BinaryExpr>(new BinaryExpr(op, std::move(left), std::move(right)));
        next->line = line;
        left = std::move(next);
    }
    return left;
}

std::unique_ptr<Expr> Parser::parse_factor() {
    int line = peek().line;
    auto left = parse_primary();
    while (match(TokenType::STAR) || match(TokenType::SLASH)) {
        TokenType op = tokens_[pos_-1].type;
        auto right = parse_primary();
        auto next = std::unique_ptr<BinaryExpr>(new BinaryExpr(op, std::move(left), std::move(right)));
        next->line = line;
        left = std::move(next);
    }
    return left;
}

std::unique_ptr<Expr> Parser::parse_primary() {
    int line = peek().line;
    std::unique_ptr<Expr> res;

    if (match(TokenType::NUMBER)) {
        res.reset(new IntExpr(std::stoll(tokens_[pos_-1].text)));
    }
    else if (match(TokenType::STRING)) {
        res.reset(new StrExpr(tokens_[pos_-1].text));
    }
    else if (match(TokenType::IDENTIFIER)) {
        std::string name = tokens_[pos_-1].text;
        if (match(TokenType::LPAREN)) {
            std::vector<std::unique_ptr<Expr>> args;
            if (!check(TokenType::RPAREN)) {
                do {
                    args.push_back(parse_expression());
                } while (match(TokenType::COMMA));
            }
            match(TokenType::RPAREN);
            res.reset(new CallExpr(name, std::move(args)));
        } else {
            res.reset(new VarExpr(name));
        }
    }
    else if (match(TokenType::LPAREN)) {
        auto expr = parse_expression();
        match(TokenType::RPAREN);
        return expr;
    }
    else {
        std::vector<std::string> suggestions = {"int", "while", "if", "else", "return", "extern", "print_int", "print_str", "exit"};
        ErrorReporter::error(peek().line, "unexpected token '" + peek().text + "'", peek().text, suggestions);
        throw std::runtime_error("syntax error");
    }

    if (res) res->line = line;
    return res;
}

} // namespace tpp
