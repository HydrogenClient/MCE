#include "parser.hpp"
#include "errors.hpp"
#include <stdexcept>

namespace tpp {

std::vector<std::unique_ptr<Decl>> Parser::parse() {
    std::vector<std::unique_ptr<Decl>> program;
    while (!is_at_end()) {
        if (auto d = parse_decl()) program.push_back(std::move(d));
    }
    return program;
}

std::unique_ptr<Decl> Parser::parse_decl() {
    if (match(TokenType::SEMICOLON)) return nullptr;
    
    if (match(TokenType::NAMESPACE)) {
        std::string name = advance().text;
        match(TokenType::LBRACE);
        std::vector<std::unique_ptr<Decl>> members;
        while (!check(TokenType::RBRACE) && !is_at_end()) {
            if (auto d = parse_decl()) members.push_back(std::move(d));
        }
        match(TokenType::RBRACE);
        return std::unique_ptr<Decl>(new NamespaceDecl(name, std::move(members)));
    }
    
    if (match(TokenType::STRUCT)) {
        std::string name = advance().text;
        match(TokenType::LBRACE);
        std::vector<StructDecl::Member> m;
        while (!check(TokenType::RBRACE) && !is_at_end()) {
            std::string type = advance().text;
            std::string member_name = advance().text;
            match(TokenType::SEMICOLON);
            m.push_back({type, member_name});
        }
        match(TokenType::RBRACE);
        match(TokenType::SEMICOLON);
        types_.insert(name);
        return std::unique_ptr<Decl>(new StructDecl(name, std::move(m)));
    }
    
    if (check(TokenType::ENUM) || check(TokenType::USING) || check(TokenType::STATIC_ASSERT)) {
        return std::unique_ptr<Decl>(new StmtDecl(parse_statement()));
    }
    
    // Check if function or var
    if (pos_ + 2 < tokens_.size() && tokens_[pos_+2].type == TokenType::LPAREN) {
        return parse_function();
    } else if (pos_ + 1 < tokens_.size() && tokens_[pos_].type == TokenType::EXTERN && pos_ + 3 < tokens_.size() && tokens_[pos_+3].type == TokenType::LPAREN) {
        return parse_function();
    } else {
        return std::unique_ptr<Decl>(new StmtDecl(parse_statement()));
    }
}

std::unique_ptr<Function> Parser::parse_function() {
    int line = peek().line;
    bool is_ext = match(TokenType::EXTERN);
    if (types_.count(peek().text)) advance();
    else if (match(TokenType::DECLTYPE)) {
        match(TokenType::LPAREN);
        parse_expression();
        match(TokenType::RPAREN);
    }
    else match(TokenType::INT); // fallback
    
    std::string name = advance().text;
    match(TokenType::LPAREN);
    std::vector<std::string> params;
    if (!check(TokenType::RPAREN)) {
        do {
            if (types_.count(peek().text)) advance();
            else match(TokenType::INT);
            params.push_back(advance().text);
        } while (match(TokenType::COMMA));
    }
    match(TokenType::RPAREN);

    if (match(TokenType::ARROW)) {
        if (types_.count(peek().text)) advance();
        else if (match(TokenType::DECLTYPE)) {
            match(TokenType::LPAREN);
            parse_expression();
            match(TokenType::RPAREN);
        }
        else if (check(TokenType::INT)) advance();
    }

    while (match(TokenType::FINAL) || match(TokenType::OVERRIDE));
    
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

    bool is_constexpr = match(TokenType::CONSTEXPR);
    if (is_constexpr || (peek().type == TokenType::IDENTIFIER && types_.count(peek().text)) || check(TokenType::INT) || check(TokenType::AUTO) || check(TokenType::DECLTYPE) || check(TokenType::LONG)) {
        std::string type_name = "int";
        if (is_constexpr) {
             if (types_.count(peek().text)) type_name = advance().text;
             else if (match(TokenType::DECLTYPE)) {
                  match(TokenType::LPAREN);
                  parse_expression();
                  match(TokenType::RPAREN);
                  type_name = "decltype";
             }
             else { match(TokenType::INT); type_name = "int"; }
        } else if (match(TokenType::DECLTYPE)) {
             match(TokenType::LPAREN);
             parse_expression();
             match(TokenType::RPAREN);
             type_name = "decltype";
        } else if (match(TokenType::LONG)) {
             type_name = "long";
             if (match(TokenType::LONG)) type_name = "long long";
        } else {
             type_name = advance().text;
        }
        std::string name = advance().text;
        std::unique_ptr<Expr> init = nullptr;
        if (match(TokenType::ASSIGN)) init = parse_expression();
        match(TokenType::SEMICOLON);
        res.reset(new VarDeclStmt(type_name, name, std::move(init)));
    }
    else if (match(TokenType::STATIC_ASSERT)) {
        match(TokenType::LPAREN);
        auto cond = parse_expression();
        match(TokenType::COMMA);
        std::string msg = advance().text;
        match(TokenType::RPAREN);
        match(TokenType::SEMICOLON);
        res.reset(new StaticAssertStmt(std::move(cond), msg));
    }
    else if (match(TokenType::USING)) {
        std::string name = advance().text;
        match(TokenType::ASSIGN);
        if (types_.count(peek().text)) advance();
        else match(TokenType::INT);
        match(TokenType::SEMICOLON);
        types_.insert(name);
        res.reset(new TypeAliasStmt(name));
    }
    else if (match(TokenType::ENUM)) {
        match(TokenType::CLASS);
        std::string name = advance().text;
        match(TokenType::LBRACE);
        std::vector<std::pair<std::string, long long>> values;
        long long current_val = 0;
        while (!check(TokenType::RBRACE) && !is_at_end()) {
            std::string key = advance().text;
            if (match(TokenType::ASSIGN)) {
                current_val = std::stoll(advance().text);
            }
            values.push_back({key, current_val++});
            if (!match(TokenType::COMMA)) break;
        }
        match(TokenType::RBRACE);
        match(TokenType::SEMICOLON);
        types_.insert(name);
        res.reset(new EnumStmt(name, std::move(values)));
    }
    else if (match(TokenType::WHILE)) {
        match(TokenType::LPAREN);
        auto cond = parse_expression();
        match(TokenType::RPAREN);
        auto body = parse_statement();
        res.reset(new WhileStmt(std::move(cond), std::move(body)));
    }
    else if (match(TokenType::FOR)) {
        match(TokenType::LPAREN);
        std::unique_ptr<Stmt> init = nullptr;
        if (!match(TokenType::SEMICOLON)) {
            init = parse_statement();
        }
        std::unique_ptr<Expr> cond = nullptr;
        if (!match(TokenType::SEMICOLON)) {
            cond = parse_expression();
            match(TokenType::SEMICOLON);
        }
        std::unique_ptr<Expr> inc = nullptr;
        if (!match(TokenType::RPAREN)) {
            inc = parse_expression();
            match(TokenType::RPAREN);
        }
        auto body = parse_statement();
        res.reset(new ForStmt(std::move(init), std::move(cond), std::move(inc), std::move(body)));
    }
    else if (match(TokenType::DO)) {
        auto body = parse_statement();
        match(TokenType::WHILE);
        match(TokenType::LPAREN);
        auto cond = parse_expression();
        match(TokenType::RPAREN);
        match(TokenType::SEMICOLON);
        res.reset(new DoWhileStmt(std::move(body), std::move(cond)));
    }
    else if (match(TokenType::BREAK)) {
        match(TokenType::SEMICOLON);
        res.reset(new BreakStmt());
    }
    else if (match(TokenType::CONTINUE)) {
        match(TokenType::SEMICOLON);
        res.reset(new ContinueStmt());
    }
    else if (match(TokenType::SWITCH)) {
        match(TokenType::LPAREN);
        auto cond = parse_expression();
        match(TokenType::RPAREN);
        auto body = parse_statement();
        res.reset(new SwitchStmt(std::move(cond), std::move(body)));
    }
    else if (match(TokenType::CASE)) {
        auto val = parse_expression();
        match(TokenType::COLON);
        res.reset(new CaseStmt(std::move(val)));
    }
    else if (match(TokenType::DEFAULT)) {
        match(TokenType::COLON);
        res.reset(new DefaultStmt());
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
    return parse_assignment();
}

std::unique_ptr<Expr> Parser::parse_assignment() {
    auto left = parse_equality();
    if (match(TokenType::ASSIGN)) {
        auto right = parse_assignment();
        return std::unique_ptr<Expr>(new AssignExpr(std::move(left), std::move(right)));
    }
    return left;
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
    auto left = parse_shift();
    while (match(TokenType::LT) || match(TokenType::GT)) {
        TokenType op = tokens_[pos_-1].type;
        auto right = parse_shift();
        auto next = std::unique_ptr<BinaryExpr>(new BinaryExpr(op, std::move(left), std::move(right)));
        next->line = line;
        left = std::move(next);
    }
    return left;
}

std::unique_ptr<Expr> Parser::parse_shift() {
    int line = peek().line;
    auto left = parse_term();
    while (match(TokenType::LSH)) {
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
    if (match(TokenType::INC) || match(TokenType::DEC)) {
        auto op = tokens_[pos_-1].type;
        auto operand = parse_primary();
        auto res = std::unique_ptr<Expr>(new UnaryExpr(op, std::move(operand), false));
        res->line = line;
        return res;
    }

    std::unique_ptr<Expr> res;

    if (match(TokenType::NUMBER)) {
        res.reset(new IntExpr(std::stoll(tokens_[pos_-1].text)));
    }
    else if (match(TokenType::STRING)) {
        res.reset(new StrExpr(tokens_[pos_-1].text));
    }
    else if (match(TokenType::NULLPTR_TOKEN)) {
        res.reset(new NullExpr());
    }
    else if (match(TokenType::SIZEOF)) {
        match(TokenType::LPAREN);
        if (types_.count(peek().text)) advance();
        else parse_expression();
        match(TokenType::RPAREN);
        res.reset(new IntExpr(8)); // placeholder, everything is 8
    }
    else if (match(TokenType::TRUE_TOKEN)) {
        res.reset(new IntExpr(1));
    }
    else if (match(TokenType::FALSE_TOKEN)) {
        res.reset(new IntExpr(0));
    }
    else if (match(TokenType::IDENTIFIER)) {
        std::string full_name = tokens_[pos_-1].text;
        while (match(TokenType::COLON_COLON)) {
            full_name += "::" + advance().text;
        }
        
        if (match(TokenType::LPAREN)) {
            std::vector<std::unique_ptr<Expr>> args;
            if (!check(TokenType::RPAREN)) {
                do {
                    args.push_back(parse_expression());
                } while (match(TokenType::COMMA));
            }
            match(TokenType::RPAREN);
            res.reset(new CallExpr(full_name, std::move(args)));
        } else {
            // Split back into scope and name if it's a ScopedVarExpr
            size_t last_cc = full_name.find_last_of(":");
            if (last_cc != std::string::npos) {
                std::string scope = full_name.substr(0, last_cc - 1);
                std::string name = full_name.substr(last_cc + 1);
                res.reset(new ScopedVarExpr(scope, name));
            } else {
                res.reset(new VarExpr(full_name));
            }
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
    
    if (match(TokenType::INC) || match(TokenType::DEC)) {
        res.reset(new UnaryExpr(tokens_[pos_-1].type, std::move(res), true));
        res->line = line;
    }
    
    // Member access: object.member
    while (match(TokenType::DOT)) {
        std::string member = advance().text;
        res.reset(new MemberExpr(std::move(res), member));
        res->line = line;
    }

    return res;
}

} // namespace tpp
