#pragma once
#include <string>
#include <vector>

namespace tpp {

enum class TokenType {
    // Keywords
    INT, WHILE, IF, ELSE, RETURN, EXTERN,
    AUTO, NULLPTR_TOKEN, STATIC_ASSERT, USING, ENUM, CLASS, CONSTEXPR, NAMESPACE,
    DECLTYPE, FINAL, OVERRIDE,
    
    // Literals
    IDENTIFIER, NUMBER, STRING,
    
    // Operators/Symbols
    LPAREN, RPAREN, LBRACE, RBRACE, SEMICOLON, COMMA,
    ASSIGN, PLUS, MINUS, STAR, SLASH,
    LT, GT, EQEQ, NEQ, COLON_COLON, LSH, ARROW,
    
    EOF_TOKEN
};

struct Token {
    TokenType type;
    std::string text;
    int line;
};

class Lexer {
public:
    explicit Lexer(const std::string& source) : source_(source) {}
    std::vector<Token> tokenize();

private:
    char peek() const { return pos_ < source_.size() ? source_[pos_] : '\0'; }
    char advance() { return source_[pos_++]; }
    void skip_whitespace();

    std::string source_;
    size_t pos_ = 0;
    int line_ = 1;
};

} // namespace tpp
