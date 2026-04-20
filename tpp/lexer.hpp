#pragma once
#include <string>
#include <vector>

namespace tpp {

enum class TokenType {
    // Keywords
    INT, WHILE, IF, ELSE, RETURN, EXTERN, FOR, LONG,
    AUTO, NULLPTR_TOKEN, STATIC_ASSERT, USING, ENUM, CLASS, CONSTEXPR, NAMESPACE,
    DECLTYPE, FINAL, OVERRIDE,
    BOOL, TRUE_TOKEN, FALSE_TOKEN, VOID, BREAK, CONTINUE, DO, SWITCH, CASE, DEFAULT,
    CHAR, SHORT, UNSIGNED, SIGNED, STRUCT, SIZEOF, GOTO, STATIC, INLINE,
    ALIGNAS, ALIGNOF, AND, AND_EQ, ASM, BITAND, BITOR, CATCH, CHAR16_T, CHAR32_T,
    COMPL, CONST, CONST_CAST, DELETE, DOUBLE, DYNAMIC_CAST, EXPLICIT, EXPORT,
    FLOAT, FRIEND, MUTABLE, NEW, NOEXCEPT, NOT, NOT_EQ, OPERATOR, OR, OR_EQ,
    PRIVATE, PROTECTED, PUBLIC, REINTERPRET_CAST, STATIC_CAST, TEMPLATE, THIS,
    THREAD_LOCAL, THROW, TRY, TYPEDEF, TYPEID, TYPENAME, UNION, VIRTUAL, VOLATILE,
    WCHAR_T, XOR, XOR_EQ,
    
    // Literals
    IDENTIFIER, NUMBER, STRING,
    
    // Operators/Symbols
    LPAREN, RPAREN, LBRACE, RBRACE, SEMICOLON, COMMA, DOT, COLON,
    ASSIGN, PLUS, MINUS, STAR, SLASH,
    LT, GT, EQEQ, NEQ, COLON_COLON, LSH, ARROW, INC, DEC,
    
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
