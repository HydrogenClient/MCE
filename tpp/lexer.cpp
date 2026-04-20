#include "lexer.hpp"
#include <cctype>
#include <unordered_map>

namespace tpp {

static const std::unordered_map<std::string, TokenType> KEYWORDS = {
    {"int",           TokenType::INT},
    {"while",         TokenType::WHILE},
    {"if",            TokenType::IF},
    {"else",          TokenType::ELSE},
    {"return",        TokenType::RETURN},
    {"extern",        TokenType::EXTERN},
    {"auto",          TokenType::AUTO},
    {"nullptr",       TokenType::NULLPTR_TOKEN},
    {"static_assert", TokenType::STATIC_ASSERT},
    {"using",         TokenType::USING},
    {"enum",          TokenType::ENUM},
    {"class",         TokenType::CLASS},
    {"constexpr",     TokenType::CONSTEXPR},
    {"namespace",     TokenType::NAMESPACE},
    {"decltype",      TokenType::DECLTYPE},
    {"final",         TokenType::FINAL},
    {"override",      TokenType::OVERRIDE},
    {"for",           TokenType::FOR},
    {"long",          TokenType::LONG},
    {"bool",          TokenType::BOOL},
    {"true",          TokenType::TRUE_TOKEN},
    {"false",         TokenType::FALSE_TOKEN},
    {"void",          TokenType::VOID},
    {"break",         TokenType::BREAK},
    {"continue",      TokenType::CONTINUE},
    {"do",            TokenType::DO},
    {"switch",        TokenType::SWITCH},
    {"case",          TokenType::CASE},
    {"default",       TokenType::DEFAULT},
    {"char",          TokenType::CHAR},
    {"short",         TokenType::SHORT},
    {"unsigned",      TokenType::UNSIGNED},
    {"signed",        TokenType::SIGNED},
    {"struct",        TokenType::STRUCT},
    {"sizeof",        TokenType::SIZEOF},
    {"goto",          TokenType::GOTO},
    {"static",        TokenType::STATIC},
    {"inline",        TokenType::INLINE},
    {"alignas",       TokenType::ALIGNAS},
    {"alignof",       TokenType::ALIGNOF},
    {"and",           TokenType::AND},
    {"and_eq",        TokenType::AND_EQ},
    {"asm",           TokenType::ASM},
    {"bitand",        TokenType::BITAND},
    {"bitor",         TokenType::BITOR},
    {"catch",         TokenType::CATCH},
    {"char16_t",      TokenType::CHAR16_T},
    {"char32_t",      TokenType::CHAR32_T},
    {"compl",         TokenType::COMPL},
    {"const",         TokenType::CONST},
    {"const_cast",    TokenType::CONST_CAST},
    {"delete",        TokenType::DELETE},
    {"double",        TokenType::DOUBLE},
    {"dynamic_cast",  TokenType::DYNAMIC_CAST},
    {"explicit",      TokenType::EXPLICIT},
    {"export",        TokenType::EXPORT},
    {"float",         TokenType::FLOAT},
    {"friend",        TokenType::FRIEND},
    {"mutable",       TokenType::MUTABLE},
    {"new",           TokenType::NEW},
    {"noexcept",      TokenType::NOEXCEPT},
    {"not",           TokenType::NOT},
    {"not_eq",        TokenType::NOT_EQ},
    {"operator",      TokenType::OPERATOR},
    {"or",            TokenType::OR},
    {"or_eq",         TokenType::OR_EQ},
    {"private",       TokenType::PRIVATE},
    {"protected",     TokenType::PROTECTED},
    {"public",        TokenType::PUBLIC},
    {"reinterpret_cast", TokenType::REINTERPRET_CAST},
    {"static_cast",   TokenType::STATIC_CAST},
    {"template",      TokenType::TEMPLATE},
    {"this",          TokenType::THIS},
    {"thread_local",  TokenType::THREAD_LOCAL},
    {"throw",         TokenType::THROW},
    {"try",           TokenType::TRY},
    {"typedef",       TokenType::TYPEDEF},
    {"typeid",        TokenType::TYPEID},
    {"typename",      TokenType::TYPENAME},
    {"union",         TokenType::UNION},
    {"virtual",       TokenType::VIRTUAL},
    {"volatile",      TokenType::VOLATILE},
    {"wchar_t",       TokenType::WCHAR_T},
    {"xor",           TokenType::XOR},
    {"xor_eq",        TokenType::XOR_EQ},
};

std::vector<Token> Lexer::tokenize() {
    std::vector<Token> tokens;
    while (pos_ < source_.size()) {
        skip_whitespace();
        if (pos_ >= source_.size()) break;

        char c = advance();
        if (isalpha(c) || c == '_') {
            std::string text(1, c);
            while (isalnum(peek()) || peek() == '_') text += advance();
            auto it = KEYWORDS.find(text);
            TokenType type = (it != KEYWORDS.end()) ? it->second : TokenType::IDENTIFIER;
            tokens.push_back({type, text, line_});
        }
        else if (isdigit(c)) {
            std::string text(1, c);
            if (c == '0' && (peek() == 'b' || peek() == 'B')) {
                text += advance(); // b
                while (peek() == '0' || peek() == '1' || peek() == '\'') {
                    if (peek() == '\'') { advance(); continue; }
                    text += advance();
                }
                tokens.push_back({TokenType::NUMBER, std::to_string(std::stoll(text.substr(2), nullptr, 2)), line_});
            } else {
                while (isdigit(peek()) || peek() == '\'' || peek() == '.') {
                    if (peek() == '\'') { advance(); continue; }
                    text += advance();
                }
                // Handle float to int truncation for now since backend is i64
                if (text.find('.') != std::string::npos) {
                    try {
                        tokens.push_back({TokenType::NUMBER, std::to_string((long long)std::stod(text)), line_});
                    } catch (...) {
                        tokens.push_back({TokenType::NUMBER, "0", line_});
                    }
                } else {
                    tokens.push_back({TokenType::NUMBER, text, line_});
                }
            }
        }
        else if (c == '"') {
            std::string text;
            while (peek() != '"' && peek() != '\0') {
                if (peek() == '\\') {
                    advance();
                    char e = advance();
                    if (e == 'n') text += '\n';
                    else if (e == 'r') text += '\r';
                    else if (e == 't') text += '\t';
                    else text += e;
                } else {
                    text += advance();
                }
            }
            if (peek() == '"') advance();
            tokens.push_back({TokenType::STRING, text, line_});
        }
        else {
            switch (c) {
                case '(': tokens.push_back({TokenType::LPAREN, "(", line_}); break;
                case ')': tokens.push_back({TokenType::RPAREN, ")", line_}); break;
                case '{': tokens.push_back({TokenType::LBRACE, "{", line_}); break;
                case '}': tokens.push_back({TokenType::RBRACE, "}", line_}); break;
                case ';': tokens.push_back({TokenType::SEMICOLON, ";", line_}); break;
                case ':':
                    if (peek() == ':') { advance(); tokens.push_back({TokenType::COLON_COLON, "::", line_}); }
                    else { tokens.push_back({TokenType::COLON, ":", line_}); }
                    break;
                case '.': tokens.push_back({TokenType::DOT, ".", line_}); break;
                case ',': tokens.push_back({TokenType::COMMA, ",", line_}); break;
                case '+': 
                    if (peek() == '+') { advance(); tokens.push_back({TokenType::INC, "++", line_}); }
                    else { tokens.push_back({TokenType::PLUS, "+", line_}); }
                    break;
                case '-':
                    if (peek() == '-') { advance(); tokens.push_back({TokenType::DEC, "--", line_}); }
                    else if (peek() == '>') { advance(); tokens.push_back({TokenType::ARROW, "->", line_}); }
                    else { tokens.push_back({TokenType::MINUS, "-", line_}); }
                    break;
                case '*': tokens.push_back({TokenType::STAR, "*", line_}); break;
                case '/':
                    if (peek() == '/') {
                        advance();
                        while (peek() != '\n' && peek() != '\0') advance();
                    } else if (peek() == '*') {
                        advance();
                        while (pos_ < source_.size()) {
                            if (peek() == '*' && source_[pos_+1] == '/') {
                                advance(); advance();
                                break;
                            }
                            if (peek() == '\n') line_++;
                            advance();
                        }
                    } else {
                        tokens.push_back({TokenType::SLASH, "/", line_});
                    }
                    break;
                case '=':
                    if (peek() == '=') { advance(); tokens.push_back({TokenType::EQEQ, "==", line_}); }
                    else { tokens.push_back({TokenType::ASSIGN, "=", line_}); }
                    break;
                case '!':
                    if (peek() == '=') { advance(); tokens.push_back({TokenType::NEQ, "!=", line_}); }
                    break;
                case '<':
                    if (peek() == '<') { advance(); tokens.push_back({TokenType::LSH, "<<", line_}); }
                    else { tokens.push_back({TokenType::LT, "<", line_}); }
                    break;
                case '>': tokens.push_back({TokenType::GT, ">", line_}); break;
                case '\n': line_++; break;
            }
        }
    }
    tokens.push_back({TokenType::EOF_TOKEN, "", line_});
    return tokens;
}

void Lexer::skip_whitespace() {
    while (pos_ < source_.size() && isspace(source_[pos_])) {
        if (source_[pos_] == '\n') line_++;
        pos_++;
    }
}

} // namespace tpp
