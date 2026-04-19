#include "lexer.hpp"
#include <cctype>
#include <unordered_map>

namespace tpp {

static const std::unordered_map<std::string, TokenType> KEYWORDS = {
    {"int",    TokenType::INT},
    {"while",  TokenType::WHILE},
    {"if",     TokenType::IF},
    {"else",   TokenType::ELSE},
    {"return", TokenType::RETURN},
    {"extern", TokenType::EXTERN},
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
            while (isdigit(peek())) text += advance();
            tokens.push_back({TokenType::NUMBER, text, line_});
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
                case ',': tokens.push_back({TokenType::COMMA, ",", line_}); break;
                case '+': tokens.push_back({TokenType::PLUS, "+", line_}); break;
                case '-': tokens.push_back({TokenType::MINUS, "-", line_}); break;
                case '*': tokens.push_back({TokenType::STAR, "*", line_}); break;
                case '/': tokens.push_back({TokenType::SLASH, "/", line_}); break;
                case '=':
                    if (peek() == '=') { advance(); tokens.push_back({TokenType::EQEQ, "==", line_}); }
                    else { tokens.push_back({TokenType::ASSIGN, "=", line_}); }
                    break;
                case '!':
                    if (peek() == '=') { advance(); tokens.push_back({TokenType::NEQ, "!=", line_}); }
                    break;
                case '<': tokens.push_back({TokenType::LT, "<", line_}); break;
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
