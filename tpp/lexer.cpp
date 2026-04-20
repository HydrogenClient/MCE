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
                    break;
                case ',': tokens.push_back({TokenType::COMMA, ",", line_}); break;
                case '+': tokens.push_back({TokenType::PLUS, "+", line_}); break;
                case '-':
                    if (peek() == '>') { advance(); tokens.push_back({TokenType::ARROW, "->", line_}); }
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
