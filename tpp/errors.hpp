#pragma once
#include <string>
#include <vector>
#include <iostream>
#include <algorithm>

namespace tpp {

class ErrorReporter {
public:
    static void init(const std::string& source, const std::string& filename) {
        source_ = source;
        filename_ = filename;
    }

    static void error(int line, const std::string& message, const std::string& text = "", const std::vector<std::string>& suggestions = {}) {
        std::cerr << "\033[1;37m" << filename_ << ":" << line << ": \033[1;31merror: \033[0m" << message << "\n";
        
        // Snippet
        std::string line_str = get_line(line);
        if (!line_str.empty()) {
            std::string line_num = std::to_string(line) + " | ";
            std::cerr << " " << line_num << line_str << "\n";
            
            // Caret (simple version, assuming single match in line for now or just pointing at line start)
            std::cerr << std::string(line_num.length() + 1, ' ') << "\033[1;32m^";
            if (!text.empty()) {
                size_t pos = line_str.find(text);
                if (pos != std::string::npos) {
                    std::cerr << std::string(pos, ' ') << "~"; // This isn't quite right for multiple matches but good enough
                }
            }
            std::cerr << "\033[0m\n";
        }

        if (!suggestions.empty() && !text.empty()) {
            std::string best_match;
            int min_dist = 999;
            for (const auto& s : suggestions) {
                int d = levenshtein(text, s);
                if (d < min_dist && d < 3) {
                    min_dist = d;
                    best_match = s;
                }
            }
            if (!best_match.empty()) {
                std::cerr << "\033[1;36mnote: \033[0m" << "did you mean '\033[1;32m" << best_match << "\033[0m'?\n";
            }
        }
    }

private:
    static std::string get_line(int line_num) {
        std::string line;
        int current = 1;
        for (char c : source_) {
            if (current == line_num) {
                if (c == '\n' || c == '\r') break;
                line += c;
            } else if (c == '\n') {
                current++;
            }
        }
        return line;
    }

    static int levenshtein(const std::string& s1, const std::string& s2) {
        int m = s1.length();
        int n = s2.length();
        std::vector<std::vector<int>> d(m + 1, std::vector<int>(n + 1));
        for (int i = 0; i <= m; i++) d[i][0] = i;
        for (int j = 0; j <= n; j++) d[0][j] = j;
        for (int j = 1; j <= n; j++) {
            for (int i = 1; i <= m; i++) {
                int cost = (s1[i - 1] == s2[j - 1]) ? 0 : 1;
                d[i][j] = std::min({d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost});
            }
        }
        return d[m][n];
    }

    static std::string source_;
    static std::string filename_;
};

} // namespace tpp
