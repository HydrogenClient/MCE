#pragma once
#include <string>
#include <fstream>
#include <sstream>
#include <iostream>
#include <vector>

namespace tpp {

class Preprocessor {
public:
    static std::string process(const std::string& source, const std::string& include_dir) {
        std::stringstream in(source);
        std::stringstream out;
        std::string line;
        
        while (std::getline(in, line)) {
            if (line.find("#include") == 0) {
                size_t start = line.find('<');
                size_t end = line.find('>');
                if (start == std::string::npos || end == std::string::npos) {
                    start = line.find('"');
                    end = line.rfind('"');
                }
                
                if (start != std::string::npos && end != std::string::npos && end > start) {
                    std::string filename = line.substr(start + 1, end - start - 1);
                    std::string path = include_dir + "/" + filename;
                    
                    std::ifstream f(path);
                    if (f) {
                        std::stringstream ss;
                        ss << f.rdbuf();
                        out << ss.str() << "\n";
                        continue;
                    } else {
                        std::cerr << "Warning: Could not find include file: " << path << "\n";
                    }
                }
            }
            out << line << "\n";
        }
        return out.str();
    }
};

} // namespace tpp
