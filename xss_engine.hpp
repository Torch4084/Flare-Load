#ifndef XSS_ENGINE_HPP
#define XSS_ENGINE_HPP

#include "engine.hpp"
#include <vector>

class XSSEngine : public VulnerabilityEngine {
public:
    XSSEngine(HttpClient& c);
    void run(const std::string& target_url) override;

private:
    std::vector<std::string> generate_mutations(const std::string& token);
    std::string construct_payload(const std::string& tag, const std::string& event, const std::string& js);
    bool verify_reflection(const std::string& url, const std::string& payload);
    bool flag_found = false;
};

#endif // XSS_ENGINE_HPP
