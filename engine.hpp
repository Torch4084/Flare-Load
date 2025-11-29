#ifndef ENGINE_HPP
#define ENGINE_HPP

#include <string>
#include <iostream>
#include "http_client.hpp"

class VulnerabilityEngine {
protected:
    HttpClient& client;

public:
    VulnerabilityEngine(HttpClient& c) : client(c) {}
    virtual ~VulnerabilityEngine() {}

    virtual void run(const std::string& target_url) = 0;
};

#endif // ENGINE_HPP
