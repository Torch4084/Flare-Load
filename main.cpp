#include "http_client.hpp"
#include "xss_engine.hpp"
#include <iostream>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <url>" << std::endl;
        return 1;
    }

    std::string target_url = argv[1];
    HttpClient client;

    std::cout << "========================================" << std::endl;
    std::cout << "   FLARE-LOAD (C++) - Advanced XSS Payload Generator" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "[*] Target: " << target_url << std::endl;

    // XSS Engine
    XSSEngine xss_engine(client);
    xss_engine.run(target_url);

    return 0;
}
