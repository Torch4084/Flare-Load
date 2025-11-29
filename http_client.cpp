#include "http_client.hpp"
#include <iostream>
#include <sstream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <algorithm>

HttpClient::HttpClient() {}

HttpClient::~HttpClient() {}

HttpClient::UrlParts HttpClient::parse_url(const std::string& url) {
    UrlParts parts;
    std::string url_str = url;
    
    // Remove protocol
    size_t protocol_pos = url_str.find("://");
    if (protocol_pos != std::string::npos) {
        url_str = url_str.substr(protocol_pos + 3);
    }

    // Find path
    size_t path_pos = url_str.find('/');
    if (path_pos == std::string::npos) {
        parts.host = url_str;
        parts.path = "/";
    } else {
        parts.host = url_str.substr(0, path_pos);
        parts.path = url_str.substr(path_pos);
    }

    // Find port
    size_t port_pos = parts.host.find(':');
    if (port_pos != std::string::npos) {
        parts.port = std::stoi(parts.host.substr(port_pos + 1));
        parts.host = parts.host.substr(0, port_pos);
    } else {
        parts.port = 80; // Default to HTTP
    }

    return parts;
}

HttpResponse HttpClient::get(const std::string& url) {
    UrlParts parts = parse_url(url);
    
    std::stringstream request_stream;
    request_stream << "GET " << parts.path << " HTTP/1.1\r\n";
    request_stream << "Host: " << parts.host << "\r\n";
    request_stream << "User-Agent: FlareLoad/1.0\r\n";
    request_stream << "Connection: close\r\n";
    request_stream << "\r\n";

    return send_request(parts.host, parts.port, request_stream.str());
}

HttpResponse HttpClient::send_request(const std::string& host, int port, const std::string& request) {
    HttpResponse response;
    response.status_code = 0;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::cerr << "Error creating socket" << std::endl;
        return response;
    }

    struct hostent* server = gethostbyname(host.c_str());
    if (server == NULL) {
        std::cerr << "Error resolving host: " << host << std::endl;
        close(sock);
        return response;
    }

    struct sockaddr_in serv_addr;
    std::memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    std::memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    serv_addr.sin_port = htons(port);

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        std::cerr << "Error connecting to server" << std::endl;
        close(sock);
        return response;
    }

    if (send(sock, request.c_str(), request.length(), 0) < 0) {
        std::cerr << "Error sending request" << std::endl;
        close(sock);
        return response;
    }

    std::string response_str;
    char buffer[4096];
    ssize_t bytes_received;
    while ((bytes_received = recv(sock, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[bytes_received] = '\0';
        response_str += buffer;
    }
    close(sock);

    // Parse response
    std::stringstream response_stream(response_str);
    std::string line;
    
    // Status line
    if (std::getline(response_stream, line)) {
        if (line.find("HTTP/") == 0) {
            size_t first_space = line.find(' ');
            size_t second_space = line.find(' ', first_space + 1);
            if (first_space != std::string::npos && second_space != std::string::npos) {
                response.status_code = std::stoi(line.substr(first_space + 1, second_space - first_space - 1));
            }
        }
    }

    // Headers
    while (std::getline(response_stream, line) && line != "\r") {
        size_t colon_pos = line.find(':');
        if (colon_pos != std::string::npos) {
            std::string key = line.substr(0, colon_pos);
            std::string value = line.substr(colon_pos + 1);
            // Trim whitespace
            value.erase(0, value.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of(" \t\r") + 1);
            response.headers[key] = value;
        }
    }

    // Body
    // The rest of the stream is the body. Note: this basic parsing doesn't handle chunked encoding properly yet.
    // For this prototype, we'll assume simple identity encoding or small responses.
    std::string body_part;
    while (std::getline(response_stream, body_part)) {
        response.body += body_part + "\n";
    }

    return response;
}
