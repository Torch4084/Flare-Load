#ifndef HTTP_CLIENT_HPP
#define HTTP_CLIENT_HPP

#include <string>
#include <map>

struct HttpResponse {
    int status_code;
    std::map<std::string, std::string> headers;
    std::string body;
};

class HttpClient {
public:
    HttpClient();
    ~HttpClient();

    HttpResponse get(const std::string& url);
    // Post can be added later if needed, focusing on GET for now as per plan

private:
    struct UrlParts {
        std::string host;
        int port;
        std::string path;
    };

    UrlParts parse_url(const std::string& url);
    HttpResponse send_request(const std::string& host, int port, const std::string& request);
};

#endif // HTTP_CLIENT_HPP
