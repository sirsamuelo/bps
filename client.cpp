#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <cmath>
#include <fstream>
#include <string>
#include <unordered_map>

unsigned long long diffie_hellman(unsigned long long base, unsigned long long exp, unsigned long long mod) {
    unsigned long long result = 1;
    base = base % mod;  // Update base if it's more than or equal to mod
  
    while (exp > 0) {
        // If exponent is odd, multiply result by base
        if (exp % 2 == 1) {
            result = (result * base) % mod;
        }
        
        // exponent must be even now
        exp = exp >> 1; // equivalent to exp/2
        base = (base * base) % mod;
    }
    return result;
}

bool verify_md5(const std::string& filename, const std::unordered_map<std::string, std::string>& known_hashes) {
    std::ifstream file(filename);
    std::string line;

    if (!file.is_open()) {
        std::cerr << "Could not open " << filename << std::endl;
        return false;
    }

    while (std::getline(file, line)) {
        std::string hash = line.substr(0, 32);
        std::string file_name = line.substr(33);  // Assuming that there is at least one space between the hash and the file name

        if (known_hashes.find(file_name) != known_hashes.end()) {
            if (known_hashes.at(file_name) != hash) {
                std::cerr << "Hash mismatch for " << file_name << std::endl;
                return false;
            }
        }
    }

    return true;
}

int main()
{
    std::unordered_map<std::string, std::string> known_hashes = {
        {"client.cpp", "18599d7d85f1f9dd0dd27f687ad38d09"},
        {"server.cpp", "fecf7b9851af8187d21eb5d4e36506f8"}
    };

    if (!verify_md5("md5sum.txt", known_hashes)) {
        std::cerr << "Integrity check failed. Exiting..." << std::endl;
        return 1;
    }


    int sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(8080);
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1"); // alebo IP adresa tvojho servera

    if (sock == -1)
    {
        std::cerr << "Could not create socket\n";
        return 1;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        std::cerr << "Connection failed\n";
        return 1;
    }

    char buffer[1024] = {0};
    read(sock, buffer, 1024);
    std::cout << "Message from server: " << buffer << std::endl;

    // Diffie-Hellman inicializácia
    unsigned long long p = 29;
    unsigned long long g = 5;
    unsigned long long b = 15; // Náhodné číslo na klientovi

    unsigned long long B = diffie_hellman(g, b, p);

    // Posiela B serveru a prijíma A od servera
    // ...


    // Prijíma A od servera
    char bufferFromA[1024] = {0};
    ssize_t bytesRead = read(sock, bufferFromA, 1024);
    if (bytesRead < 0)
    {
        std::cerr << "Read failed\n";
        return 1;
    }
    std::cout << "Received buffer: " << bufferFromA << std::endl;
    unsigned long long A = std::stoull(bufferFromA);

    // Posiela B serveru
    std::string B_str = std::to_string(B);
    send(sock, B_str.c_str(), B_str.length(), 0);

    // Vypočíta zdieľaný tajný kľúč
    unsigned long long shared_secret = diffie_hellman(A, b, p);

    std::cout << "Shared secret: " << shared_secret << std::endl;

    return 0;
}
