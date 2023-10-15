#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cmath> 
#include <cstring>
#include <fstream>
#include <string>
#include <unordered_map>
using namespace std;


unsigned long long diffie_hellman(unsigned long long generator, unsigned long long privateKey, unsigned long long primeNum) {
    unsigned long long result = 1;
 
    generator = generator % primeNum;  
  
    while (privateKey > 0) {
        if (privateKey % 2 == 1) {
            result = (result * generator) % primeNum;
        }
        privateKey = privateKey / 2;
        generator = (generator * generator) % primeNum;
    }
    return result;
}

bool verify_md5(const string& filename, const unordered_map<string, string>& known_hashes) {
    ifstream file(filename);
    string line;

    if (!file.is_open()) {
        cerr << "Could not open " << filename << endl;
        return false;
    }

    while (getline(file, line)) {
        string hash = line.substr(0, 32);
        string file_name = line.substr(33);  
 
        if (known_hashes.find(file_name) != known_hashes.end()) {
            if (known_hashes.at(file_name) != hash) {
                cerr << "Hash mismatch for " << file_name << endl;
                return false;
            }
        }
    }
    return true;
}


int main() {
    unordered_map<string, string> known_hashes = {
        {"client.cpp", "18599d7d85f1f9dd0dd27f687ad38d09"},
        {"server.cpp", "fecf7b9851af8187d21eb5d4e36506f8"}
    };



    if (!verify_md5("md5sum.txt", known_hashes)) {
        cerr << "Integrity check failed. Exiting..." << endl;
        return 1;
    }

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(8080);

    bind(server_fd, (struct sockaddr *)&address, sizeof(address));
    listen(server_fd, 10);

    int addrlen = sizeof(address);
    int new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);

    string hello = "Hello from server";
    send(new_socket, hello.c_str(), hello.length(), 0);
    cout << "Message sent" << endl;


    unsigned long long p = 29;
    unsigned long long g = 5; 
    unsigned long long pKey = 6;  

    unsigned long long A = diffie_hellman(g, pKey, p);

    string A_str = to_string(A);
    cout << "Sending A: " << A_str << endl;  
    send(new_socket, A_str.c_str(), A_str.length(), 0);
    
    char buffer[1024] = {0};
    read(new_socket, buffer, 1024);
    unsigned long long B = stoull(buffer);

    unsigned long long shared_secret = diffie_hellman(B, pKey, p);

    cout << "Shared secret: " << shared_secret << endl;

    return 0;
}
