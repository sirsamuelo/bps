#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <cmath>
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

int main()
{
    unordered_map<string, string> known_hashes = {
        {"client.cpp", "18599d7d85f1f9dd0dd27f687ad38d09"},
        {"server.cpp", "fecf7b9851af8187d21eb5d4e36506f8"}
    };

    if (!verify_md5("md5sum.txt", known_hashes)) {
        cerr << "Integrity check failed. Exiting..." << endl;
        return 1;
    }


    int sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(8080);
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (sock == -1)
    {
        cerr << "Could not create socket\n";
        return 1;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        cerr << "Connection failed\n";
        return 1;
    }

    char buffer[1024] = {0};
    read(sock, buffer, 1024);
    cout << "Message from server: " << buffer << endl;

    unsigned long long prime = 29;
    unsigned long long gen = 5;
    unsigned long long privateVal = 15; 

    unsigned long long B = diffie_hellman(gen, privateVal, prime);


    char bufferFromA[1024] = {0};
    ssize_t bytesRead = read(sock, bufferFromA, 1024);
    if (bytesRead < 0)
    {
        cerr << "Read failed\n";
        return 1;
    }
    cout << "Received buffer: " << bufferFromA << endl;
    unsigned long long A = stoull(bufferFromA);

    string B_str = to_string(B);
    send(sock, B_str.c_str(), B_str.length(), 0);

    unsigned long long shared_secret = diffie_hellman(A, privateVal, prime);

    cout << "Shared secret: " << shared_secret << endl;

    return 0;
}
