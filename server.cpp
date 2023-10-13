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

//g = 5
//a = 6
//p = 29
unsigned long long diffie_hellman(unsigned long long generator, unsigned long long privateKey, unsigned long long primeNum) {
    unsigned long long result = 1;
    //generator musi byt mensi ako prime number ? 
    generator = generator % primeNum;  // Update generator if it's more than or equal to primeNum
  
    while (privateKey > 0) {
         std::cout << "zaciatok iteracie" << std::endl;
         std::cout << "privateKey: " << privateKey << ", result: " << result << ", generator: " << generator << std::endl;

        if (privateKey % 2 == 1) {
            result = (result * generator) % primeNum;
        }
        
        privateKey = privateKey / 2;
        generator = (generator * generator) % primeNum;

        std::cout << "koniec iteracie" << std::endl;
        std::cout << "privateKey: " << privateKey << ", result: " << result << ", generator: " << generator << std::endl;

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
        string file_name = line.substr(33);  // Assuming that there is at least one space between the hash and the file name
        cout << "Hash je: " << hash <<endl;
        cout << "Subor je: " << file_name <<endl;


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


     // Diffie-Hellman inicializácia
    unsigned long long p = 29; // Veľké prvočíslo
    unsigned long long g = 5;  // Generátor
    unsigned long long pKey = 6;  // Náhodné číslo na serveri

    unsigned long long A = diffie_hellman(g, pKey, p);


    // Posiela A klientovi
    string A_str = to_string(A);
    cout << "Sending A: " << A_str << endl;  // Debug
    send(new_socket, A_str.c_str(), A_str.length(), 0);
    
    // Prijíma B od klienta
    char buffer[1024] = {0};
    read(new_socket, buffer, 1024);
    unsigned long long B = stoull(buffer);

    // Vypočíta zdieľaný tajný kľúč
    unsigned long long shared_secret = diffie_hellman(B, pKey, p);

    cout << "Shared secret: " << shared_secret << endl;

    return 0;
}
