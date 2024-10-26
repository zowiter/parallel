#include <iomanip>
#include <sstream>
#include <openssl/md5.h>
#include <cstring> 
#include <iostream>

int main() {
    unsigned char digest[MD5_DIGEST_LENGTH];
    std::string input;
    std::cout << "Enter password: ";  
    std::cin >> input; 

    MD5(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), digest);

    std::ostringstream hash;
    for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        hash << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
    }
    std::string hash_string = hash.str();

    std::cout << "MD5 hash: " << hash_string << std::endl;
    
    std::cout << "Enter hash: ";
    std::string target;
    std::cin >> target; 
    char password[11] = "0000000000"; 

    for (unsigned long long i = 0; i <= 9999999999ULL; ++i) {
        std::ostringstream password_stream;
        password_stream <<  std::setfill('0') << std::setw(10)  << i;
        std::string password_str = password_stream.str();

        MD5(reinterpret_cast<const unsigned char*>(password_str.c_str()), password_str.length(), digest);

    	std::ostringstream hex_hash;
    	for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
            hex_hash << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
    	}
        std::string hex_hash_str = hex_hash.str();


        if (hex_hash_str == target) {
            std::cout << "Orginal password: " <<  password_str << std::endl;
            break;
        }

        if (i % 100000 == 0) {
            std::cout << "Wrong: " << password_str << " " << hex_hash_str << " Trying again..." << std::endl;
        }
    }
    return 0;
}
