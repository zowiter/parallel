#include <cstring>
#include <iomanip>
#include <iostream>
#include <openssl/md5.h>
#include <sstream>
#include <thread>
#include <mutex>

std::mutex mutex_flag;
bool flag = false; 

struct ThreadParams {
    unsigned long long start;
    unsigned long long end;
    std::string original_password;
};

void bruteForce(ThreadParams params) {
    for (unsigned long long i = params.start; i <= params.end; ++i) {
        {
            std::lock_guard<std::mutex> lock(mutex_flag);
            if (flag) {
                return;  
            }
        }

        std::ostringstream password_stream, hex_hash;
        password_stream << std::setfill('0') << std::setw(10) << i;

        std::string password_str = password_stream.str();

        unsigned char digest[MD5_DIGEST_LENGTH];
        MD5(reinterpret_cast<const unsigned char*>(password_str.c_str()), password_str.length(), digest);

        for (int j = 0; j < MD5_DIGEST_LENGTH; ++j) {
            hex_hash << std::hex << std::setw(2) << std::setfill('0') << (int)digest[j];
        }
        std::string hex_hash_str = hex_hash.str();

        if (hex_hash_str == params.original_password) {
            std::lock_guard<std::mutex> lock(mutex_flag);
            std::cout << "Original password: " << password_str << std::endl;
            flag = true; 
            return;
        } else if (i % 100000 == 0) {
            std::lock_guard<std::mutex> lock(mutex_flag);
            std::cout << "Wrong: " << password_str << " " << hex_hash_str << " Trying again..." << std::endl;
        }
    }
}

int main() {
    unsigned char digest_hashing[MD5_DIGEST_LENGTH];
    std::string input;
    std::cout << "Enter password: ";  
    std::cin >> input; 

    MD5(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), digest_hashing);

    std::ostringstream hash;
    for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        hash << std::hex << std::setw(2) << std::setfill('0') << (int)digest_hashing[i];
    }
    std::string hash_string = hash.str();

    std::cout << "MD5 hash: " << hash_string << std::endl;
    std::cout << "Enter hash: ";
    std::string original_password;
    std::cin >> original_password;

    unsigned long long max_value = 9999999999ULL;
    unsigned long long half_value = max_value / 2;

    ThreadParams params1 = {0, half_value, original_password};
    ThreadParams params2 = {half_value + 1, max_value, original_password};
    std::thread thread1(bruteForce, params1);
    std::thread thread2(bruteForce, params2);
    thread1.join();
    thread2.join();

    if (!flag) {
        std::cout << "Password not found." << std::endl;
    }

    return 0;
}
