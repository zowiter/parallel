#include <cstring>
#include <iomanip>
#include <iostream>
#include <openssl/md5.h>
#include <pthread.h>
#include <sstream>

#define NUM_THREADS 2

bool flag = false; 
pthread_mutex_t flag_mutex; 

struct ThreadParams {
    unsigned long long start;
    unsigned long long end;
    std::string original_password;
};

void* bruteForce(void* param) {
    ThreadParams* params = static_cast<ThreadParams*>(param);
    unsigned long long start = params->start;
    unsigned long long end = params->end;
    std::string original_password = params->original_password;

    for (unsigned long long i = start; i <= end; ++i) {
        pthread_mutex_lock(&flag_mutex);
        if (flag) {
            pthread_mutex_unlock(&flag_mutex);  
            return nullptr;
        }
        pthread_mutex_unlock(&flag_mutex);  

        std::ostringstream password_stream, hex_hash;
        password_stream << std::setfill('0') << std::setw(10) << i;

        std::string password_str = password_stream.str();

        unsigned char digest[MD5_DIGEST_LENGTH];
        MD5(reinterpret_cast<const unsigned char*>(password_str.c_str()), password_str.length(), digest);

        for (int j = 0; j < MD5_DIGEST_LENGTH; ++j) {
            hex_hash << std::hex << std::setw(2) << std::setfill('0') << (int)digest[j];
        }
        std::string hex_hash_str = hex_hash.str();

        if (hex_hash_str == original_password) {
            pthread_mutex_lock(&flag_mutex);
            std::cout << "Original password: " << password_str << std::endl;
            flag = true;
            pthread_mutex_unlock(&flag_mutex); 
            return nullptr;
        } else if (i % 100000 == 0) {
            std::cout << "Wrong: " << password_str << " " << hex_hash_str << " Trying again..." << std::endl;
        }
    }
    return nullptr;
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
    pthread_mutex_init(&flag_mutex, nullptr);

    unsigned long long max_value = 9999999999ULL;
    unsigned long long half_value = max_value / 2;

    ThreadParams params1 = {0, half_value, original_password};
    ThreadParams params2 = {half_value + 1, max_value, original_password};
    pthread_t threads[NUM_THREADS];
    pthread_create(&threads[0], nullptr, bruteForce, &params1);
    pthread_join(threads[0], nullptr);
    pthread_join(threads[1], nullptr);

    if (!flag) {
        std::cout << "Password not found." << std::endl;
    }

    pthread_mutex_destroy(&flag_mutex);

    return 0;
}