#include <cstring>
#include <iomanip>
#include <iostream>
#include <openssl/md5.h>
#include <sstream>
#include <windows.h>

#define NUM_THREADS 2

HANDLE mutex;  
bool flag = false; 

struct ThreadParams {
    unsigned long long start;
    unsigned long long end;
    std::string original_password;
};

DWORD WINAPI bruteForce(LPVOID param) {
    ThreadParams* params = static_cast<ThreadParams*>(param);
    unsigned long long start = params->start;
    unsigned long long end = params->end;
    std::string original_password = params->original_password;

    for (unsigned long long i = start; i <= end; ++i) {
        WaitForSingleObject(mutex, INFINITE);  
        if (flag) {
            ReleaseMutex(mutex); 
            return 0;
        }
        ReleaseMutex(mutex); 
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
            WaitForSingleObject(mutex, INFINITE);
            std::cout << "Original password: " << password_str << std::endl;
            flag = true;
            ReleaseMutex(mutex); 
            return 0;
        } else if (i % 100000 == 0) {
            std::cout << "Wrong: " << password_str << " " << hex_hash_str << " Trying again..." << std::endl;
        }
    }
    return 0;
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

    mutex = CreateMutex(NULL, FALSE, NULL);
    if (mutex == NULL) {
        std::cerr << "CreateMutex error: " << GetLastError() << std::endl;
        return 1;
    }

    unsigned long long max_value = 9999999999ULL;
    unsigned long long half_value = max_value / 2;

    ThreadParams params1 = {0, half_value, original_password};
    ThreadParams params2 = {half_value + 1, max_value, original_password};

    HANDLE threads[NUM_THREADS];
    threads[0] = CreateThread(NULL, 0, bruteForce, &params1, 0, NULL);
    threads[1] = CreateThread(NULL, 0, bruteForce, &params2, 0, NULL);
    WaitForMultipleObjects(NUM_THREADS, threads, TRUE, INFINITE);
    CloseHandle(threads[0]);
    CloseHandle(threads[1]);
    CloseHandle(mutex);

    if (!flag) {
        std::cout << "Password not found." << std::endl;
    }

    return 0;
}
