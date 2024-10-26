#include <cstring>
#include <iomanip>
#include <iostream>
#include <atomic>
#include <omp.h>
#include <openssl/md5.h>
#include <sstream>
#define NUM_THREADS 2

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
  std::atomic<bool> flag{false};
#pragma omp parallel for num_threads(NUM_THREADS)
    for (unsigned long long i = 0; i <= 9999999999ULL; ++i) {
      if (flag)
        continue;
      std::ostringstream password_stream, hex_hash;
      password_stream << std::setfill('0') << std::setw(10) << i;
      
      std::string password_str = password_stream.str();

      unsigned char digest[MD5_DIGEST_LENGTH];
      MD5(reinterpret_cast<const unsigned char *>(password_str.c_str()),
          password_str.length(), digest);

      for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        hex_hash << std::hex << std::setw(2) << std::setfill('0')
                 << (int)digest[i];
      }
      std::string hex_hash_str = hex_hash.str();

      if (hex_hash_str == original_password) {
        std::cout << "Orginal password: " << password_str << std::endl;
        flag = true;
        #pragma omp cancel for
      }
      else if (i % 100000 == 0) {
        std::cout << "Wrong: " << password_str << " " << hex_hash_str
                  << " Trying again..." << std::endl;
      }
    }

  return 0;
}
