#include "crypto_utils.h"
#include <gmpxx.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <chrono>
#include <cstring>
#include <algorithm>


// modular arithmetic

mpz_class mod_exp(const mpz_class &base, const mpz_class &exp, const mpz_class &mod){
    mpz_class result;
    mpz_powm(result.get_mpz_t(), base.get_mpz_t(), exp.get_mpz_t(), mod.get_mpz_t());
    return result;
}
