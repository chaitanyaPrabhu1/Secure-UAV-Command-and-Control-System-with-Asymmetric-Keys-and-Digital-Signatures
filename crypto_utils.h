#pragma once
#include <gmpxx.h>
#include <string>
#include <sys/types.h>
#include <vector>
#include <cstdint>

using Bytes = std::vector<uint8_t>;


struct ElGamalParams{
    mpz_class p;
    mpz_class g;
    int SL;
};


struct ElGamalKeyPair{
    ElGamalParams params;
    mpz_class x;
    mpz_class y;
};


struct ElGamalCipertext{
    mpz_class c1;
    mpz_class c2;
};


struct ElGamalSignature{
    mpz_class r;
    mpz_class s;
};

mpz_class mod_exp(const mpz_class &base, const mpz_class &exp, const mpz_class &mod);

mpz_class mod_inv(const mpz_class &a, const mpz_class &m);

mpz_class generate_prime(int bits);

mpz_class find_generator(const mpz_class &p);

ElGamalKeyPair elgamal_keygen(int SL);

ElGamalCipertext elgalmal_encrypt(const ElGamalParams &params, const mpz_class &y, const mpz_class &m);

mpz_class elgamal_decrypt(const ElGamalParams &params, const mpz_class &x, const mpz_class &h);


ElGamalSignature elgamal_sign(const ElGamalParams &params, const mpz_class &x, const mpz_class &h);

bool elgamal_verify(const ElGamalParams &params, const mpz_class &y, const mpz_class &h, const ElGamalSignature &sig);

Bytes sha256( const Bytes &data);
Bytes sha256(const std::string &data);


Bytes hmac_sha256(const Bytes &key, const Bytes &data);

Bytes aes256_cbc_encrypt(const Bytes &key, const Bytes &data);

Bytes aes256_cbc_decrypt(const Bytes &key, const Bytes &iv, const Bytes &ciphertext);

// random
Bytes secure_random_bytes(size_t n);
mpz_class random_mpz(const mpz_class &upper);

// serialization
Bytes serialize_mpz(const Bytes &data);
mpz_class deserialize_mpz(const Bytes &data);

Bytes deserialize_bytes(const Bytes &buf, size_t &offset);

std::string get_timestamp();
