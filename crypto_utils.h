#pragma once

#include <gmpxx.h>
#include <string>
#include <vector>
#include <cstdint>

// ─── Data types ───────────────────────────────────────────────────────────────

using Bytes = std::vector<uint8_t>;

struct ElGamalParams {
    mpz_class p;   // large prime
    mpz_class g;   // generator (primitive root mod p)
    int SL;        // security level (bit-length of p)
};

struct ElGamalKeyPair {
    ElGamalParams params;
    mpz_class x;   // private key: random in [1, p-2]
    mpz_class y;   // public key:  g^x mod p
};

struct ElGamalCiphertext {
    mpz_class c1;
    mpz_class c2;
};

struct ElGamalSignature {
    mpz_class r;
    mpz_class s;
};

// ─── Modular Arithmetic (Manual) ──────────────────────────────────────────────

// Compute (base^exp) mod mod — square-and-multiply via GMP
mpz_class mod_exp(const mpz_class& base, const mpz_class& exp, const mpz_class& mod);

// Compute modular inverse of a mod m using extended Euclidean (GMP)
mpz_class mod_inverse(const mpz_class& a, const mpz_class& m);

// ─── Prime / Generator Generation ─────────────────────────────────────────────

// Generate a random prime of exactly `bits` bit-length
mpz_class generate_prime(int bits);

// Find a primitive root (generator) modulo prime p
mpz_class find_generator(const mpz_class& p);

// ─── ElGamal (Manual Implementation) ──────────────────────────────────────────

// Generate ElGamal key pair with given security level
ElGamalKeyPair elgamal_keygen(int SL);

// Encrypt message m ∈ [0, p-1]. Returns (c1, c2)
ElGamalCiphertext elgamal_encrypt(const ElGamalParams& params,
                                   const mpz_class& y,
                                   const mpz_class& m);

// Decrypt ciphertext → m
mpz_class elgamal_decrypt(const ElGamalParams& params,
                           const mpz_class& x,
                           const ElGamalCiphertext& ct);

// Sign hash H(m) — returns (r, s) where gcd(k, p-1) = 1
ElGamalSignature elgamal_sign(const ElGamalParams& params,
                               const mpz_class& x,
                               const mpz_class& h);

// Verify signature (r, s) against hash h
bool elgamal_verify(const ElGamalParams& params,
                     const mpz_class& y,
                     const mpz_class& h,
                     const ElGamalSignature& sig);

// ─── Hash / HMAC / AES Wrappers (OpenSSL) ─────────────────────────────────────

// SHA-256 hash
Bytes sha256(const Bytes& data);
Bytes sha256(const std::string& data);

// HMAC-SHA256
Bytes hmac_sha256(const Bytes& key, const Bytes& data);

// AES-256-CBC encrypt (PKCS7 padding)
Bytes aes256_cbc_encrypt(const Bytes& key, const Bytes& iv, const Bytes& plaintext);

// AES-256-CBC decrypt (PKCS7 unpadding)
Bytes aes256_cbc_decrypt(const Bytes& key, const Bytes& iv, const Bytes& ciphertext);

// ─── Random ───────────────────────────────────────────────────────────────────

// Cryptographically secure random bytes from /dev/urandom
Bytes secure_random_bytes(size_t n);

// Random mpz in range [1, upper-1]
mpz_class random_mpz(const mpz_class& upper);

// ─── Serialisation Helpers ────────────────────────────────────────────────────

Bytes mpz_to_bytes(const mpz_class& n);
mpz_class bytes_to_mpz(const Bytes& b);
std::string bytes_to_hex(const Bytes& b);
Bytes hex_to_bytes(const std::string& hex);

// ─── Network Serialisation ────────────────────────────────────────────────────

// Serialize mpz_class to length-prefixed bytes (4-byte big-endian length + data)
Bytes serialize_mpz(const mpz_class& n);

// Deserialize mpz_class from buffer at offset; advances offset
mpz_class deserialize_mpz(const Bytes& buf, size_t& offset);

// Serialize a Bytes vector with 4-byte length prefix
Bytes serialize_bytes(const Bytes& data);

// Deserialize a Bytes vector from buffer at offset; advances offset
Bytes deserialize_bytes(const Bytes& buf, size_t& offset);

// Get current timestamp as string
std::string get_timestamp();
