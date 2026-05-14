#include "crypto_utils.h"

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

// ═══════════════════════════════════════════════════════════════════════════════
//  Modular Arithmetic
// ═══════════════════════════════════════════════════════════════════════════════

mpz_class mod_exp(const mpz_class& base, const mpz_class& exp,
                  const mpz_class& mod) {
    mpz_class result;
    mpz_powm(result.get_mpz_t(), base.get_mpz_t(), exp.get_mpz_t(),
             mod.get_mpz_t());
    return result;
}

mpz_class mod_inverse(const mpz_class& a, const mpz_class& m) {
    mpz_class result;
    if (mpz_invert(result.get_mpz_t(), a.get_mpz_t(), m.get_mpz_t()) == 0) {
        throw std::runtime_error("mod_inverse: inverse does not exist");
    }
    return result;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Random Number Generation
// ═══════════════════════════════════════════════════════════════════════════════
// Bytes = vector<uint8_t>
// this returns secure n bytes random bytes
Bytes secure_random_bytes(size_t n) {
    Bytes buf(n);
    std::ifstream urandom("/dev/urandom", std::ios::binary);
    if (!urandom) throw std::runtime_error("Cannot open /dev/urandom");
    urandom.read(reinterpret_cast<char*>(buf.data()), n);
    if (!urandom) throw std::runtime_error("Failed to read /dev/urandom");
    return buf;
}

mpz_class random_mpz(const mpz_class& upper) {
    // Generate a random number in [1, upper-1]
    // number of bits required to represent upper-1
    size_t bits = mpz_sizeinbase(upper.get_mpz_t(), 2);
    // converting bits to bytes,  +7 help in rounding-up
    size_t byte_len = (bits + 7) / 8;

    mpz_class result;
    do {
        // generating random bytes
        Bytes buf = secure_random_bytes(byte_len);
        // converting random bytes to mpz_class
        mpz_import(result.get_mpz_t(), buf.size(), 1, 1, 0, 0, buf.data());
        // taking modulo to get a number in [0, upper-2]
        result = result % (upper - 1);
    } while (result < 1); // retrying if result is 0

    return result;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Prime & Generator Generation
// ═══════════════════════════════════════════════════════════════════════════════

mpz_class generate_prime(int bits) {
    // Generate a random odd number of `bits` bit-length, then find next prime
    size_t byte_len = (bits + 7) / 8;
    Bytes buf = secure_random_bytes(byte_len);

    mpz_class candidate;
    mpz_import(candidate.get_mpz_t(), buf.size(), 1, 1, 0, 0, buf.data());

    // Ensure exactly `bits` bits: set top bit, clear bits above
    mpz_setbit(candidate.get_mpz_t(), bits - 1);
    // Clear bits above `bits`
    mpz_class mask;
    mpz_ui_pow_ui(mask.get_mpz_t(), 2, bits);
    mask -= 1;
    candidate &= mask;

    // Find next prime
    mpz_class prime;
    mpz_nextprime(prime.get_mpz_t(), candidate.get_mpz_t());

    // Ensure the prime is within the bit-length range (may overshoot by 1 bit)
    // If it does, retry
    if (mpz_sizeinbase(prime.get_mpz_t(), 2) > (size_t)bits) {
        return generate_prime(bits); // retry
    }
    return prime;
}

// Find a safe prime p = 2q+1 where q is also prime, for easier generator finding
// Actually per assignment: we need p such that 2^(SL-1) < p < 2^SL
// and g is a primitive root modulo p.
// For efficiency: find prime p where (p-1)/2 is also prime (safe prime)
// then any quadratic non-residue is a generator.

static mpz_class generate_safe_prime(int bits) {
    // For 2048-bit safe primes, this can take a while
    // Generate q prime, then check if p = 2q + 1 is prime
    while (true) {
        mpz_class q = generate_prime(bits - 1);
        mpz_class p = 2 * q + 1;
        if (mpz_probab_prime_p(p.get_mpz_t(), 25) >= 1) {
            if (mpz_sizeinbase(p.get_mpz_t(), 2) == (size_t)bits) {
                return p;
            }
        }
    }
}

mpz_class find_generator(const mpz_class& p) {
    // For a safe prime p = 2q + 1, the generators are elements of order p-1
    // An element g is a generator if g^2 != 1 mod p and g^q != 1 mod p
    mpz_class q = (p - 1) / 2;
    mpz_class g = 2;
    while (true) {
        if (mod_exp(g, 2, p) != 1 && mod_exp(g, q, p) != 1) {
            return g;
        }
        g += 1;
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  ElGamal — Manual Implementation
// ═══════════════════════════════════════════════════════════════════════════════

ElGamalKeyPair elgamal_keygen(int SL) {
    ElGamalKeyPair kp;
    kp.params.SL = SL;

    // Generate safe prime p of SL bits
    kp.params.p = generate_safe_prime(SL);

    // Find generator g
    kp.params.g = find_generator(kp.params.p);

    // Private key x ∈ [1, p-2]
    kp.x = random_mpz(kp.params.p - 1);

    // Public key y = g^x mod p
    kp.y = mod_exp(kp.params.g, kp.x, kp.params.p);

    return kp;
}

ElGamalCiphertext elgamal_encrypt(const ElGamalParams& params,
                                   const mpz_class& y,
                                   const mpz_class& m) {
    ElGamalCiphertext ct;

    // Random k ∈ [1, p-2]
    mpz_class k = random_mpz(params.p - 1);

    // c1 = g^k mod p
    ct.c1 = mod_exp(params.g, k, params.p);

    // c2 = (m · y^k) mod p
    mpz_class yk = mod_exp(y, k, params.p);
    ct.c2 = (m * yk) % params.p;

    return ct;
}

mpz_class elgamal_decrypt(const ElGamalParams& params,
                           const mpz_class& x,
                           const ElGamalCiphertext& ct) {
    // m = c2 · (c1^x)^(-1) mod p
    mpz_class c1x = mod_exp(ct.c1, x, params.p);
    mpz_class c1x_inv = mod_inverse(c1x, params.p);
    mpz_class m = (ct.c2 * c1x_inv) % params.p;
    return m;
}

ElGamalSignature elgamal_sign(const ElGamalParams& params,
                               const mpz_class& x,
                               const mpz_class& h) {
    ElGamalSignature sig;
    mpz_class p_minus_1 = params.p - 1;

    // Choose random k with gcd(k, p-1) = 1
    mpz_class k, g;
    do {
        k = random_mpz(p_minus_1);
        mpz_gcd(g.get_mpz_t(), k.get_mpz_t(), p_minus_1.get_mpz_t());
    } while (g != 1);

    // r = g^k mod p
    sig.r = mod_exp(params.g, k, params.p);

    // s = (H(m) - x·r) · k^(-1)  mod (p-1)
    mpz_class k_inv = mod_inverse(k, p_minus_1);
    mpz_class xr = (x * sig.r) % p_minus_1;
    mpz_class diff = (h - xr) % p_minus_1;
    if (diff < 0) diff += p_minus_1;
    sig.s = (diff * k_inv) % p_minus_1;

    return sig;
}

bool elgamal_verify(const ElGamalParams& params,
                     const mpz_class& y,
                     const mpz_class& h,
                     const ElGamalSignature& sig) {
    // Check: g^H(m) ≡ y^r · r^s (mod p)
    if (sig.r <= 0 || sig.r >= params.p) return false;

    mpz_class lhs = mod_exp(params.g, h, params.p);
    mpz_class yr = mod_exp(y, sig.r, params.p);
    mpz_class rs = mod_exp(sig.r, sig.s, params.p);
    mpz_class rhs = (yr * rs) % params.p;

    return lhs == rhs;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  SHA-256
// ═══════════════════════════════════════════════════════════════════════════════

Bytes sha256(const Bytes& data) {
    Bytes hash(32);
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, data.data(), data.size());
    unsigned int len = 0;
    EVP_DigestFinal_ex(ctx, hash.data(), &len);
    EVP_MD_CTX_free(ctx);
    return hash;
}

Bytes sha256(const std::string& data) {
    Bytes d(data.begin(), data.end());
    return sha256(d);
}

// ═══════════════════════════════════════════════════════════════════════════════
//  HMAC-SHA256
// ═══════════════════════════════════════════════════════════════════════════════

Bytes hmac_sha256(const Bytes& key, const Bytes& data) {
    Bytes result(32);
    unsigned int len = 0;

    EVP_MAC* mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);

    OSSL_PARAM params_arr[2];
    params_arr[0] = OSSL_PARAM_construct_utf8_string("digest",
                        const_cast<char*>("SHA256"), 0);
    params_arr[1] = OSSL_PARAM_construct_end();

    EVP_MAC_init(ctx, key.data(), key.size(), params_arr);
    EVP_MAC_update(ctx, data.data(), data.size());
    size_t out_len = 0;
    EVP_MAC_final(ctx, result.data(), &out_len, result.size());

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return result;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  AES-256-CBC
// ═══════════════════════════════════════════════════════════════════════════════

Bytes aes256_cbc_encrypt(const Bytes& key, const Bytes& iv,
                          const Bytes& plaintext) {
    if (key.size() != 32) throw std::runtime_error("AES key must be 32 bytes");
    if (iv.size() != 16) throw std::runtime_error("AES IV must be 16 bytes");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());

    // Enable PKCS7 padding (default)
    Bytes ciphertext(plaintext.size() + 16);  // room for padding
    int len = 0, total = 0;

    EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                      plaintext.data(), plaintext.size());
    total = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + total, &len);
    total += len;

    ciphertext.resize(total);
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

Bytes aes256_cbc_decrypt(const Bytes& key, const Bytes& iv,
                          const Bytes& ciphertext) {
    if (key.size() != 32) throw std::runtime_error("AES key must be 32 bytes");
    if (iv.size() != 16) throw std::runtime_error("AES IV must be 16 bytes");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());

    Bytes plaintext(ciphertext.size());
    int len = 0, total = 0;

    EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                      ciphertext.data(), ciphertext.size());
    total = len;
    EVP_DecryptFinal_ex(ctx, plaintext.data() + total, &len);
    total += len;

    plaintext.resize(total);
    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Serialization Helpers
// ═══════════════════════════════════════════════════════════════════════════════

Bytes mpz_to_bytes(const mpz_class& n) {
    size_t count = 0;
    void* raw = mpz_export(nullptr, &count, 1, 1, 0, 0, n.get_mpz_t());
    Bytes result;
    if (raw && count > 0) {
        result.assign(static_cast<uint8_t*>(raw),
                      static_cast<uint8_t*>(raw) + count);
        free(raw);
    } else {
        result.push_back(0);
    }
    return result;
}

mpz_class bytes_to_mpz(const Bytes& b) {
    mpz_class result;
    if (!b.empty()) {
        mpz_import(result.get_mpz_t(), b.size(), 1, 1, 0, 0, b.data());
    }
    return result;
}

std::string bytes_to_hex(const Bytes& b) {
    std::ostringstream ss;
    for (uint8_t byte : b) {
        ss << std::hex << std::setfill('0') << std::setw(2) << (int)byte;
    }
    return ss.str();
}

Bytes hex_to_bytes(const std::string& hex) {
    Bytes result;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        result.push_back(
            static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16)));
    }
    return result;
}

// ─── Network Serialization ────────────────────────────────────────────────────

Bytes serialize_mpz(const mpz_class& n) {
    Bytes data = mpz_to_bytes(n);
    uint32_t len = static_cast<uint32_t>(data.size());
    Bytes result(4 + data.size());
    result[0] = (len >> 24) & 0xFF;
    result[1] = (len >> 16) & 0xFF;
    result[2] = (len >> 8) & 0xFF;
    result[3] = len & 0xFF;
    std::copy(data.begin(), data.end(), result.begin() + 4);
    return result;
}

mpz_class deserialize_mpz(const Bytes& buf, size_t& offset) {
    if (offset + 4 > buf.size())
        throw std::runtime_error("deserialize_mpz: buffer too short for length");

    uint32_t len = (uint32_t(buf[offset]) << 24) |
                   (uint32_t(buf[offset + 1]) << 16) |
                   (uint32_t(buf[offset + 2]) << 8) |
                   uint32_t(buf[offset + 3]);
    offset += 4;

    if (offset + len > buf.size())
        throw std::runtime_error("deserialize_mpz: buffer too short for data");

    Bytes data(buf.begin() + offset, buf.begin() + offset + len);
    offset += len;
    return bytes_to_mpz(data);
}

Bytes serialize_bytes(const Bytes& data) {
    uint32_t len = static_cast<uint32_t>(data.size());
    Bytes result(4 + data.size());
    result[0] = (len >> 24) & 0xFF;
    result[1] = (len >> 16) & 0xFF;
    result[2] = (len >> 8) & 0xFF;
    result[3] = len & 0xFF;
    std::copy(data.begin(), data.end(), result.begin() + 4);
    return result;
}

Bytes deserialize_bytes(const Bytes& buf, size_t& offset) {
    if (offset + 4 > buf.size())
        throw std::runtime_error("deserialize_bytes: buffer too short for length");

    uint32_t len = (uint32_t(buf[offset]) << 24) |
                   (uint32_t(buf[offset + 1]) << 16) |
                   (uint32_t(buf[offset + 2]) << 8) |
                   uint32_t(buf[offset + 3]);
    offset += 4;

    if (offset + len > buf.size())
        throw std::runtime_error("deserialize_bytes: buffer too short for data");

    Bytes data(buf.begin() + offset, buf.begin() + offset + len);
    offset += len;
    return data;
}

std::string get_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto epoch = now.time_since_epoch();
    auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(epoch);
    return std::to_string(millis.count());
}
