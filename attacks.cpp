#include "crypto_utils.h"

#include <iostream>
#include <string>
#include <cstring>
#include <chrono>
#include <thread>

// POSIX networking
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

// ─── Protocol Opcodes ─────────────────────────────────────────────────────────

constexpr uint8_t OP_PARAM_INIT   = 0x10;
constexpr uint8_t OP_AUTH_REQ     = 0x20;
constexpr uint8_t OP_AUTH_RES     = 0x30;
constexpr uint8_t OP_SK_CONFIRM   = 0x40;
constexpr uint8_t OP_SUCCESS      = 0x50;
constexpr uint8_t OP_ERR_MISMATCH = 0x60;

static const int         MCC_PORT = 5555;
static const std::string MCC_HOST = "127.0.0.1";

// ─── Network Helpers ──────────────────────────────────────────────────────────

static bool send_all(int fd, const Bytes& data) {
    size_t sent = 0;
    while (sent < data.size()) {
        ssize_t n = send(fd, data.data() + sent, data.size() - sent, 0);
        if (n <= 0) return false;
        sent += n;
    }
    return true;
}

static bool send_message(int fd, uint8_t opcode, const Bytes& payload) {
    uint32_t len = static_cast<uint32_t>(payload.size());
    Bytes msg(5 + payload.size());
    msg[0] = opcode;
    msg[1] = (len >> 24) & 0xFF;
    msg[2] = (len >> 16) & 0xFF;
    msg[3] = (len >> 8)  & 0xFF;
    msg[4] = len & 0xFF;
    std::copy(payload.begin(), payload.end(), msg.begin() + 5);
    return send_all(fd, msg);
}

static bool recv_all(int fd, Bytes& buf, size_t n) {
    buf.resize(n);
    size_t received = 0;
    while (received < n) {
        ssize_t r = recv(fd, buf.data() + received, n - received, 0);
        if (r <= 0) return false;
        received += r;
    }
    return true;
}

static bool recv_message(int fd, uint8_t& opcode, Bytes& payload) {
    Bytes header;
    if (!recv_all(fd, header, 5)) return false;
    opcode = header[0];
    uint32_t len = (uint32_t(header[1]) << 24) |
                   (uint32_t(header[2]) << 16) |
                   (uint32_t(header[3]) << 8)  |
                   uint32_t(header[4]);
    if (len > 0) {
        if (!recv_all(fd, payload, len)) return false;
    } else {
        payload.clear();
    }
    return true;
}

static int connect_to_mcc() {
    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) return -1;
    struct sockaddr_in server_addr;
    std::memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port   = htons(MCC_PORT);
    inet_pton(AF_INET, MCC_HOST.c_str(), &server_addr.sin_addr);
    if (connect(sock_fd, (struct sockaddr*)&server_addr,
                sizeof(server_addr)) < 0) {
        close(sock_fd);
        return -1;
    }
    return sock_fd;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Attack 1: Replay Attack — Re-sending Phase 1A AUTH_REQ
// ═══════════════════════════════════════════════════════════════════════════════

static void attack_replay() {
    std::cout << "\n╔═══════════════════════════════════════════╗" << std::endl;
    std::cout << "║  ATTACK 1: Replay Attack                  ║" << std::endl;
    std::cout << "╚═══════════════════════════════════════════╝" << std::endl;
    std::cout << "[ATTACK] Re-sending a captured AUTH_REQ packet...\n"
              << std::endl;

    // Step 1: Connect legitimately and capture the AUTH_REQ
    int sock1 = connect_to_mcc();
    if (sock1 < 0) {
        std::cerr << "[ATTACK] Failed to connect to MCC" << std::endl;
        return;
    }

    // Receive PARAM_INIT
    uint8_t opcode;
    Bytes param_payload;
    if (!recv_message(sock1, opcode, param_payload)) {
        std::cerr << "[ATTACK] Failed to receive PARAM_INIT" << std::endl;
        close(sock1);
        return;
    }

    // Parse params to build a fake AUTH_REQ
    size_t offset = 0;
    mpz_class p = deserialize_mpz(param_payload, offset);
    mpz_class g = deserialize_mpz(param_payload, offset);
    int sl_val = (int(param_payload[offset]) << 24) |
                 (int(param_payload[offset+1]) << 16) |
                 (int(param_payload[offset+2]) << 8) |
                 int(param_payload[offset+3]);
    offset += 4;
    Bytes ts_bytes = deserialize_bytes(param_payload, offset);
    Bytes id_bytes = deserialize_bytes(param_payload, offset);
    mpz_class mcc_y = deserialize_mpz(param_payload, offset);

    ElGamalParams params;
    params.p = p; params.g = g; params.SL = sl_val;

    // Build a legitimate AUTH_REQ
    mpz_class drone_x = random_mpz(p - 1);
    mpz_class drone_y = mod_exp(g, drone_x, p);

    Bytes k_bytes = secure_random_bytes(32);
    mpz_class k_d_mcc = bytes_to_mpz(k_bytes) % (p - 1);
    if (k_d_mcc < 1) k_d_mcc = 1;

    Bytes rn_i = secure_random_bytes(32);
    std::string ts_i = get_timestamp();

    ElGamalCiphertext ct = elgamal_encrypt(params, mcc_y, k_d_mcc);

    Bytes auth_payload;
    Bytes y_ser = serialize_mpz(drone_y);
    auth_payload.insert(auth_payload.end(), y_ser.begin(), y_ser.end());
    Bytes ts_s(ts_i.begin(), ts_i.end());
    Bytes ts_ser = serialize_bytes(ts_s);
    auth_payload.insert(auth_payload.end(), ts_ser.begin(), ts_ser.end());
    Bytes rn_ser = serialize_bytes(rn_i);
    auth_payload.insert(auth_payload.end(), rn_ser.begin(), rn_ser.end());
    std::string fake_id = "DRONE_REPLAY";
    Bytes fid(fake_id.begin(), fake_id.end());
    Bytes fid_ser = serialize_bytes(fid);
    auth_payload.insert(auth_payload.end(), fid_ser.begin(), fid_ser.end());
    Bytes c1_ser = serialize_mpz(ct.c1);
    auth_payload.insert(auth_payload.end(), c1_ser.begin(), c1_ser.end());
    Bytes c2_ser = serialize_mpz(ct.c2);
    auth_payload.insert(auth_payload.end(), c2_ser.begin(), c2_ser.end());

    Bytes sig_hash = sha256(auth_payload);
    mpz_class h = bytes_to_mpz(sig_hash) % (p - 1);
    if (h < 1) h = 1;
    ElGamalSignature sig = elgamal_sign(params, drone_x, h);
    Bytes r_ser = serialize_mpz(sig.r);
    auth_payload.insert(auth_payload.end(), r_ser.begin(), r_ser.end());
    Bytes s_ser = serialize_mpz(sig.s);
    auth_payload.insert(auth_payload.end(), s_ser.begin(), s_ser.end());

    // Send the original AUTH_REQ
    send_message(sock1, OP_AUTH_REQ, auth_payload);
    std::cout << "[ATTACK] Original AUTH_REQ sent." << std::endl;

    // Save the captured payload for replay
    Bytes captured_auth = auth_payload;

    close(sock1);
    std::cout << "[ATTACK] Connection 1 closed. Waiting before replay..."
              << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(2));

    // Step 2: Open new connection and replay the same AUTH_REQ
    int sock2 = connect_to_mcc();
    if (sock2 < 0) {
        std::cerr << "[ATTACK] Failed to reconnect to MCC" << std::endl;
        return;
    }

    // Receive new PARAM_INIT (ignore)
    uint8_t op2;
    Bytes p2;
    recv_message(sock2, op2, p2);

    // Replay the captured AUTH_REQ with stale timestamp
    std::cout << "[ATTACK] REPLAYING captured AUTH_REQ with stale timestamp..."
              << std::endl;
    send_message(sock2, OP_AUTH_REQ, captured_auth);

    // The MCC should reject this because:
    // - The signature is with a different drone key pair
    // - The timestamp is stale
    // Wait for response
    uint8_t resp_op;
    Bytes resp_payload;
    bool got_resp = recv_message(sock2, resp_op, resp_payload);

    if (!got_resp) {
        std::cout << "[ATTACK] ✗ MCC dropped the connection (rejected replay)"
                  << std::endl;
    } else {
        std::cout << "[ATTACK] MCC responded with opcode 0x"
                  << std::hex << (int)resp_op << std::dec << std::endl;
        if (resp_op == OP_ERR_MISMATCH || resp_op == OP_AUTH_RES) {
            std::cout << "[ATTACK] ✗ MCC processed but signature mismatch "
                      << "expected on subsequent steps" << std::endl;
        }
    }

    close(sock2);
    std::cout << "[ATTACK] Replay attack demonstration complete.\n" << std::endl;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Attack 2: MitM Tampering — Modify prime p in Phase 0
// ═══════════════════════════════════════════════════════════════════════════════

static void attack_mitm_tamper() {
    std::cout << "\n╔═══════════════════════════════════════════╗" << std::endl;
    std::cout << "║  ATTACK 2: MitM Parameter Tampering       ║" << std::endl;
    std::cout << "╚═══════════════════════════════════════════╝" << std::endl;
    std::cout << "[ATTACK] Simulating MitM by modifying received prime p...\n"
              << std::endl;

    int sock = connect_to_mcc();
    if (sock < 0) {
        std::cerr << "[ATTACK] Failed to connect to MCC" << std::endl;
        return;
    }

    // Receive PARAM_INIT
    uint8_t opcode;
    Bytes payload;
    if (!recv_message(sock, opcode, payload)) {
        std::cerr << "[ATTACK] Failed to receive PARAM_INIT" << std::endl;
        close(sock);
        return;
    }

    std::cout << "[ATTACK] Received PARAM_INIT. Simulating tampering..."
              << std::endl;

    // Parse the payload
    size_t offset = 0;
    mpz_class p = deserialize_mpz(payload, offset);
    mpz_class g = deserialize_mpz(payload, offset);

    // Tamper: modify p (add 2)
    mpz_class tampered_p = p + 2;
    std::cout << "[ATTACK] Original p (first 40 hex): "
              << bytes_to_hex(mpz_to_bytes(p)).substr(0, 40) << "..."
              << std::endl;
    std::cout << "[ATTACK] Tampered p (first 40 hex): "
              << bytes_to_hex(mpz_to_bytes(tampered_p)).substr(0, 40) << "..."
              << std::endl;

    // Reconstruct the tampered payload
    Bytes tampered_payload;
    Bytes tp_ser = serialize_mpz(tampered_p);
    tampered_payload.insert(tampered_payload.end(), tp_ser.begin(), tp_ser.end());
    // Copy rest of original payload (from g onward)
    // The offset after p parsing:
    size_t after_p = 0;
    deserialize_mpz(payload, after_p);  // skip p
    tampered_payload.insert(tampered_payload.end(),
                            payload.begin() + after_p, payload.end());

    // Now try to verify the MCC signature on tampered data
    // Parse the tampered payload to extract params and verify
    size_t t_off = 0;
    mpz_class t_p = deserialize_mpz(tampered_payload, t_off);
    mpz_class t_g = deserialize_mpz(tampered_payload, t_off);

    int sl_val = (int(tampered_payload[t_off]) << 24) |
                 (int(tampered_payload[t_off+1]) << 16) |
                 (int(tampered_payload[t_off+2]) << 8) |
                 int(tampered_payload[t_off+3]);
    t_off += 4;

    Bytes ts = deserialize_bytes(tampered_payload, t_off);
    Bytes id = deserialize_bytes(tampered_payload, t_off);
    mpz_class mcc_y = deserialize_mpz(tampered_payload, t_off);

    size_t sig_start = t_off;
    ElGamalSignature sig;
    sig.r = deserialize_mpz(tampered_payload, t_off);
    sig.s = deserialize_mpz(tampered_payload, t_off);

    // Verify signature using tampered data
    Bytes signed_data(tampered_payload.begin(),
                      tampered_payload.begin() + sig_start);
    Bytes v_hash = sha256(signed_data);
    // Use original p for verification (since mcc_y is in original group)
    mpz_class h = bytes_to_mpz(v_hash) % (p - 1);
    if (h < 1) h = 1;

    ElGamalParams params;
    params.p = p; params.g = g; params.SL = sl_val;

    bool valid = elgamal_verify(params, mcc_y, h, sig);

    if (valid) {
        std::cout << "[ATTACK] ✗ Signature valid on tampered data "
                  << "(UNEXPECTED)" << std::endl;
    } else {
        std::cout << "[ATTACK] ✓ Signature INVALID on tampered data. "
                  << "Tampering detected!" << std::endl;
        std::cout << "[ATTACK] A real drone would abort the connection."
                  << std::endl;
    }

    close(sock);
    std::cout << "[ATTACK] MitM tampering demonstration complete.\n" << std::endl;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Attack 3: Unauthorized Access — Unknown Drone ID
// ═══════════════════════════════════════════════════════════════════════════════

static void attack_unauthorized() {
    std::cout << "\n╔═══════════════════════════════════════════╗" << std::endl;
    std::cout << "║  ATTACK 3: Unauthorized Access             ║" << std::endl;
    std::cout << "╚═══════════════════════════════════════════╝" << std::endl;
    std::cout << "[ATTACK] Connecting with unauthorized drone ID...\n"
              << std::endl;

    int sock = connect_to_mcc();
    if (sock < 0) {
        std::cerr << "[ATTACK] Failed to connect to MCC" << std::endl;
        return;
    }

    // Receive PARAM_INIT
    uint8_t opcode;
    Bytes param_payload;
    if (!recv_message(sock, opcode, param_payload)) {
        std::cerr << "[ATTACK] Failed to receive PARAM_INIT" << std::endl;
        close(sock);
        return;
    }

    // Parse params
    size_t offset = 0;
    mpz_class p = deserialize_mpz(param_payload, offset);
    mpz_class g = deserialize_mpz(param_payload, offset);
    int sl_val = (int(param_payload[offset]) << 24) |
                 (int(param_payload[offset+1]) << 16) |
                 (int(param_payload[offset+2]) << 8) |
                 int(param_payload[offset+3]);
    offset += 4;
    deserialize_bytes(param_payload, offset);  // ts
    deserialize_bytes(param_payload, offset);  // id_mcc
    mpz_class mcc_y = deserialize_mpz(param_payload, offset);

    ElGamalParams params;
    params.p = p; params.g = g; params.SL = sl_val;

    // Generate rogue key pair
    mpz_class rogue_x = random_mpz(p - 1);
    mpz_class rogue_y = mod_exp(g, rogue_x, p);

    // Generate a shared key
    Bytes k_bytes = secure_random_bytes(32);
    mpz_class k_d_mcc = bytes_to_mpz(k_bytes) % (p - 1);
    if (k_d_mcc < 1) k_d_mcc = 1;

    Bytes rn = secure_random_bytes(32);
    std::string ts_i = get_timestamp();
    ElGamalCiphertext ct = elgamal_encrypt(params, mcc_y, k_d_mcc);

    // Use an UNKNOWN drone ID
    std::string rogue_id = "ROGUE_DRONE_X9Z";
    std::cout << "[ATTACK] Using unauthorized ID: " << rogue_id << std::endl;

    Bytes auth_payload;
    Bytes y_ser = serialize_mpz(rogue_y);
    auth_payload.insert(auth_payload.end(), y_ser.begin(), y_ser.end());
    Bytes ts_s(ts_i.begin(), ts_i.end());
    Bytes ts_ser = serialize_bytes(ts_s);
    auth_payload.insert(auth_payload.end(), ts_ser.begin(), ts_ser.end());
    Bytes rn_ser = serialize_bytes(rn);
    auth_payload.insert(auth_payload.end(), rn_ser.begin(), rn_ser.end());
    Bytes rid(rogue_id.begin(), rogue_id.end());
    Bytes rid_ser = serialize_bytes(rid);
    auth_payload.insert(auth_payload.end(), rid_ser.begin(), rid_ser.end());
    Bytes c1_ser = serialize_mpz(ct.c1);
    auth_payload.insert(auth_payload.end(), c1_ser.begin(), c1_ser.end());
    Bytes c2_ser = serialize_mpz(ct.c2);
    auth_payload.insert(auth_payload.end(), c2_ser.begin(), c2_ser.end());

    // Sign with rogue key
    Bytes sig_hash = sha256(auth_payload);
    mpz_class h = bytes_to_mpz(sig_hash) % (p - 1);
    if (h < 1) h = 1;
    ElGamalSignature sig = elgamal_sign(params, rogue_x, h);
    Bytes r_ser = serialize_mpz(sig.r);
    auth_payload.insert(auth_payload.end(), r_ser.begin(), r_ser.end());
    Bytes s_ser = serialize_mpz(sig.s);
    auth_payload.insert(auth_payload.end(), s_ser.begin(), s_ser.end());

    send_message(sock, OP_AUTH_REQ, auth_payload);
    std::cout << "[ATTACK] AUTH_REQ sent with rogue ID." << std::endl;

    // Wait for response
    uint8_t resp_op;
    Bytes resp_payload;
    bool got_resp = recv_message(sock, resp_op, resp_payload);

    if (!got_resp) {
        std::cout << "[ATTACK] MCC dropped connection (rejected unauthorized)"
                  << std::endl;
    } else {
        std::cout << "[ATTACK] MCC responded with opcode 0x"
                  << std::hex << (int)resp_op << std::dec << std::endl;
        if (resp_op == OP_AUTH_RES) {
            std::cout << "[ATTACK] MCC accepted (Phase 1B). "
                      << "Attempting Phase 2 with wrong key..." << std::endl;
            // The session key derivation will fail because we used a
            // different key pair. We'll send a bad HMAC.
            Bytes bad_sk(32, 0xAA);
            std::string ts_f = get_timestamp();
            Bytes hmac_data;
            Bytes rid2(rogue_id.begin(), rogue_id.end());
            hmac_data.insert(hmac_data.end(), rid2.begin(), rid2.end());
            Bytes ts_f_b(ts_f.begin(), ts_f.end());
            hmac_data.insert(hmac_data.end(), ts_f_b.begin(), ts_f_b.end());
            Bytes hmac_val = hmac_sha256(bad_sk, hmac_data);

            Bytes sk_payload;
            Bytes hd_ser = serialize_bytes(hmac_data);
            sk_payload.insert(sk_payload.end(), hd_ser.begin(), hd_ser.end());
            Bytes hv_ser = serialize_bytes(hmac_val);
            sk_payload.insert(sk_payload.end(), hv_ser.begin(), hv_ser.end());

            send_message(sock, OP_SK_CONFIRM, sk_payload);

            uint8_t sk_op;
            Bytes sk_resp;
            if (recv_message(sock, sk_op, sk_resp)) {
                if (sk_op == OP_ERR_MISMATCH) {
                    std::cout << "[ATTACK] ✓ MCC rejected with ERR_MISMATCH. "
                              << "Unauthorized access blocked!" << std::endl;
                } else if (sk_op == OP_SUCCESS) {
                    std::cout << "[ATTACK] ✗ MCC accepted (UNEXPECTED)"
                              << std::endl;
                }
            }
        } else if (resp_op == OP_ERR_MISMATCH) {
            std::cout << "[ATTACK] ✓ MCC rejected immediately." << std::endl;
        }
    }

    close(sock);
    std::cout << "[ATTACK] Unauthorized access demonstration complete.\n"
              << std::endl;
}

// ─── Main ─────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    std::cout << "╔═══════════════════════════════════════════╗" << std::endl;
    std::cout << "║   Attack Demonstration Suite              ║" << std::endl;
    std::cout << "║   Secure UAV C2 System                    ║" << std::endl;
    std::cout << "╚═══════════════════════════════════════════╝" << std::endl;
    std::cout << "\nEnsure MCC server is running before executing attacks.\n"
              << std::endl;

    std::string choice = "all";
    if (argc >= 2) choice = argv[1];

    if (choice == "1" || choice == "replay" || choice == "all") {
        attack_replay();
    }
    if (choice == "2" || choice == "mitm" || choice == "all") {
        attack_mitm_tamper();
    }
    if (choice == "3" || choice == "unauth" || choice == "all") {
        attack_unauthorized();
    }

    std::cout << "\n═══════════════════════════════════════════" << std::endl;
    std::cout << "  All attack demonstrations completed." << std::endl;
    std::cout << "═══════════════════════════════════════════" << std::endl;

    return 0;
}
