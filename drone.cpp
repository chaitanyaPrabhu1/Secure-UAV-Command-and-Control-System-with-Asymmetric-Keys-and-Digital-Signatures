#include "crypto_utils.h"

#include <iostream>
#include <string>
#include <sstream>
#include <vector>
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
constexpr uint8_t OP_GROUP_KEY    = 0x70;
constexpr uint8_t OP_GROUP_CMD    = 0x80;
constexpr uint8_t OP_SHUTDOWN     = 0x90;

// ─── Configuration ────────────────────────────────────────────────────────────

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

// ─── Phase 0: Receive and Validate Parameters ────────────────────────────────

struct Phase0Data {
    ElGamalParams params;
    mpz_class     mcc_pub_key; // y_MCC
    std::string   mcc_id;
    std::string   ts0;
};

static bool phase0_recv_params(int sock_fd, Phase0Data& data) {
    std::cout << "[DRONE] Phase 0: Waiting for parameters..." << std::endl;

    uint8_t opcode;
    Bytes payload;
    if (!recv_message(sock_fd, opcode, payload)) {
        std::cerr << "[DRONE] Failed to receive PARAM_INIT" << std::endl;
        return false;
    }
    if (opcode != OP_PARAM_INIT) {
        std::cerr << "[DRONE] Expected PARAM_INIT (0x10), got 0x"
                  << std::hex << (int)opcode << std::dec << std::endl;
        return false;
    }

    size_t offset = 0;

    // Parse p
    data.params.p = deserialize_mpz(payload, offset);

    // Parse g
    data.params.g = deserialize_mpz(payload, offset);

    // Parse SL (4 bytes)
    if (offset + 4 > payload.size()) {
        std::cerr << "[DRONE] Payload too short for SL" << std::endl;
        return false;
    }
    data.params.SL = (int(payload[offset]) << 24) |
                     (int(payload[offset+1]) << 16) |
                     (int(payload[offset+2]) << 8) |
                     int(payload[offset+3]);
    offset += 4;

    // Parse TS_0
    Bytes ts_bytes = deserialize_bytes(payload, offset);
    data.ts0 = std::string(ts_bytes.begin(), ts_bytes.end());

    // Parse ID_MCC
    Bytes id_bytes = deserialize_bytes(payload, offset);
    data.mcc_id = std::string(id_bytes.begin(), id_bytes.end());

    // Parse MCC public key y
    data.mcc_pub_key = deserialize_mpz(payload, offset);

    // Security validation (§Phase 0, step 4)
    // Check SL >= 2048
    if (data.params.SL < 2048) {
        std::cerr << "[DRONE] SECURITY: SL=" << data.params.SL
                  << " is below minimum 2048. ABORTING." << std::endl;
        return false;
    }

    // Check len(bin(p)) ≈ SL
    size_t p_bits = mpz_sizeinbase(data.params.p.get_mpz_t(), 2);
    if (p_bits < (size_t)(data.params.SL - 1) ||
        p_bits > (size_t)(data.params.SL + 1)) {
        std::cerr << "[DRONE] SECURITY: p has " << p_bits
                  << " bits but SL=" << data.params.SL
                  << ". Inconsistency detected. ABORTING." << std::endl;
        return false;
    }

    // Verify MCC signature
    // Signed data is everything before the signature (r, s)
    // We need to find where the signature starts
    size_t sig_start = offset;  // at this point, offset is at sig.r

    Bytes signed_data(payload.begin(), payload.begin() + sig_start);
    Bytes v_hash = sha256(signed_data);
    mpz_class h = bytes_to_mpz(v_hash);
    h = h % (data.params.p - 1);
    if (h < 1) h = 1;

    // Parse signature
    ElGamalSignature sig;
    sig.r = deserialize_mpz(payload, offset);
    sig.s = deserialize_mpz(payload, offset);

    if (!elgamal_verify(data.params, data.mcc_pub_key, h, sig)) {
        std::cerr << "[DRONE] SECURITY: MCC signature verification FAILED. "
                  << "ABORTING." << std::endl;
        return false;
    }

    std::cout << "[DRONE] Phase 0: Parameters received and validated."
              << std::endl;
    std::cout << "[DRONE]   SL=" << data.params.SL
              << "  p bits=" << p_bits
              << "  g=" << data.params.g
              << "  MCC_ID=" << data.mcc_id << std::endl;

    return true;
}

// ─── Phase 1A: Send AUTH_REQ to MCC ───────────────────────────────────────────

struct Phase1AData {
    std::string ts_i;
    Bytes       rn_i;
    mpz_class   k_d_mcc;    // shared secret key
    mpz_class   drone_x;    // drone's private key
    mpz_class   drone_y;    // drone's public key
};

static bool phase1a_send_auth(int sock_fd, const Phase0Data& p0,
                               const std::string& drone_id,
                               Phase1AData& data) {
    std::cout << "[DRONE] Phase 1A: Generating auth request..." << std::endl;

    // Generate drone's ElGamal key pair (using MCC's params)
    data.drone_x = random_mpz(p0.params.p - 1);
    data.drone_y = mod_exp(p0.params.g, data.drone_x, p0.params.p);

    // Generate random 256-bit K_D,MCC and nonce RN_i
    Bytes k_bytes = secure_random_bytes(32);
    data.k_d_mcc = bytes_to_mpz(k_bytes);
    // Ensure K_D,MCC < p
    data.k_d_mcc = data.k_d_mcc % (p0.params.p - 1);
    if (data.k_d_mcc < 1) data.k_d_mcc = 1;

    data.rn_i = secure_random_bytes(32);
    data.ts_i = get_timestamp();

    // Encrypt K_D,MCC with MCC's public key
    ElGamalCiphertext ct = elgamal_encrypt(p0.params, p0.mcc_pub_key,
                                            data.k_d_mcc);

    // Build payload: drone_y | TS_i | RN_i | ID_D | C_i(c1, c2)
    Bytes payload;

    Bytes y_ser = serialize_mpz(data.drone_y);
    payload.insert(payload.end(), y_ser.begin(), y_ser.end());

    Bytes ts_bytes(data.ts_i.begin(), data.ts_i.end());
    Bytes ts_ser = serialize_bytes(ts_bytes);
    payload.insert(payload.end(), ts_ser.begin(), ts_ser.end());

    Bytes rn_ser = serialize_bytes(data.rn_i);
    payload.insert(payload.end(), rn_ser.begin(), rn_ser.end());

    Bytes id_bytes(drone_id.begin(), drone_id.end());
    Bytes id_ser = serialize_bytes(id_bytes);
    payload.insert(payload.end(), id_ser.begin(), id_ser.end());

    Bytes c1_ser = serialize_mpz(ct.c1);
    payload.insert(payload.end(), c1_ser.begin(), c1_ser.end());
    Bytes c2_ser = serialize_mpz(ct.c2);
    payload.insert(payload.end(), c2_ser.begin(), c2_ser.end());

    // Sign the payload (before appending signature)
    Bytes sig_hash = sha256(payload);
    mpz_class h = bytes_to_mpz(sig_hash);
    h = h % (p0.params.p - 1);
    if (h < 1) h = 1;
    ElGamalSignature sig = elgamal_sign(p0.params, data.drone_x, h);

    Bytes r_ser = serialize_mpz(sig.r);
    payload.insert(payload.end(), r_ser.begin(), r_ser.end());
    Bytes s_ser = serialize_mpz(sig.s);
    payload.insert(payload.end(), s_ser.begin(), s_ser.end());

    if (!send_message(sock_fd, OP_AUTH_REQ, payload)) {
        std::cerr << "[DRONE] Failed to send AUTH_REQ" << std::endl;
        return false;
    }

    std::cout << "[DRONE] Phase 1A: AUTH_REQ sent." << std::endl;
    return true;
}

// ─── Phase 1B: Receive AUTH_RES from MCC ──────────────────────────────────────

struct Phase1BData {
    std::string ts_mcc;
    Bytes       rn_mcc;
};

static bool phase1b_recv_auth_res(int sock_fd, const Phase0Data& p0,
                                   const Phase1AData& a, Phase1BData& b) {
    std::cout << "[DRONE] Phase 1B: Waiting for AUTH_RES..." << std::endl;

    uint8_t opcode;
    Bytes payload;
    if (!recv_message(sock_fd, opcode, payload)) {
        std::cerr << "[DRONE] Failed to receive AUTH_RES" << std::endl;
        return false;
    }
    if (opcode != OP_AUTH_RES) {
        std::cerr << "[DRONE] Expected AUTH_RES (0x30), got 0x"
                  << std::hex << (int)opcode << std::dec << std::endl;
        return false;
    }

    size_t offset = 0;

    // TS_MCC
    Bytes ts_bytes = deserialize_bytes(payload, offset);
    b.ts_mcc = std::string(ts_bytes.begin(), ts_bytes.end());

    // RN_MCC
    b.rn_mcc = deserialize_bytes(payload, offset);

    // ID_MCC
    Bytes id_bytes = deserialize_bytes(payload, offset);
    std::string recv_mcc_id(id_bytes.begin(), id_bytes.end());

    // C_MCC (encrypted K_D,MCC)
    ElGamalCiphertext ct;
    ct.c1 = deserialize_mpz(payload, offset);
    ct.c2 = deserialize_mpz(payload, offset);

    // Find sig start
    size_t sig_start = offset;

    // Signature
    ElGamalSignature sig;
    sig.r = deserialize_mpz(payload, offset);
    sig.s = deserialize_mpz(payload, offset);

    // Verify MCC signature
    Bytes signed_data(payload.begin(), payload.begin() + sig_start);
    Bytes v_hash = sha256(signed_data);
    mpz_class h = bytes_to_mpz(v_hash);
    h = h % (p0.params.p - 1);
    if (h < 1) h = 1;

    if (!elgamal_verify(p0.params, p0.mcc_pub_key, h, sig)) {
        std::cerr << "[DRONE] Phase 1B: MCC signature verification FAILED."
                  << std::endl;
        return false;
    }

    // Decrypt C_MCC to verify same K_D,MCC
    mpz_class k_verify = elgamal_decrypt(p0.params, a.drone_x, ct);
    if (k_verify != a.k_d_mcc) {
        std::cerr << "[DRONE] Phase 1B: K_D,MCC mismatch! MCC may be "
                  << "compromised." << std::endl;
        return false;
    }

    std::cout << "[DRONE] Phase 1B: AUTH_RES verified. K_D,MCC confirmed."
              << std::endl;
    return true;
}

// ─── Phase 2: Session Key Derivation & Confirmation ───────────────────────────

static bool phase2_session_key(int sock_fd, const Phase1AData& a,
                                const Phase1BData& b,
                                const std::string& drone_id,
                                Bytes& sk_out) {
    std::cout << "[DRONE] Phase 2: Deriving session key..." << std::endl;

    // SK = SHA256(K_D,MCC || TS_i || TS_MCC || RN_i || RN_MCC)
    Bytes sk_input;
    Bytes k_bytes = mpz_to_bytes(a.k_d_mcc);
    sk_input.insert(sk_input.end(), k_bytes.begin(), k_bytes.end());
    Bytes ts_i(a.ts_i.begin(), a.ts_i.end());
    sk_input.insert(sk_input.end(), ts_i.begin(), ts_i.end());
    Bytes ts_m(b.ts_mcc.begin(), b.ts_mcc.end());
    sk_input.insert(sk_input.end(), ts_m.begin(), ts_m.end());
    sk_input.insert(sk_input.end(), a.rn_i.begin(), a.rn_i.end());
    sk_input.insert(sk_input.end(), b.rn_mcc.begin(), b.rn_mcc.end());

    sk_out = sha256(sk_input);

    std::cout << "[DRONE] Session Key: " << bytes_to_hex(sk_out) << std::endl;

    // Send HMAC confirmation: HMAC_SK(ID_D || TS_final)
    std::string ts_final = get_timestamp();
    Bytes hmac_data;
    Bytes id_bytes(drone_id.begin(), drone_id.end());
    hmac_data.insert(hmac_data.end(), id_bytes.begin(), id_bytes.end());
    Bytes ts_bytes(ts_final.begin(), ts_final.end());
    hmac_data.insert(hmac_data.end(), ts_bytes.begin(), ts_bytes.end());

    Bytes hmac_val = hmac_sha256(sk_out, hmac_data);

    // Payload: hmac_data | hmac_val
    Bytes payload;
    Bytes hd_ser = serialize_bytes(hmac_data);
    payload.insert(payload.end(), hd_ser.begin(), hd_ser.end());
    Bytes hv_ser = serialize_bytes(hmac_val);
    payload.insert(payload.end(), hv_ser.begin(), hv_ser.end());

    if (!send_message(sock_fd, OP_SK_CONFIRM, payload)) {
        std::cerr << "[DRONE] Failed to send SK_CONFIRM" << std::endl;
        return false;
    }

    // Wait for SUCCESS or ERR_MISMATCH
    uint8_t opcode;
    Bytes resp;
    if (!recv_message(sock_fd, opcode, resp)) {
        std::cerr << "[DRONE] Failed to receive confirmation" << std::endl;
        return false;
    }

    if (opcode == OP_SUCCESS) {
        std::cout << "[DRONE] Phase 2: Handshake complete! (SUCCESS)"
                  << std::endl;
        return true;
    } else if (opcode == OP_ERR_MISMATCH) {
        std::cerr << "[DRONE] Phase 2: Session key MISMATCH (ERR_MISMATCH)"
                  << std::endl;
        return false;
    } else {
        std::cerr << "[DRONE] Phase 2: Unexpected opcode 0x"
                  << std::hex << (int)opcode << std::dec << std::endl;
        return false;
    }
}

// ─── Phase 3: Receive Group Key & Broadcast Commands ──────────────────────────

static void phase3_receive_loop(int sock_fd, const Bytes& session_key) {
    std::cout << "[DRONE] Waiting for Group Key and commands..." << std::endl;

    Bytes group_key;

    while (true) {
        uint8_t opcode;
        Bytes payload;
        if (!recv_message(sock_fd, opcode, payload)) {
            std::cerr << "[DRONE] Connection lost." << std::endl;
            break;
        }

        if (opcode == OP_GROUP_KEY) {
            std::cout << "[DRONE] Received GROUP_KEY message." << std::endl;
            size_t off = 0;
            Bytes iv = deserialize_bytes(payload, off);
            Bytes encrypted_gk = deserialize_bytes(payload, off);
            Bytes recv_hmac = deserialize_bytes(payload, off);

            // Verify HMAC
            Bytes hmac_data;
            hmac_data.insert(hmac_data.end(), iv.begin(), iv.end());
            hmac_data.insert(hmac_data.end(),
                             encrypted_gk.begin(), encrypted_gk.end());
            Bytes expected_hmac = hmac_sha256(session_key, hmac_data);
            if (expected_hmac != recv_hmac) {
                std::cerr << "[DRONE] GROUP_KEY HMAC verification FAILED."
                          << std::endl;
                continue;
            }

            // Decrypt GK
            group_key = aes256_cbc_decrypt(session_key, iv, encrypted_gk);
            std::cout << "[DRONE] Group Key received: "
                      << bytes_to_hex(group_key) << std::endl;

        } else if (opcode == OP_GROUP_CMD) {
            std::cout << "[DRONE] Received GROUP_CMD message." << std::endl;
            size_t off = 0;
            Bytes iv = deserialize_bytes(payload, off);
            Bytes encrypted_cmd = deserialize_bytes(payload, off);
            Bytes recv_hmac = deserialize_bytes(payload, off);

            // Verify HMAC with GK
            Bytes hmac_data;
            hmac_data.insert(hmac_data.end(), iv.begin(), iv.end());
            hmac_data.insert(hmac_data.end(),
                             encrypted_cmd.begin(), encrypted_cmd.end());
            Bytes expected_hmac = hmac_sha256(group_key, hmac_data);
            if (expected_hmac != recv_hmac) {
                std::cerr << "[DRONE] GROUP_CMD HMAC verification FAILED."
                          << std::endl;
                continue;
            }

            // Decrypt command with GK
            Bytes cmd_bytes = aes256_cbc_decrypt(group_key, iv, encrypted_cmd);
            std::string command(cmd_bytes.begin(), cmd_bytes.end());
            std::cout << "[DRONE] ══════ BROADCAST COMMAND ══════" << std::endl;
            std::cout << "[DRONE] " << command << std::endl;
            std::cout << "[DRONE] ════════════════════════════════" << std::endl;

        } else if (opcode == OP_SHUTDOWN) {
            std::cout << "[DRONE] Received SHUTDOWN. Disconnecting." << std::endl;
            break;
        } else {
            std::cerr << "[DRONE] Unknown opcode: 0x"
                      << std::hex << (int)opcode << std::dec << std::endl;
        }
    }
}

// ─── Main ─────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    std::string drone_id = "DRONE_001";
    if (argc >= 2) {
        drone_id = argv[1];
    }

    std::cout << "╔═══════════════════════════════════════════╗" << std::endl;
    std::cout << "║   Secure UAV Drone Client                 ║" << std::endl;
    std::cout << "║   ID: " << drone_id;
    // Pad to 35 chars
    for (size_t i = drone_id.size(); i < 34; i++) std::cout << ' ';
    std::cout << "║" << std::endl;
    std::cout << "╚═══════════════════════════════════════════╝" << std::endl;

    // Connect to MCC
    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        std::cerr << "[DRONE] Failed to create socket" << std::endl;
        return 1;
    }

    struct sockaddr_in server_addr;
    std::memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port   = htons(MCC_PORT);
    inet_pton(AF_INET, MCC_HOST.c_str(), &server_addr.sin_addr);

    std::cout << "[DRONE] Connecting to MCC at " << MCC_HOST << ":"
              << MCC_PORT << "..." << std::endl;

    if (connect(sock_fd, (struct sockaddr*)&server_addr,
                sizeof(server_addr)) < 0) {
        std::cerr << "[DRONE] Connection failed" << std::endl;
        close(sock_fd);
        return 1;
    }

    std::cout << "[DRONE] Connected to MCC." << std::endl;

    // Phase 0: Receive params
    Phase0Data p0;
    if (!phase0_recv_params(sock_fd, p0)) {
        close(sock_fd);
        return 1;
    }

    // Phase 1A: Send AUTH_REQ
    Phase1AData a;
    if (!phase1a_send_auth(sock_fd, p0, drone_id, a)) {
        close(sock_fd);
        return 1;
    }

    // Phase 1B: Receive AUTH_RES
    Phase1BData b;
    if (!phase1b_recv_auth_res(sock_fd, p0, a, b)) {
        close(sock_fd);
        return 1;
    }

    // Phase 2: Session Key
    Bytes session_key;
    if (!phase2_session_key(sock_fd, a, b, drone_id, session_key)) {
        close(sock_fd);
        return 1;
    }

    // Phase 3: Wait for GROUP_KEY and commands
    phase3_receive_loop(sock_fd, session_key);

    close(sock_fd);
    std::cout << "[DRONE] Disconnected." << std::endl;
    return 0;
}
