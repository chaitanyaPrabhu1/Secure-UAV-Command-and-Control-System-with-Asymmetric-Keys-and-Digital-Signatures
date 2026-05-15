#include "crypto_utils.h"

#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <map>
#include <mutex>
#include <thread>
#include <atomic>
#include <algorithm>
#include <cstring>
#include <chrono>

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

static const int    MCC_PORT   = 5555;
static const int    SL         = 2048;
static const std::string MCC_ID = "MCC_001";

// ─── Drone Info ───────────────────────────────────────────────────────────────

struct DroneInfo {
    int         socket_fd;
    std::string drone_id;
    Bytes       session_key;   // SK_D,MCC (32 bytes)
    mpz_class   drone_pub_key; // y_D
    bool        authenticated;
    std::string status;
};

// ─── Global State ─────────────────────────────────────────────────────────────

static std::mutex                       fleet_mutex;
static std::map<std::string, DroneInfo> fleet_registry;
static std::atomic<bool>                running{true};
static Bytes                            current_gk;  // current group key

static ElGamalKeyPair mcc_keys;

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
    // Message format: [opcode (1)] [length (4 big-endian)] [payload]
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
    // Read header: 1 byte opcode + 4 bytes length
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

// ─── Phase 0: Send Parameters to Drone ────────────────────────────────────────

static bool phase0_send_params(int client_fd) {
    std::cout << "[MCC] Phase 0: Sending parameters to drone..." << std::endl;

    // Build M0 = p || g || SL || TS0 || ID_MCC
    Bytes payload;

    // Serialize p
    Bytes p_ser = serialize_mpz(mcc_keys.params.p);
    payload.insert(payload.end(), p_ser.begin(), p_ser.end());

    // Serialize g
    Bytes g_ser = serialize_mpz(mcc_keys.params.g);
    payload.insert(payload.end(), g_ser.begin(), g_ser.end());

    // Serialize SL (4 bytes)
    uint32_t sl = static_cast<uint32_t>(mcc_keys.params.SL);
    payload.push_back((sl >> 24) & 0xFF);
    payload.push_back((sl >> 16) & 0xFF);
    payload.push_back((sl >> 8) & 0xFF);
    payload.push_back(sl & 0xFF);

    // Serialize timestamp
    std::string ts = get_timestamp();
    Bytes ts_bytes(ts.begin(), ts.end());
    Bytes ts_ser = serialize_bytes(ts_bytes);
    payload.insert(payload.end(), ts_ser.begin(), ts_ser.end());

    // Serialize MCC ID
    Bytes id_bytes(MCC_ID.begin(), MCC_ID.end());
    Bytes id_ser = serialize_bytes(id_bytes);
    payload.insert(payload.end(), id_ser.begin(), id_ser.end());

    // Serialize MCC public key y
    Bytes y_ser = serialize_mpz(mcc_keys.y);
    payload.insert(payload.end(), y_ser.begin(), y_ser.end());

    // Sign {M0}
    Bytes m0_hash = sha256(payload);
    mpz_class h = bytes_to_mpz(m0_hash);
    h = h % (mcc_keys.params.p - 1);
    if (h < 1) h = 1;
    ElGamalSignature sig = elgamal_sign(mcc_keys.params, mcc_keys.x, h);

    // Append signature (r, s)
    Bytes r_ser = serialize_mpz(sig.r);
    payload.insert(payload.end(), r_ser.begin(), r_ser.end());
    Bytes s_ser = serialize_mpz(sig.s);
    payload.insert(payload.end(), s_ser.begin(), s_ser.end());

    if (!send_message(client_fd, OP_PARAM_INIT, payload)) {
        std::cerr << "[MCC] Failed to send PARAM_INIT" << std::endl;
        return false;
    }

    std::cout << "[MCC] Phase 0: Parameters sent successfully." << std::endl;
    return true;
}

// ─── Phase 1A: Receive AUTH_REQ from Drone ────────────────────────────────────

struct Phase1AData {
    std::string ts_i;
    Bytes       rn_i;
    std::string drone_id;
    mpz_class   k_d_mcc;    // decrypted shared key
    mpz_class   drone_y;    // drone's public key
};

static bool phase1a_recv_auth(int client_fd, Phase1AData& data) {
    std::cout << "[MCC] Phase 1A: Waiting for AUTH_REQ..." << std::endl;

    uint8_t opcode;
    Bytes payload;
    if (!recv_message(client_fd, opcode, payload)) {
        std::cerr << "[MCC] Failed to receive AUTH_REQ" << std::endl;
        return false;
    }
    if (opcode != OP_AUTH_REQ) {
        std::cerr << "[MCC] Expected AUTH_REQ (0x20), got 0x"
                  << std::hex << (int)opcode << std::dec << std::endl;
        return false;
    }

    size_t offset = 0;

    // Drone public key y_D
    data.drone_y = deserialize_mpz(payload, offset);

    // TS_i
    Bytes ts_bytes = deserialize_bytes(payload, offset);
    data.ts_i = std::string(ts_bytes.begin(), ts_bytes.end());

    // RN_i
    data.rn_i = deserialize_bytes(payload, offset);

    // ID_D
    Bytes id_bytes = deserialize_bytes(payload, offset);
    data.drone_id = std::string(id_bytes.begin(), id_bytes.end());

    // C_i (encrypted K_D,MCC): c1, c2
    ElGamalCiphertext ct;
    ct.c1 = deserialize_mpz(payload, offset);
    ct.c2 = deserialize_mpz(payload, offset);

    // Signature (r, s) over (TS_i || RN_i || ID_D || C_i)
    ElGamalSignature sig;
    sig.r = deserialize_mpz(payload, offset);
    sig.s = deserialize_mpz(payload, offset);

    // Verify signature
    // Reconstruct signed data: everything before the signature
    size_t sig_data_start = 0;
    // We need to find where the signature begins — reparse to get size
    size_t check_offset = 0;
    deserialize_mpz(payload, check_offset); // drone_y
    Bytes signed_data(payload.begin() + check_offset, payload.begin() + offset);
    // Actually, let's just hash everything before the sig
    // Recompute: signed portion = drone_y | ts | rn | id | c1 | c2
    size_t sig_start_offset = 0;
    // Parse to find where sig starts
    size_t temp = 0;
    deserialize_mpz(payload, temp);   // drone_y
    deserialize_bytes(payload, temp); // ts_i
    deserialize_bytes(payload, temp); // rn_i
    deserialize_bytes(payload, temp); // id_d
    deserialize_mpz(payload, temp);   // c1
    deserialize_mpz(payload, temp);   // c2
    sig_start_offset = temp;

    Bytes to_verify(payload.begin(), payload.begin() + sig_start_offset);
    Bytes v_hash = sha256(to_verify);
    mpz_class h_verify = bytes_to_mpz(v_hash);
    h_verify = h_verify % (mcc_keys.params.p - 1);
    if (h_verify < 1) h_verify = 1;

    if (!elgamal_verify(mcc_keys.params, data.drone_y, h_verify, sig)) {
        std::cerr << "[MCC] Phase 1A: Signature verification FAILED for drone "
                  << data.drone_id << std::endl;
        return false;
    }
    std::cout << "[MCC] Phase 1A: Signature verified for drone "
              << data.drone_id << std::endl;

    // Decrypt C_i to get K_D,MCC
    data.k_d_mcc = elgamal_decrypt(mcc_keys.params, mcc_keys.x, ct);
    std::cout << "[MCC] Phase 1A: Decrypted shared key from drone "
              << data.drone_id << std::endl;

    return true;
}

// ─── Phase 1B: Send AUTH_RES to Drone ─────────────────────────────────────────

struct Phase1BData {
    Bytes       rn_mcc;
    std::string ts_mcc;
};

static bool phase1b_send_auth_res(int client_fd, const Phase1AData& a,
                                   Phase1BData& b) {
    std::cout << "[MCC] Phase 1B: Sending AUTH_RES..." << std::endl;

    b.rn_mcc = secure_random_bytes(32);
    b.ts_mcc = get_timestamp();

    Bytes payload;

    // TS_MCC
    Bytes ts_bytes(b.ts_mcc.begin(), b.ts_mcc.end());
    Bytes ts_ser = serialize_bytes(ts_bytes);
    payload.insert(payload.end(), ts_ser.begin(), ts_ser.end());

    // RN_MCC
    Bytes rn_ser = serialize_bytes(b.rn_mcc);
    payload.insert(payload.end(), rn_ser.begin(), rn_ser.end());

    // ID_MCC
    Bytes id_bytes(MCC_ID.begin(), MCC_ID.end());
    Bytes id_s = serialize_bytes(id_bytes);
    payload.insert(payload.end(), id_s.begin(), id_s.end());

    // C_MCC = encrypt K_D,MCC with drone's public key
    ElGamalCiphertext ct = elgamal_encrypt(mcc_keys.params, a.drone_y,
                                            a.k_d_mcc);
    Bytes c1_ser = serialize_mpz(ct.c1);
    payload.insert(payload.end(), c1_ser.begin(), c1_ser.end());
    Bytes c2_ser = serialize_mpz(ct.c2);
    payload.insert(payload.end(), c2_ser.begin(), c2_ser.end());

    // Sign (TS_MCC || RN_MCC || ID_MCC || C_MCC)
    Bytes sig_hash = sha256(payload);
    mpz_class h = bytes_to_mpz(sig_hash);
    h = h % (mcc_keys.params.p - 1);
    if (h < 1) h = 1;
    ElGamalSignature sig = elgamal_sign(mcc_keys.params, mcc_keys.x, h);

    Bytes r_ser = serialize_mpz(sig.r);
    payload.insert(payload.end(), r_ser.begin(), r_ser.end());
    Bytes s_ser = serialize_mpz(sig.s);
    payload.insert(payload.end(), s_ser.begin(), s_ser.end());

    if (!send_message(client_fd, OP_AUTH_RES, payload)) {
        std::cerr << "[MCC] Failed to send AUTH_RES" << std::endl;
        return false;
    }

    std::cout << "[MCC] Phase 1B: AUTH_RES sent to drone "
              << a.drone_id << std::endl;
    return true;
}

// ─── Phase 2: Session Key Confirmation ────────────────────────────────────────

static bool phase2_session_key(int client_fd, const Phase1AData& a,
                                const Phase1BData& b, Bytes& sk_out) {
    std::cout << "[MCC] Phase 2: Session key derivation..." << std::endl;

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

    // Wait for drone's HMAC confirmation
    uint8_t opcode;
    Bytes hmac_payload;
    if (!recv_message(client_fd, opcode, hmac_payload)) {
        std::cerr << "[MCC] Failed to receive SK_CONFIRM" << std::endl;
        return false;
    }
    if (opcode != OP_SK_CONFIRM) {
        std::cerr << "[MCC] Expected SK_CONFIRM (0x40), got 0x"
                  << std::hex << (int)opcode << std::dec << std::endl;
        return false;
    }

    // HMAC data: ID_D || TS_final
    // Extract drone's HMAC
    size_t off = 0;
    Bytes drone_hmac_data = deserialize_bytes(hmac_payload, off);
    Bytes drone_hmac_val  = deserialize_bytes(hmac_payload, off);

    // Verify HMAC
    Bytes expected_hmac = hmac_sha256(sk_out, drone_hmac_data);
    if (expected_hmac == drone_hmac_val) {
        std::cout << "[MCC] Phase 2: HMAC verified. Sending SUCCESS." << std::endl;
        send_message(client_fd, OP_SUCCESS, {});
        return true;
    } else {
        std::cerr << "[MCC] Phase 2: HMAC MISMATCH. Sending ERR." << std::endl;
        send_message(client_fd, OP_ERR_MISMATCH, {});
        return false;
    }
}

// ─── Drone Handler Thread ─────────────────────────────────────────────────────

static void handle_drone(int client_fd) {
    try {
        // Phase 0: Send params
        if (!phase0_send_params(client_fd)) {
            close(client_fd);
            return;
        }

        // Phase 1A: Receive AUTH_REQ
        Phase1AData a;
        if (!phase1a_recv_auth(client_fd, a)) {
            close(client_fd);
            return;
        }

        // Phase 1B: Send AUTH_RES
        Phase1BData b;
        if (!phase1b_send_auth_res(client_fd, a, b)) {
            close(client_fd);
            return;
        }

        // Phase 2: Session Key
        Bytes session_key;
        if (!phase2_session_key(client_fd, a, b, session_key)) {
            close(client_fd);
            return;
        }

        // Register drone
        {
            std::lock_guard<std::mutex> lock(fleet_mutex);
            DroneInfo info;
            info.socket_fd     = client_fd;
            info.drone_id      = a.drone_id;
            info.session_key   = session_key;
            info.drone_pub_key = a.drone_y;
            info.authenticated = true;
            info.status        = "ACTIVE";
            fleet_registry[a.drone_id] = info;
        }

        std::cout << "[MCC] Drone " << a.drone_id
                  << " authenticated and registered." << std::endl;

        // Keep connection alive — wait for shutdown
        while (running.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }

    } catch (const std::exception& e) {
        std::cerr << "[MCC] Error handling drone: " << e.what() << std::endl;
    }
    close(client_fd);
}

// ─── Phase 3: Group Key Distribution ──────────────────────────────────────────

static bool distribute_group_key() {
    std::lock_guard<std::mutex> lock(fleet_mutex);

    if (fleet_registry.empty()) {
        std::cout << "[MCC] No active drones to distribute GK to." << std::endl;
        return false;
    }

    // GK = SHA256(SK_D1 || SK_D2 || ... || SK_Dn || KR_MCC)
    Bytes gk_input;
    for (auto& [id, info] : fleet_registry) {
        if (info.authenticated) {
            gk_input.insert(gk_input.end(),
                            info.session_key.begin(), info.session_key.end());
        }
    }
    // KR_MCC — MCC random contribution
    Bytes kr_mcc = secure_random_bytes(32);
    gk_input.insert(gk_input.end(), kr_mcc.begin(), kr_mcc.end());

    Bytes gk = sha256(gk_input);
    current_gk = gk;  // store for broadcast use

    std::cout << "[MCC] Group Key generated: " << bytes_to_hex(gk) << std::endl;

    // Send GK to each drone, encrypted with their SK via AES-256-CBC
    for (auto& [id, info] : fleet_registry) {
        if (!info.authenticated) continue;

        Bytes iv = secure_random_bytes(16);
        Bytes encrypted_gk = aes256_cbc_encrypt(info.session_key, iv, gk);

        Bytes payload;
        Bytes iv_ser = serialize_bytes(iv);
        payload.insert(payload.end(), iv_ser.begin(), iv_ser.end());
        Bytes enc_ser = serialize_bytes(encrypted_gk);
        payload.insert(payload.end(), enc_ser.begin(), enc_ser.end());

        // HMAC for integrity
        Bytes hmac_data;
        hmac_data.insert(hmac_data.end(), iv.begin(), iv.end());
        hmac_data.insert(hmac_data.end(),
                         encrypted_gk.begin(), encrypted_gk.end());
        Bytes hmac_val = hmac_sha256(info.session_key, hmac_data);
        Bytes hmac_ser = serialize_bytes(hmac_val);
        payload.insert(payload.end(), hmac_ser.begin(), hmac_ser.end());

        if (!send_message(info.socket_fd, OP_GROUP_KEY, payload)) {
            std::cerr << "[MCC] Failed to send GROUP_KEY to " << id << std::endl;
        } else {
            std::cout << "[MCC] GROUP_KEY sent to " << id << std::endl;
        }
    }

    return true;
}

// ─── Broadcast Command ───────────────────────────────────────────────────────

static bool broadcast_command(const std::string& cmd) {
    // First distribute group key (sets current_gk)
    if (!distribute_group_key()) return false;

    // Small delay for drones to process GK
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    std::lock_guard<std::mutex> lock(fleet_mutex);

    // Encrypt command with GK via AES-256-CBC (per assignment §Phase 3.4)
    Bytes cmd_bytes(cmd.begin(), cmd.end());

    for (auto& [id, info] : fleet_registry) {
        if (!info.authenticated) continue;

        Bytes iv = secure_random_bytes(16);
        Bytes encrypted_cmd = aes256_cbc_encrypt(current_gk, iv, cmd_bytes);

        Bytes payload;
        Bytes iv_ser = serialize_bytes(iv);
        payload.insert(payload.end(), iv_ser.begin(), iv_ser.end());
        Bytes enc_ser = serialize_bytes(encrypted_cmd);
        payload.insert(payload.end(), enc_ser.begin(), enc_ser.end());

        Bytes hmac_data;
        hmac_data.insert(hmac_data.end(), iv.begin(), iv.end());
        hmac_data.insert(hmac_data.end(),
                         encrypted_cmd.begin(), encrypted_cmd.end());
        Bytes hmac_val = hmac_sha256(current_gk, hmac_data);
        Bytes hmac_ser = serialize_bytes(hmac_val);
        payload.insert(payload.end(), hmac_ser.begin(), hmac_ser.end());

        if (!send_message(info.socket_fd, OP_GROUP_CMD, payload)) {
            std::cerr << "[MCC] Failed to send GROUP_CMD to " << id << std::endl;
        } else {
            std::cout << "[MCC] GROUP_CMD sent to " << id << std::endl;
        }
    }
    return true;
}

// ─── Send Shutdown to All ─────────────────────────────────────────────────────

static void shutdown_all() {
    std::lock_guard<std::mutex> lock(fleet_mutex);
    for (auto& [id, info] : fleet_registry) {
        send_message(info.socket_fd, OP_SHUTDOWN, {});
        close(info.socket_fd);
        std::cout << "[MCC] Shutdown sent to " << id << std::endl;
    }
    fleet_registry.clear();
}

// ─── CLI Thread ───────────────────────────────────────────────────────────────

static void cli_thread() {
    std::string line;
    while (running.load()) {
        std::cout << "\n[MCC] > " << std::flush;
        if (!std::getline(std::cin, line)) break;

        std::istringstream iss(line);
        std::string cmd;
        iss >> cmd;

        if (cmd == "list") {
            std::lock_guard<std::mutex> lock(fleet_mutex);
            if (fleet_registry.empty()) {
                std::cout << "[MCC] No drones connected." << std::endl;
            } else {
                std::cout << "[MCC] ──── Connected Drones ────" << std::endl;
                for (auto& [id, info] : fleet_registry) {
                    std::cout << "  ID: " << id
                              << "  Status: " << info.status
                              << "  Auth: " << (info.authenticated ? "YES" : "NO")
                              << std::endl;
                }
                std::cout << "[MCC] ────────────────────────────" << std::endl;
            }
        } else if (cmd == "broadcast") {
            std::string rest;
            std::getline(iss, rest);
            // Trim leading space
            if (!rest.empty() && rest[0] == ' ') rest = rest.substr(1);
            if (rest.empty()) {
                std::cout << "[MCC] Usage: broadcast <command>" << std::endl;
            } else {
                std::cout << "[MCC] Broadcasting: " << rest << std::endl;
                broadcast_command(rest);
            }
        } else if (cmd == "shutdown") {
            std::cout << "[MCC] Shutting down..." << std::endl;
            running.store(false);
            shutdown_all();
            break;
        } else if (!cmd.empty()) {
            std::cout << "[MCC] Unknown command: " << cmd << std::endl;
            std::cout << "[MCC] Available: list, broadcast <cmd>, shutdown"
                      << std::endl;
        }
    }
}

// ─── Main ─────────────────────────────────────────────────────────────────────

int main() {
    std::cout << "╔═══════════════════════════════════════════╗" << std::endl;
    std::cout << "║   Secure UAV Mission Control Center       ║" << std::endl;
    std::cout << "║   ID: " << MCC_ID << "                          ║" << std::endl;
    std::cout << "╚═══════════════════════════════════════════╝" << std::endl;

    // Phase 0: Generate ElGamal parameters
    std::cout << "\n[MCC] Generating ElGamal parameters (SL=" << SL
              << ")... This may take a while." << std::endl;

    auto start = std::chrono::high_resolution_clock::now();
    mcc_keys = elgamal_keygen(SL);
    auto end = std::chrono::high_resolution_clock::now();
    auto dur = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    std::cout << "[MCC] Key generation complete in " << dur.count()
              << " ms." << std::endl;
    std::cout << "[MCC] Prime p bit-length: "
              << mpz_sizeinbase(mcc_keys.params.p.get_mpz_t(), 2) << std::endl;
    std::cout << "[MCC] Generator g: " << mcc_keys.params.g << std::endl;

    // Create TCP server socket
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        std::cerr << "[MCC] Failed to create socket" << std::endl;
        return 1;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(MCC_PORT);

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        std::cerr << "[MCC] Failed to bind to port " << MCC_PORT << std::endl;
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 10) < 0) {
        std::cerr << "[MCC] Failed to listen" << std::endl;
        close(server_fd);
        return 1;
    }

    std::cout << "[MCC] Listening on port " << MCC_PORT << std::endl;
    std::cout << "[MCC] Commands: list, broadcast <cmd>, shutdown\n" << std::endl;

    // Start CLI thread
    std::thread cli(cli_thread);

    // Accept connections
    while (running.load()) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        // Use select/poll with timeout to check running flag
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(server_fd, &fds);
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int ret = select(server_fd + 1, &fds, nullptr, nullptr, &tv);
        if (ret <= 0) continue;

        int client_fd = accept(server_fd, (struct sockaddr*)&client_addr,
                               &client_len);
        if (client_fd < 0) continue;

        std::cout << "\n[MCC] New connection from "
                  << inet_ntoa(client_addr.sin_addr)
                  << ":" << ntohs(client_addr.sin_port) << std::endl;

        // Spawn handler thread
        std::thread(handle_drone, client_fd).detach();
    }

    cli.join();
    close(server_fd);
    std::cout << "[MCC] Server shut down." << std::endl;
    return 0;
}
