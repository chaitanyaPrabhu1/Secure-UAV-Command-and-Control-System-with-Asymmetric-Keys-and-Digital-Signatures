# Secure UAV Command and Control System

Lab Assignment 2 — System and Network Security (CS8.403)

A distributed UAV Command-and-Control (C2) system with manual ElGamal cryptography, mutual authentication, session key derivation, and group key establishment. Implemented in C++17.

## Dependencies

- **GMP** (GNU Multiple Precision Arithmetic Library) — for big-number math
- **OpenSSL** (libcrypto) — for SHA-256, HMAC-SHA256, AES-256-CBC
- **CMake** ≥ 3.16
- **g++** with C++17 support

### Install (Ubuntu/Debian)

```bash
sudo apt install build-essential cmake libgmp-dev libssl-dev
```

## Build

```bash
mkdir build && cd build
cmake ..
make -j$(nproc)
```

This produces three executables in `build/`:
- `mcc` — Mission Control Center server
- `drone` — Drone client
- `attacks` — Attack demonstration suite

## Usage

### 1. Start MCC Server

```bash
./mcc
```

The MCC will:
1. Generate 2048-bit ElGamal parameters (takes a few seconds to minutes)
2. Start listening on TCP port 5555
3. Present an interactive CLI

### 2. Start Drone(s)

In separate terminals:

```bash
./drone DRONE_001
./drone DRONE_002
./drone DRONE_003
```

Each drone will automatically:
1. Connect to MCC (localhost:5555)
2. Receive and validate parameters (Phase 0)
3. Perform mutual authentication (Phases 1A, 1B)
4. Derive session key (Phase 2)
5. Wait for group key and broadcast commands (Phase 3)

### 3. MCC CLI Commands

| Command | Description |
|---------|-------------|
| `list` | Show all connected drones and their status |
| `broadcast <cmd>` | Generate Group Key, distribute it, and broadcast an encrypted command |
| `shutdown` | Close all sessions and exit |

### 4. Run Attack Demo

With MCC running:

```bash
./attacks         # Run all 3 attacks
./attacks replay  # Replay attack only
./attacks mitm    # MitM tampering only
./attacks unauth  # Unauthorized access only
```

## File Structure

| File | Description |
|------|-------------|
| `crypto_utils.h/cpp` | Manual ElGamal, modular math, HMAC/AES wrappers |
| `mcc.cpp` | Concurrent MCC server with protocol logic |
| `drone.cpp` | Drone client-side protocol logic |
| `attacks.cpp` | Attack demonstration scripts |
| `SECURITY.md` | Freshness and Forward Secrecy analysis |
| `CMakeLists.txt` | Build configuration |

## Performance

Performance measured on a typical machine with 2048-bit primes:

| Operation | Time |
|-----------|------|
| Safe Prime Generation (2048-bit) | ~10–120 seconds |
| ElGamal Key Generation | ~10–120 seconds |
| Modular Exponentiation (2048-bit) | < 10 ms |
| ElGamal Encrypt | < 20 ms |
| ElGamal Decrypt | < 10 ms |
| ElGamal Sign | < 20 ms |
| ElGamal Verify | < 20 ms |
| Full Handshake (Phases 0–2) | < 500 ms (after keygen) |

> **Note**: Safe prime generation is the bottleneck. Once parameters are generated, all other operations are fast.

## Protocol Opcodes

| Opcode | Name | Description |
|--------|------|-------------|
| 0x10 | PARAM_INIT | Phase 0: Crypto parameters + MCC signature |
| 0x20 | AUTH_REQ | Phase 1A: Drone authentication packet |
| 0x30 | AUTH_RES | Phase 1B: MCC proof of decryption |
| 0x40 | SK_CONFIRM | Phase 2: Session key verification (HMAC) |
| 0x50 | SUCCESS | Handshake complete |
| 0x60 | ERR_MISMATCH | Key or HMAC verification failed |
| 0x70 | GROUP_KEY | Phase 3: Distribution of GK |
| 0x80 | GROUP_CMD | Secure broadcast (encrypted via GK) |
| 0x90 | SHUTDOWN | Close all drone connections |
