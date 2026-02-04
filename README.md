# Secure UAV Command and Control System (C Implementation)

## Course
**System and Network Security (CS8.403)**  
International Institute of Information Technology, Hyderabad

## Lab Assignment 2  
**Secure UAV Command and Control System with Asymmetric Keys and Digital Signatures**

---

## 1. Overview

This project implements a **secure, distributed UAV Command-and-Control (C2) system** consisting of a **Mission Control Center (MCC)** and multiple **Drones**. The system enables authenticated drones to securely communicate with the MCC and receive encrypted fleet-wide broadcast commands.

The design strictly follows the assignment specification and emphasizes **manual implementation of asymmetric cryptography**, secure protocol design, and resistance to common network attacks.

---

## 2. Objectives

- Implement **ElGamal public-key encryption and digital signatures** manually
- Achieve **mutual authentication** between MCC and drones
- Establish secure **session keys** with freshness guarantees
- Enable **secure group communication** for broadcast commands
- Demonstrate resistance to replay, MITM, and unauthorized access attacks

---

## 3. Project Structure (Flat Layout)

```

.
├── crypto_utils.c        # Modular arithmetic, ElGamal, hashing, AES wrappers
├── crypto_utils.h
│
├── protocol.c            # Protocol phases (0–3), message handling
├── protocol.h
│
├── mcc.c                 # Mission Control Center (server)
├── drone.c               # Drone client
│
├── attacks.c             # Replay, MITM, and rogue drone demonstrations
│
├── common.h              # Shared constants, opcodes, message structures
│
├── test_crypto.c         # Cryptographic correctness and performance tests
│
├── Makefile
├── README.md
├── SECURITY.md
└── .gitignore

````

---

## 4. Cryptographic Components

### 4.1 Asymmetric Cryptography (Manual ElGamal)

The following components are implemented **from scratch**:

- Modular exponentiation
- Extended Euclidean Algorithm
- Modular inverse computation
- ElGamal key generation
- ElGamal encryption and decryption
- ElGamal digital signature and verification

No high-level asymmetric cryptographic libraries are used.

---

### 4.2 Symmetric Cryptography

- **AES-256-CBC** is used for encrypting group commands
- **HMAC-SHA256** is used for message integrity
- AES is used strictly as a raw block cipher, as permitted by the assignment

---

## 5. Communication Protocol

### Phase 0 — Parameter Initialization
- MCC distributes cryptographic parameters `(p, g, SL)`
- Drone verifies prime length and security level
- Prevents parameter downgrade and tampering attacks

### Phase 1 — Mutual Authentication
- Drone authenticates to MCC using encrypted secrets and digital signatures
- MCC proves authenticity by decrypting and re-encrypting the shared secret

### Phase 2 — Session Key Establishment
- Both parties derive a session key using shared secrets, timestamps, and nonces
- Session key correctness is verified using HMAC

### Phase 3 — Group Key Establishment
- MCC derives a fleet-wide Group Key (GK)
- GK is securely distributed to each drone
- All broadcast commands are encrypted using GK

---

## 6. Security Properties

- **Authentication:** Ensured via ElGamal digital signatures
- **Confidentiality:** Encryption protects all sensitive data
- **Integrity:** HMAC detects message tampering
- **Freshness:** Nonces and timestamps prevent replay attacks
- **Limited Forward Secrecy:** Session keys are ephemeral and not reused

Detailed analysis is provided in `SECURITY.md`.

---

## 7. Attack Demonstrations

The file `attacks.c` demonstrates the following attacks:

1. **Replay Attack**  
   Re-sending a previously captured authentication request

2. **Man-in-the-Middle (MITM) Attack**  
   Tampering with cryptographic parameters during Phase 0

3. **Unauthorized Access**  
   Rogue drone attempting to authenticate using an invalid identity

All attacks are successfully detected and mitigated.

---

## 8. Build Instructions

### Dependencies
- GCC
- GMP (GNU Multiple Precision Arithmetic Library)
- OpenSSL crypto library (for SHA-256 and AES only)

### Compile
```bash
make
````

### Clean

```bash
make clean
```

---

## 9. Running the System

### Start the Mission Control Center

```bash
./mcc
```

### Start a Drone

```bash
./drone
```

### Run Attack Demonstrations

```bash
./attacks
```

---

## 10. Performance Notes

* Modular exponentiation with 2048-bit primes was benchmarked using `test_crypto.c`
* Performance measurements are included to demonstrate feasibility
* Execution times are acceptable for the scope of this assignment

---

## 11. Implementation Notes

* The implementation prioritizes **correctness and clarity**
* Cryptographic logic is strictly separated from networking code
* Concurrency is implemented using a thread-per-drone model
* The code adheres to assignment library usage restrictions

---

## 12. Disclaimer

This project is developed **strictly for academic purposes** as part of a university assignment.
It is not intended for real-world deployment in security-critical environments.

---

