# Security Analysis

## How the Protocol Ensures Freshness

### Timestamps
Every protocol message includes a timestamp (`TS_i`, `TS_MCC`, `TS_0`). These prevent old messages from being accepted:
- Phase 0: MCC includes `TS_0` in the parameter broadcast, signed with its private key.
- Phase 1A: Drone includes `TS_i` in `AUTH_REQ`, signed under its key.
- Phase 1B: MCC includes `TS_MCC` in `AUTH_RES`, also signed.
- Phase 2: The session key `SK` is derived as `SHA-256(K_D,MCC || TS_i || TS_MCC || RN_i || RN_MCC)`. Even if the same `K_D,MCC` were reused, different timestamps produce a different session key.

### Nonces
Random nonces `RN_i` (from drone) and `RN_MCC` (from MCC) are generated fresh in every session. They are:
- Included in the session key derivation, ensuring uniqueness even under timestamp collision.
- Cryptographically random (256-bit, from `/dev/urandom`), making prediction infeasible.

### HMAC Confirmation
Phase 2 includes an HMAC confirmation using the derived session key. This binds the session key to the drone's identity and a final timestamp, proving both parties share the same key at the same point in time.

### Result
An attacker cannot replay old messages because:
1. Stale timestamps will be detected.
2. Nonces are unique per session, so replayed nonces produce a different session key.
3. HMAC verification will fail if the session key doesn't match.

---

## How the Protocol Ensures Forward Secrecy

### Ephemeral Shared Secret
Each session begins with the drone generating a fresh random 256-bit `K_D,MCC`. This is:
- Generated independently for each session.
- Encrypted with the MCC's public key (ElGamal encryption).
- Never stored long-term after the session key is derived.

### Session Key Derivation
The session key is: `SK = SHA-256(K_D,MCC || TS_i || TS_MCC || RN_i || RN_MCC)`.

This means:
- `SK` depends on the ephemeral `K_D,MCC`, which is unique per session.
- Even if the MCC's long-term private key (`x_MCC`) is later compromised, an attacker cannot recover past `K_D,MCC` values because:
  - The ElGamal encryption used a random `k` that was discarded.
  - Without `k`, the attacker cannot decrypt `C_i = (g^k, m · y^k)` even with `x_MCC`.

### Group Key Independence
The group key `GK = SHA-256(SK_1 || SK_2 || ... || SK_n || KR_MCC)` is derived from all session keys plus a fresh MCC random contribution. Compromising one session key does not reveal the group key without all other session keys.

### Result
Compromise of long-term keys (ElGamal private keys) does not allow decryption of past session traffic because each session's shared secret `K_D,MCC` was encrypted with a unique ephemeral random factor `k`.
