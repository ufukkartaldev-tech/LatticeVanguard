# LatticeVanguard: Optimized Post-Quantum Cryptography Library for ESP32

## Overview
LatticeVanguard is a high-performance, memory-efficient Post-Quantum Cryptography (PQC) library specifically engineered for the ESP32 microcontroller architecture. The system leverages the NIST-standardized Kyber Key Encapsulation Mechanism (KEM) and Dilithium Digital Signature Algorithm (DSA) to provide robust, quantum-resistant security for resource-constrained embedded systems.

## Key Features
- **Kyber (512/768)**: Quantum-resistant key exchange protocol ensuring forward secrecy against future cryptographic threats.
- **Dilithium2**: High-assurance digital signature scheme providing identity verification and data integrity.
- **PQC-Mesh Network**: Advanced multi-hop routing and automated relaying (B-Node) layer over the ESP-NOW protocol.
- **KeyVault (Secure Storage)**: Persistent NVS storage for PQC keys, protected via hardware-accelerated AES-256-GCM and device-unique Secret Salts.
- **Hybrid Encryption**: Dual-layer security utilizing hardware AES-256-GCM and ChaCha20 for defense-in-depth data protection.
- **Asynchronous Framework**: Non-blocking architecture offloading network traffic to Core 0 while reserving Core 1 for intensive cryptographic arithmetic.

## Security & Resilience Infrastructure (v4.5 "Fortress")
The library incorporates multiple defensive layers to mitigate advanced cyber threats and hardware-level attacks:

1.  **Post-Quantum Trust-Chain (Handshake)**: A secure, sovereign device admission protocol. New nodes must present a Dilithium-signed "Participation Certificate" from an Admin node to join the network, preventing unauthorized device injection.
2.  **Stealth Mode (Header Obfuscation)**: Packets are fully encrypted (Headers + Payload) using AES-256-GCM with a dynamic Privacy Key. This turns network traffic into unreadable noise, preventing Traffic Analysis and metadata leakage.
3.  **Moving Target Defense (Key Rotation)**: The network's privacy key automatically evolves every 1000 messages (Epochs). If a session key is compromised, it cannot be used to decrypt past or future traffic.
4.  **Anti-Tamper Self-Destruct (Panic Wipe)**: Detects physical tampering, voltage glitching, or brute-force attempts. Upon breach detection, the system triggers an autonomous "Panic Wipe," erasing all secret keys from NVS within milliseconds.
5.  **Hardware-Rooted Secret Salt (eFuse Pinning)**: The Master Key derivation material is stored in read-protected ESP32 eFuse blocks. This prevents "Flash Dump" attacks, as the key cannot be reconstructed from external memory extracts.
6.  **Redundant Security Logic**: Critical security checks use dual-flag verification with magic-value buffers to protect against "Instruction Skipping" fault injection attacks.
7.  **Forensic BlackBox**: Security incidents (Flood attacks, signature failures, panic triggers) are encrypted and logged to persistent memory for post-mortem analysis by authorized administrators.
8.  **Chaos Engineering Tests**: A dedicated "Adversary" test suite that simulates real-world hacking attempts (Replay, Flooding, Power-cycle desync, Flash corruption) to ensure continuous defensive integrity.
9.  **Persistent Anti-Replay Layer**: Monotonic message identifiers are tracked via NVS with signed-comparison logic, protecting against counter wrap-around vulnerabilities and re-injection attacks.
10. **Entropy-Locked Execution**: Real-time monitoring of the True Random Number Generator (TRNG). Operations are suspended if entropy falls below safety thresholds, preventing weak key generation.
11. **Post-Quantum OTA Verification**: Firmware updates are validated via Dilithium digital signatures, ensuring only authorized binaries can be executed on the nodes.

## Memory Optimization Strategies
To ensure reliable execution within the 520 KB RAM constraints of the ESP32, several specialized techniques have been implemented:

- **Universal Memory Recycling**: A shared static workspace (Union) allows for 100% memory reuse between Kyber and Dilithium operations, significantly reducing the static RAM footprint.
- **Bit-Level Packing**: Cryptographic coefficients are packed at 12-bit (Kyber) and 24-bit (Dilithium) levels, achieving a 25% reduction in polynomial storage requirements.
- **Flash Offloading (DROM)**: NTT zeta tables and Keccak constants are relocated to Flash memory via `PQC_FLASH_STORAGE` macros to maximize available heap space.

## Side-Channel & Physical Protections
- **Constant-Time (CT) Implementation**: All sensitive comparisons and arithmetic operations are executed in constant time to eliminate timing-based data exfiltration.
- **Anti-Fault-Injection**: Redundant validation logic and double-check mechanisms protect against hardware glitching and voltage manipulation attacks.
- **Secure Memory Sanitization**: Sensitive buffers and ephemeral keys are physically zeroed out (`memset 0`) immediately following their utilization.

## Technical Specifications
| Parameter | Value |
|-----------|-------|
| Target MCU | ESP32 (S3/C3/Standard) |
| Static RAM Footprint | ~16 KB |
| Stack Allocation | < 4 KB |
| Networking Protocol | ESP-NOW (Reliable Async) |
| Security Compliance | NIST Level 2-3 |

## Project Structure
- `src/include/`: Header definitions and configuration parameters.
- `src/source/`: Core algorithm implementations and communication stacks.
- `src/tests/`: Stability, performance, and security validation units.
- `kyber_dilithium.ino`: Integration entry point and application demo.

## License
This project is an open-source reference implementation intended for high-security embedded applications.
