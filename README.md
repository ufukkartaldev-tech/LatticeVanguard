# LatticeVanguard: Optimized Post-Quantum Cryptography Suite for ESP32

## Overview

LatticeVanguard is a high-performance, memory-efficient Post-Quantum Cryptography (PQC) ecosystem specifically engineered for the ESP32 microcontroller architecture. The suite implements NIST-standardized algorithms, specifically the Kyber Key Encapsulation Mechanism (KEM) and the Dilithium Digital Signature Algorithm (DSA), to provide robust, quantum-resistant security for resource-constrained embedded systems.

## Core Components

- **Kyber (512/768)**: A quantum-resistant key encapsulation mechanism providing secure key exchange with forward secrecy.
- **Dilithium2**: A high-assurance digital signature scheme ensuring identity verification and data integrity.
- **Symmetric Cryptography**: Integration of ChaCha20 and hardware-accelerated AES-256-GCM for high-speed data encryption.
- **NTT Optimization**: Highly optimized Number Theoretic Transform (NTT) implementation for efficient polynomial multiplication on embedded hardware.
- **Lattice-Mesh Networking**: A secure, multi-hop routing layer built upon the ESP-NOW protocol with integrated PQC authentication.

## Security Architecture

LatticeVanguard incorporates multiple defensive layers to mitigate advanced cryptographic threats and physical attacks:

1. **Post-Quantum Trust-Chain**: A sovereign device admission protocol where new nodes must present Dilithium-signed certificates for network access.
2. **Stealth Mode Architecture**: Full header and payload obfuscation using AES-256-GCM, transforming network traffic into indistinguishable noise.
3. **Moving Target Defense**: Automated periodic rotation of privacy keys to prevent long-term cryptanalysis.
4. **Anti-Tamper & Panic Wipe**: Real-time detection of physical breaches or brute-force attempts, triggering autonomous erasure of secret keys from memory.
5. **Hardware-Rooted Secret Salt**: Master Key derivation utilizing read-protected eFuse blocks on the ESP32 to prevent flash-dump extraction.
6. **Constant-Time Execution**: Mitigation of timing-based side-channel attacks through constant-time arithmetic and comparison operations.
7. **Secure OTA Verification**: Firmware update validation using Dilithium digital signatures to prevent unauthorized binary execution.

## Project Structure

The project is organized into modular components for clarity and maintainability:

- `src/include/`: Header files and system configuration.
  - `kyber_modular.h` / `dilithium.h`: Core PQC algorithm definitions.
  - `workspace.h`: Memory management and unified buffer allocation.
  - `pqc_config.h`: Compile-time features and environment settings.
  - `security.h` / `trust_manager.h`: Security enforcement and trust-chain logic.
- `src/source/`: Implementation files.
  - `ntt.cpp` / `dilithium_ntt.cpp`: Optimized mathematical transforms.
  - `network.cpp`: ESP-NOW based communication stack.
  - `storage.cpp`: NVS-backed secure key storage (KeyVault).
- `src/tests/`: Comprehensive validation suite.
  - `test_adversary.cpp`: Simulation of hacking attempts and stress conditions.
  - `test_suite.cpp`: Automated unit and integration tests.
- `kyber_dilithium.ino`: Main entry point for the ESP32 firmware.
- `pc_main.cpp`: Entry point for native PC testing and development.
- `run_pc_tests.bat`: Batch script for compiling and running tests on Windows (MSVC).

## Performance and Optimization

To operate successfully within the 520 KB RAM constraints of the ESP32, the following strategies are employed:

- **Unified Static Workspace**: A shared memory region (Union-based) allowing 100% reuse between Kyber and Dilithium, minimizing the static RAM footprint to approximately 16 KB.
- **Bit-Level Packing**: Efficient storage of coefficients (12-bit for Kyber, 24-bit for Dilithium), reducing polynomial memory usage by 25%.
- **Flash-Based Constants**: Offloading large NTT tables and Keccak constants to Flash memory via `PQC_FLASH_STORAGE` attributes to maximize available Heap.
- **Hardware Acceleration**: Utilization of the ESP32's built-in AES and SHA accelerators where applicable to reduce CPU overhead.

## Installation and Deployment

### For ESP32 (Arduino IDE)

1. Ensure the **ESP32 Board Support** is installed in the Arduino IDE (v2.0 or higher).
2. Install necessary dependencies (if any) or ensure the `src/` directory is correctly linked.
3. Open `kyber_dilithium.ino`.
4. Configure `src/include/pqc_config.h` for your environment (e.g., enabling/disabling `ENABLE_PQC_TESTS`).
5. Select the appropriate ESP32 board (e.g., ESP32-S3) and click **Upload**.

### For PC (Visual Studio / MSVC)

1. Ensure Visual Studio (C++ Desktop Development) is installed.
2. Open a developer command prompt or ensure `cl.exe` is in your PATH.
3. Execute `run_pc_tests.bat` to compile and run the native validation suite.

## Testing and Validation

LatticeVanguard includes a robust "Forensic BlackBox" and an "Adversary" test suite. These systems simulate real-world attack vectors, including:
- Replay attacks and message spoofing.
- Fault injection and instruction skipping.
- Entropy exhaustion monitoring.
- Memory corruption and buffer overflow attempts.

## License

This project is an open-source reference implementation intended for secure embedded application development.
