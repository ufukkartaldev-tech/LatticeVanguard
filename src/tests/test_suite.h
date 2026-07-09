#ifndef PQC_TEST_SUITE_H
#define PQC_TEST_SUITE_H

#include <stdint.h>
#include <stddef.h>

namespace PQC {
namespace Test {

// 1. Temel Matematiksel Testler
class PrimTester {
public:
    static bool test_keccak();
    static bool test_ntt_symmetry();
    static bool test_ntt_edge_cases();
    static bool test_poly_serialization();
    static bool test_poly_compression_noise();
    static bool test_chacha20();
};

// 2. Kyber KEM Testleri
class KyberTester {
public:
    static bool test_kyber_kem_vectors();
    static bool test_decaps_failure();
    static bool test_memory_leaks();
    static bool test_timing_consistency();
};

// 3. Dilithium DSA Testleri
class ForgeTester {
public:
    static bool test_dilithium_malleability();
};

// 3b. Known-Answer / regression vectors (host-only, deterministic seed)
class KatTester {
public:
    static bool test_kyber512_kat();
    static bool test_kyber768_kat();
    static bool test_dilithium2_keygen_kat();
};

// 4. Sistem ve Güvenlik Denetimi
class AuditTester {
public:
    static bool test_randomness_entropy();
    static uint32_t test_stack_usage();
    static void test_power_efficiency();
    static bool test_multicore_safety();
};

// 5. Saldırı (Adversary) Testleri
class ChaosTester {
public:
    static bool test_replay_attack();
    static bool test_fragment_flooding();
    static bool test_rng_failure_lock();
    static bool test_counter_overflow();
    static bool test_flash_integrity_violation();
    static bool test_power_cycle_resilience();
    static bool test_trng_entropy_drop();
    static bool test_multi_device_stress();
};

// Test Suite Yöneticisi
class TestSuite {
public:
    static void run_all_tests();
    static void run_stress_test();
    static void log_test(const char* name, bool result);
    static bool compare_bytes(const uint8_t* a, const uint8_t* b, size_t len);
};

} // namespace Test
} // namespace PQC

#endif
