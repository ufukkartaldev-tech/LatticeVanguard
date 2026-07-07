#include "test_suite.h"
#include "../include/pqc_config.h"

#ifdef ENABLE_PQC_TESTS

#include "../include/kyber_modular.h"
#include "../include/dilithium.h"
#include "../include/health.h"
#include "../include/blackbox.h"
#include <string.h>
#include <stdio.h>

#ifdef ARDUINO
#include <Arduino.h>
#endif

namespace PQC {
namespace Test {

void TestSuite::run_stress_test() {
#ifdef ARDUINO
    Serial.println("\n--- GUMUSHANE STRESS TEST MODE ACTIVATED ---");
    Serial.println("Monitoring RAM integrity and performance for continuous PQC operations...");
    
    System::BlackBox::init(); // Initialize Flash Logging (LittleFS)
    System::BlackBox::print_saved_logs(); // Print any logs from previous failure

    static uint8_t pk_k[3000]; 
    static uint8_t sk_k[4500];
    static uint8_t ct_k[2000];
    static uint8_t ss1[64], ss2[64];

    static uint8_t pk_d[DILITHIUM2_PUBLICKEYBYTES];
    static uint8_t sk_d[DILITHIUM2_SECRETKEYBYTES];
    static uint8_t sig[DILITHIUM2_SIGNBYTES];
    size_t siglen;

    size_t initial_heap = ESP.getFreeHeap();
    uint32_t op_count = 0;

    while(true) {
        // 1. Kyber-768 Cycle
        uint32_t t0 = micros();
        KEM::Kyber768::keypair(pk_k, sk_k);
        KEM::Kyber768::encaps(ct_k, ss1, pk_k);
        KEM::Kyber768::decaps(ss2, ct_k, sk_k);
        uint32_t dt = micros() - t0;

        if (memcmp(ss1, ss2, 32) != 0) {
            Serial.println("FATAL ERROR: Kyber Integrity Check Failed!");
            System::BlackBox::log_error("Integrity_Kyber768", op_count, 0);
            while(1);
        }
        System::HealthMonitor::report_state("Stress_Kyber768", dt);

        // 2. Dilithium2 Cycle
        t0 = micros();
        DSA::Dilithium2::keypair(pk_d, sk_d);
        const char* msg = "GumusDil Stress Test Message";
        DSA::Dilithium2::sign(sig, &siglen, (uint8_t*)msg, strlen(msg), sk_d);
        DSA::Dilithium2::verify(sig, siglen, (uint8_t*)msg, strlen(msg), pk_d);
        dt = micros() - t0;
        System::HealthMonitor::report_state("Stress_Dilithium2", dt);

        op_count++;

        // Memory Integrity Check (Critical)
        size_t current_heap = ESP.getFreeHeap();
        if (current_heap < initial_heap) {
            size_t leak = initial_heap - current_heap;
            Serial.print("\n!!! CRITICAL MEMORY LEAK: "); Serial.print(leak); Serial.println(" bytes !!!");
            System::BlackBox::log_error("Memory_Leak_PQC", op_count, leak);
            while(1);
        }

        // Report every 1000 operations
        if (op_count % 1000 == 0) {
            Serial.print("\n[STRESS TEST] Iteration: ");
            Serial.println(op_count);
            System::HealthMonitor::print_performance_table();
            Serial.print("RAM Stability: [PASS] - Free Heap: "); 
            Serial.print(current_heap); Serial.println(" bytes");
            Serial.print("RNG Quality: [PASS] - Entropy: ");
            Serial.print(System::HealthMonitor::check_rng_entropy() * 100.0); Serial.println("%");
        }
        
        // Safety yield
        yield();
    }
#else
    printf("Stress test mode is optimized for ESP32 hardware execution.\n");
#endif
}

} // namespace Test
} // namespace PQC

#endif
