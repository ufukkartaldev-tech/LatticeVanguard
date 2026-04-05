/*
  UNIFIED KYBER-DILITHIUM MAIN
  ---------------------------
  Cross-platform main entry point for ESP32 and STM32
*/

#include "src/include/platform.h"
#include "src/include/workspace_unified.h"
#include "src/include/network_abstract.h"
#include "src/include/storage_abstract.h"
#include "src/include/kyber_modular.h"
#include "src/include/dilithium.h"
#include "src/include/encryption.h"

// Platform-specific includes
#ifdef PLATFORM_ESP32
  #include <Arduino.h>
  #include "src/include/blackbox.h"
  #include "src/include/security.h"
  #include "src/include/health.h"
#elif defined(PLATFORM_STM32)
  #include <stm32f1xx_hal.h>
  #include <stdio.h>
#elif defined(PLATFORM_PC)
  #include <iostream>
  #include <chrono>
#endif

using namespace PQC::KEM;
using namespace PQC::DSA;
using namespace PQC::Symmetric;
using namespace PQC::Memory;
using namespace PQC::Network;
using namespace PQC::Storage;

// Test peer MAC (for demonstration)
#ifdef PLATFORM_ESP32
const uint8_t PEER_MAC[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED};
#elif defined(PLATFORM_STM32)
const uint8_t PEER_MAC[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
#else
const uint8_t PEER_MAC[] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
#endif

// Cross-platform test functions
void test_cross_platform_kyber() {
    ScopedWorkspace ws;
    if (!ws) {
        printf("ERROR: Workspace allocation failed!\n");
        return;
    }
    
    printf("\n=== CROSS-PLATFORM KYBER-512 TEST ===\n");
    printf("Platform: %s\n", PQC::Platform::get_platform_name());
    printf("Workspace Size: %d bytes\n", UnifiedWorkspace::get_total_size());
    
    uint32_t start_time = PQC::Platform::Platform->get_tick_ms();
    
    // Generate keypair
    Kyber512::keypair(ws->kyber_pk, ws->kyber_sk);
    uint32_t keygen_time = PQC::Platform::Platform->get_tick_ms() - start_time;
    
    // Encapsulation
    start_time = PQC::Platform::Platform->get_tick_ms();
    Kyber512::encaps(ws->kyber_ct, ws->kyber_ss, ws->kyber_pk);
    uint32_t enc_time = PQC::Platform::Platform->get_tick_ms() - start_time;
    
    // Decapsulation
    start_time = PQC::Platform::Platform->get_tick_ms();
    Kyber512::decaps(ws->kyber_ss, ws->kyber_ct, ws->kyber_sk);
    uint32_t dec_time = PQC::Platform::Platform->get_tick_ms() - start_time;
    
    printf("KeyGen: %u ms\n", keygen_time);
    printf("Encaps: %u ms\n", enc_time);
    printf("Decaps: %u ms\n", dec_time);
    printf("Total: %u ms\n", keygen_time + enc_time + dec_time);
    
    // Verify
    uint8_t test_ss[32];
    Kyber512::encaps(ws->kyber_ct, test_ss, ws->kyber_pk);
    Kyber512::decaps(test_ss, ws->kyber_ct, ws->kyber_sk);
    
    bool success = (memcmp(ws->kyber_ss, test_ss, 32) == 0);
    printf("Result: %s\n", success ? "SUCCESS" : "FAILED");
    
    if (PQC::Platform::Logger) {
        PQC::Platform::Logger->log_error("KYBER_TEST", 1, success ? 0 : 32);
    }
}

void test_cross_platform_dilithium() {
    ScopedWorkspace ws;
    if (!ws) {
        printf("ERROR: Workspace allocation failed!\n");
        return;
    }
    
    printf("\n=== CROSS-PLATFORM DILITHIUM-2 TEST ===\n");
    
    uint32_t start_time = PQC::Platform::Platform->get_tick_ms();
    
    // Generate keypair
    Dilithium2::keypair(ws->dilithium_pk, ws->dilithium_sk);
    uint32_t keygen_time = PQC::Platform::Platform->get_tick_ms() - start_time;
    
    // Sign message
    const char* message = "Cross-Platform PQC Test Message";
    size_t msg_len = strlen(message);
    size_t sig_len;
    
    start_time = PQC::Platform::Platform->get_tick_ms();
    Dilithium2::sign(ws->dilithium_sig, &sig_len, (const uint8_t*)message, msg_len, ws->dilithium_sk);
    uint32_t sign_time = PQC::Platform::Platform->get_tick_ms() - start_time;
    
    // Verify signature
    start_time = PQC::Platform::Platform->get_tick_ms();
    int verify_result = Dilithium2::verify(ws->dilithium_sig, sig_len, (const uint8_t*)message, msg_len, ws->dilithium_pk);
    uint32_t verify_time = PQC::Platform::Platform->get_tick_ms() - start_time;
    
    printf("KeyGen: %u ms\n", keygen_time);
    printf("Sign: %u ms\n", sign_time);
    printf("Verify: %u ms\n", verify_time);
    printf("Total: %u ms\n", keygen_time + sign_time + verify_time);
    
    bool success = (verify_result == 0);
    printf("Result: %s\n", success ? "SUCCESS" : "FAILED");
    
    if (PQC::Platform::Logger) {
        PQC::Platform::Logger->log_error("DILITHIUM_TEST", 1, success ? 0 : 2420);
    }
}

void test_cross_platform_communication() {
    printf("\n=== CROSS-PLATFORM COMMUNICATION TEST ===\n");
    
    // Test network interface
    if (!PQC::Platform::Network) {
        printf("ERROR: Network interface not available!\n");
        return;
    }
    
    // Get device MAC
    uint8_t device_mac[6];
    if (PQC::Platform::Network->get_device_mac) {
        // This would need to be implemented in the interface
        printf("Device MAC: Not implemented\n");
    }
    
    // Test packet sending
    const char* test_msg = "Cross-Platform Test Packet";
    bool send_result = PQC::Platform::Network->send_packet(PEER_MAC, (const uint8_t*)test_msg, strlen(test_msg));
    printf("Send Test: %s\n", send_result ? "SUCCESS" : "FAILED");
    
    // Test packet receiving
    uint8_t source_mac[6];
    uint8_t recv_data[256];
    size_t recv_len;
    
    bool recv_result = PQC::Platform::Network->receive_packet(source_mac, recv_data, &recv_len);
    printf("Receive Test: %s\n", recv_result ? "SUCCESS" : "NO DATA");
}

void test_cross_platform_storage() {
    printf("\n=== CROSS-PLATFORM STORAGE TEST ===\n");
    
    if (!PQC::Platform::Storage) {
        printf("ERROR: Storage interface not available!\n");
        return;
    }
    
    // Test key storage
    uint8_t test_key[32] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                           0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                           0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                           0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20};
    
    bool save_result = PQC::Platform::Storage->save_key("TEST_KEY", test_key, 32);
    printf("Save Key: %s\n", save_result ? "SUCCESS" : "FAILED");
    
    uint8_t loaded_key[32];
    bool load_result = PQC::Platform::Storage->load_key("TEST_KEY", loaded_key, 32);
    printf("Load Key: %s\n", load_result ? "SUCCESS" : "FAILED");
    
    if (load_result) {
        bool key_match = (memcmp(test_key, loaded_key, 32) == 0);
        printf("Key Verification: %s\n", key_match ? "SUCCESS" : "FAILED");
    }
}

void test_cross_platform_memory() {
    printf("\n=== CROSS-PLATFORM MEMORY TEST ===\n");
    
    printf("Platform: %s\n", PQC::Platform::get_platform_name());
    printf("Total RAM: %d KB\n", PLATFORM_RAM_SIZE / 1024);
    printf("Workspace Size: %d KB\n", PLATFORM_MAX_WORKSPACE / 1024);
    printf("Free Heap: %d KB\n", PQC::Platform::Memory->get_free_heap() / 1024);
    printf("Min Free Heap: %d KB\n", PQC::Platform::Memory->get_min_free_heap() / 1024);
    
    // Test workspace allocation
    bool ws_allocated = UnifiedWorkspace::is_allocated();
    printf("Workspace Allocated: %s\n", ws_allocated ? "YES" : "NO");
    
    if (ws_allocated) {
        size_t free_ws = UnifiedWorkspace::get_free_size();
        printf("Workspace Free: %d KB\n", free_ws / 1024);
    }
}

// Platform-specific setup and loop
#ifdef PLATFORM_ESP32
void setup() {
    Serial.begin(115200);
    delay(2000);
    
    Serial.println("\n===== LATTICEVANGUARD: ESP32 CROSS-PLATFORM PQC =====");
    
    // Initialize platform
    if (!PQC::Platform::initialize_platform()) {
        Serial.println("ERROR: Platform initialization failed!");
        return;
    }
    
    Serial.println("Platform initialized successfully!");
    
    // Run tests
    test_cross_platform_memory();
    test_cross_platform_storage();
    test_cross_platform_kyber();
    test_cross_platform_dilithium();
    test_cross_platform_communication();
    
    Serial.println("===== ALL TESTS COMPLETED =====");
}

void loop() {
    // Periodic testing
    static uint32_t last_test = 0;
    uint32_t current_time = millis();
    
    if (current_time - last_test > 30000) { // Every 30 seconds
        test_cross_platform_kyber();
        test_cross_platform_dilithium();
        last_test = current_time;
    }
    
    delay(1000);
}
#endif

#ifdef PLATFORM_STM32
int main(void) {
    printf("\n===== LATTICEVANGUARD: STM32 CROSS-PLATFORM PQC =====\n");
    
    // Initialize platform
    if (!PQC::Platform::initialize_platform()) {
        printf("ERROR: Platform initialization failed!\n");
        return -1;
    }
    
    printf("Platform initialized successfully!\n");
    
    // Run tests
    test_cross_platform_memory();
    test_cross_platform_storage();
    test_cross_platform_kyber();
    test_cross_platform_dilithium();
    test_cross_platform_communication();
    
    printf("===== ALL TESTS COMPLETED =====\n");
    
    // Main loop
    while (1) {
        static uint32_t last_test = 0;
        uint32_t current_time = HAL_GetTick();
        
        if (current_time - last_test > 30000) { // Every 30 seconds
            test_cross_platform_kyber();
            test_cross_platform_dilithium();
            last_test = current_time;
        }
        
        HAL_Delay(1000);
    }
}
#endif

#ifdef PLATFORM_PC
int main() {
    std::cout << "\n===== LATTICEVANGUARD: PC CROSS-PLATFORM PQC =====" << std::endl;
    
    // Initialize platform
    if (!PQC::Platform::initialize_platform()) {
        std::cout << "ERROR: Platform initialization failed!" << std::endl;
        return -1;
    }
    
    std::cout << "Platform initialized successfully!" << std::endl;
    
    // Run tests
    test_cross_platform_memory();
    test_cross_platform_storage();
    test_cross_platform_kyber();
    test_cross_platform_dilithium();
    test_cross_platform_communication();
    
    std::cout << "===== ALL TESTS COMPLETED =====" << std::endl;
    
    // Main loop
    while (true) {
        static auto last_test = std::chrono::steady_clock::now();
        auto current_time = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(current_time - last_test);
        
        if (duration.count() > 30000) { // Every 30 seconds
            test_cross_platform_kyber();
            test_cross_platform_dilithium();
            last_test = current_time;
        }
        
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    
    return 0;
}
#endif
