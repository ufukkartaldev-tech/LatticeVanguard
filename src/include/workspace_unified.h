#ifndef PQC_WORKSPACE_UNIFIED_H
#define PQC_WORKSPACE_UNIFIED_H

/*
  UNIFIED MEMORY WORKSPACE (Cross-Platform)
  ----------------------------------------
  ESP32 ve STM32 için optimize edilmiş bellek yönetimi
*/

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "platform.h"

namespace PQC {
namespace Memory {

// Platform-specific workspace sizes
#ifdef PLATFORM_ESP32
  #define UNIFIED_WORKSPACE_SIZE 16384  // 16KB for ESP32
  #define CRYPTO_BUFFER_SIZE     4096   // 4KB crypto operations
  #define NETWORK_BUFFER_SIZE    2048   // 2KB network operations
#elif defined(PLATFORM_STM32)
  #define UNIFIED_WORKSPACE_SIZE 8192   // 8KB for STM32 (64KB RAM limit)
  #define CRYPTO_BUFFER_SIZE     2048   // 2KB crypto operations
  #define NETWORK_BUFFER_SIZE    1024   // 1KB network operations
#elif defined(PLATFORM_PC)
  #define UNIFIED_WORKSPACE_SIZE 32768  // 32KB for PC testing
  #define CRYPTO_BUFFER_SIZE     8192   // 8KB crypto operations
  #define NETWORK_BUFFER_SIZE    4096   // 4KB network operations
#endif

// Kyber polynomial sizes (constant across platforms)
#define KYBER_POLY_SIZE          384     // 256 coefficients * 12 bits packed
#define KYBER_POLYVECSIZE_K      4       // Kyber512: k=4
#define KYBER_POLYVECBYTES       (KYBER_POLY_SIZE * KYBER_POLYVECSIZE_K)

// Dilithium polynomial sizes
#define DILITHIUM_POLY_SIZE      1024    // 256 coefficients * 32 bits
#define DILITHIUM_L              4       // Dilithium2: l=4
#define DILITHIUM_K              4       // Dilithium2: k=4
#define DILITHIUM_POLYVECBYTES   (DILITHIUM_POLY_SIZE * DILITHIUM_L)

// Unified workspace structure
typedef struct {
    // Kyber workspace
    uint8_t kyber_pk[KYBER_POLYVECBYTES];           // Public key
    uint8_t kyber_sk[KYBER_POLYVECBYTES];           // Secret key  
    uint8_t kyber_ct[KYBER_POLYVECBYTES];           // Ciphertext
    uint8_t kyber_ss[32];                           // Shared secret
    
    // Dilithium workspace (reuses Kyber memory)
    uint8_t dilithium_pk[1312];                     // Public key
    uint8_t dilithium_sk[2528];                     // Secret key
    uint8_t dilithium_sig[2420];                    // Signature
    
    // Temporary buffers (shared between algorithms)
    uint8_t temp_buffer[CRYPTO_BUFFER_SIZE];        // General crypto operations
    uint8_t hash_buffer[64];                        // Hash operations
    
    // Alignment padding
    uint8_t padding[32];
    
    // Raw access for platform-specific operations
    uint8_t raw[UNIFIED_WORKSPACE_SIZE];
} unified_workspace_t;

// Workspace manager class
class UnifiedWorkspace {
private:
    static unified_workspace_t* workspace_instance;
    static bool workspace_allocated;
    
public:
    // Workspace lifecycle
    static bool allocate();
    static void deallocate();
    static bool is_allocated();
    static unified_workspace_t* get();
    
    // Memory utilities
    static void secure_clear();
    static void secure_clear_region(void* ptr, size_t len);
    static size_t get_total_size();
    static size_t get_free_size();
    
    // Validation utilities
    static bool validate_bounds(const void* ptr, size_t len);
    static bool is_crypto_buffer_available();
};

// RAII Workspace Guard (Exception Safety)
class ScopedWorkspace {
private:
    unified_workspace_t* ws;
    
public:
    ScopedWorkspace() {
        ws = UnifiedWorkspace::get();
        if (!ws) {
            // Allocation failed
            ws = nullptr;
        }
    }
    
    ~ScopedWorkspace() {
        if (ws) {
            // Clear sensitive data on scope exit
            UnifiedWorkspace::secure_clear();
        }
    }
    
    unified_workspace_t* operator->() const { return ws; }
    unified_workspace_t& operator*() const { return *ws; }
    operator bool() const { return ws != nullptr; }
    
    // Prevent copying
    ScopedWorkspace(const ScopedWorkspace&) = delete;
    ScopedWorkspace& operator=(const ScopedWorkspace&) = delete;
};

// Memory-efficient bit packing utilities
class BitPacker {
public:
    // Kyber coefficient packing (12-bit)
    static void pack_kyber_coefficients(uint8_t* out, const int16_t* in, size_t count);
    static void unpack_kyber_coefficients(int16_t* out, const uint8_t* in, size_t count);
    
    // Dilithium coefficient packing (24-bit)  
    static void pack_dilithium_coefficients(uint8_t* out, const int32_t* in, size_t count);
    static void unpack_dilithium_coefficients(int32_t* out, const uint8_t* in, size_t count);
    
    // Utility functions
    static size_t kyber_packed_size(size_t coefficients);
    static size_t dilithium_packed_size(size_t coefficients);
};

// Platform-specific optimizations
class MemoryOptimizer {
public:
    // ESP32: Use external RAM if available
    static bool use_external_ram();
    
    // STM32: Optimize for 64KB limit
    static void optimize_for_stm32();
    
    // General: Memory fragmentation prevention
    static void prevent_fragmentation();
    static size_t get_largest_free_block();
};

// Debug and monitoring
class MemoryMonitor {
public:
    static void print_memory_usage();
    static void log_memory_stats();
    static bool check_memory_leak();
    static void reset_peak_usage();
};

} // namespace Memory
} // namespace PQC

#endif
