#include "../include/workspace_unified.h"
#include "../include/platform.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/*
  UNIFIED WORKSPACE IMPLEMENTATION
  --------------------------------
  Cross-platform memory management for Kyber/Dilithium
*/

namespace PQC {
namespace Memory {

// Static member initialization
unified_workspace_t* UnifiedWorkspace::workspace_instance = nullptr;
bool UnifiedWorkspace::workspace_allocated = false;

bool UnifiedWorkspace::allocate() {
    if (workspace_allocated) {
        return true; // Already allocated
    }
    
    // Platform-specific allocation
#ifdef PLATFORM_ESP32
    workspace_instance = (unified_workspace_t*)malloc(UNIFIED_WORKSPACE_SIZE);
#elif defined(PLATFORM_STM32)
    workspace_instance = (unified_workspace_t*)malloc(UNIFIED_WORKSPACE_SIZE);
    if (!workspace_instance) {
        // Try smaller allocation for STM32
        workspace_instance = (unified_workspace_t*)malloc(UNIFIED_WORKSPACE_SIZE / 2);
    }
#elif defined(PLATFORM_PC)
    workspace_instance = (unified_workspace_t*)malloc(UNIFIED_WORKSPACE_SIZE);
#else
    workspace_instance = nullptr;
#endif

    if (!workspace_instance) {
        return false;
    }
    
    // Initialize to zero
    memset(workspace_instance, 0, UNIFIED_WORKSPACE_SIZE);
    workspace_allocated = true;
    
    return true;
}

void UnifiedWorkspace::deallocate() {
    if (workspace_instance && workspace_allocated) {
        // Secure clear before deallocation
        secure_clear();
        free(workspace_instance);
        workspace_instance = nullptr;
        workspace_allocated = false;
    }
}

bool UnifiedWorkspace::is_allocated() {
    return workspace_allocated && (workspace_instance != nullptr);
}

unified_workspace_t* UnifiedWorkspace::get() {
    if (!workspace_allocated || !workspace_instance) {
        return nullptr;
    }
    return workspace_instance;
}

void UnifiedWorkspace::secure_clear() {
    if (workspace_instance) {
        // Platform-specific secure clear
#ifdef PLATFORM_ESP32
        // ESP32: Use memset with multiple passes
        for (int i = 0; i < 3; i++) {
            memset(workspace_instance->raw, 0xFF, UNIFIED_WORKSPACE_SIZE);
            memset(workspace_instance->raw, 0x00, UNIFIED_WORKSPACE_SIZE);
        }
#elif defined(PLATFORM_STM32)
        // STM32: Simple memset (no hardware acceleration)
        memset(workspace_instance->raw, 0x00, UNIFIED_WORKSPACE_SIZE);
#elif defined(PLATFORM_PC)
        // PC: Multiple pass clearing
        for (int i = 0; i < 5; i++) {
            memset(workspace_instance->raw, 0xAA, UNIFIED_WORKSPACE_SIZE);
            memset(workspace_instance->raw, 0x55, UNIFIED_WORKSPACE_SIZE);
            memset(workspace_instance->raw, 0x00, UNIFIED_WORKSPACE_SIZE);
        }
#endif
    }
}

void UnifiedWorkspace::secure_clear_region(void* ptr, size_t len) {
    if (ptr && len > 0) {
        // Validate bounds
        if (validate_bounds(ptr, len)) {
            // Platform-specific clearing
#ifdef PLATFORM_ESP32
            memset(ptr, 0xFF, len);
            memset(ptr, 0x00, len);
#else
            memset(ptr, 0x00, len);
#endif
        }
    }
}

size_t UnifiedWorkspace::get_total_size() {
    return UNIFIED_WORKSPACE_SIZE;
}

size_t UnifiedWorkspace::get_free_size() {
    if (!workspace_allocated) {
        return 0;
    }
    
    // Estimate free space based on used regions
    size_t used = sizeof(workspace_instance->kyber_pk) + 
                  sizeof(workspace_instance->kyber_sk) + 
                  sizeof(workspace_instance->kyber_ct) +
                  sizeof(workspace_instance->kyber_ss) +
                  sizeof(workspace_instance->dilithium_pk) +
                  sizeof(workspace_instance->dilithium_sk) +
                  sizeof(workspace_instance->dilithium_sig);
    
    return (UNIFIED_WORKSPACE_SIZE > used) ? (UNIFIED_WORKSPACE_SIZE - used) : 0;
}

bool UnifiedWorkspace::validate_bounds(const void* ptr, size_t len) {
    if (!workspace_instance || !ptr) {
        return false;
    }
    
    const uint8_t* start = (const uint8_t*)ptr;
    const uint8_t* workspace_start = (const uint8_t*)workspace_instance;
    const uint8_t* workspace_end = workspace_start + UNIFIED_WORKSPACE_SIZE;
    
    // Check if pointer is within workspace bounds
    if (start < workspace_start || start >= workspace_end) {
        return false;
    }
    
    // Check if length would exceed bounds
    if ((start + len) > workspace_end) {
        return false;
    }
    
    return true;
}

bool UnifiedWorkspace::is_crypto_buffer_available() {
    return get_free_size() >= CRYPTO_BUFFER_SIZE;
}

// BitPacker Implementation
void BitPacker::pack_kyber_coefficients(uint8_t* out, const int16_t* in, size_t count) {
    // Pack 12-bit coefficients into bytes
    size_t out_idx = 0;
    uint32_t buffer = 0;
    uint8_t bits_in_buffer = 0;
    
    for (size_t i = 0; i < count; i++) {
        // Convert to unsigned 12-bit
        uint16_t coeff = (uint16_t)(in[i] & 0xFFF);
        buffer = (buffer << 12) | coeff;
        bits_in_buffer += 12;
        
        // Extract bytes when we have enough bits
        while (bits_in_buffer >= 8) {
            bits_in_buffer -= 8;
            out[out_idx++] = (buffer >> bits_in_buffer) & 0xFF;
        }
    }
    
    // Handle remaining bits
    if (bits_in_buffer > 0) {
        out[out_idx++] = (buffer << (8 - bits_in_buffer)) & 0xFF;
    }
}

void BitPacker::unpack_kyber_coefficients(int16_t* out, const uint8_t* in, size_t count) {
    // Unpack bytes into 12-bit coefficients
    size_t in_idx = 0;
    uint32_t buffer = 0;
    uint8_t bits_in_buffer = 0;
    
    for (size_t i = 0; i < count; i++) {
        // Accumulate bits until we have 12
        while (bits_in_buffer < 12 && in_idx < count * 3 / 2) {
            buffer = (buffer << 8) | in[in_idx++];
            bits_in_buffer += 8;
        }
        
        if (bits_in_buffer >= 12) {
            bits_in_buffer -= 12;
            uint16_t coeff = (buffer >> bits_in_buffer) & 0xFFF;
            
            // Convert back to signed
            out[i] = (coeff >= 2048) ? (coeff - 4096) : coeff;
        }
    }
}

void BitPacker::pack_dilithium_coefficients(uint8_t* out, const int32_t* in, size_t count) {
    // Pack 24-bit coefficients into bytes
    size_t out_idx = 0;
    uint32_t buffer = 0;
    uint8_t bits_in_buffer = 0;
    
    for (size_t i = 0; i < count; i++) {
        // Convert to unsigned 24-bit
        uint32_t coeff = (uint32_t)(in[i] & 0xFFFFFF);
        buffer = (buffer << 24) | coeff;
        bits_in_buffer += 24;
        
        // Extract bytes when we have enough bits
        while (bits_in_buffer >= 8) {
            bits_in_buffer -= 8;
            out[out_idx++] = (buffer >> bits_in_buffer) & 0xFF;
        }
    }
    
    // Handle remaining bits
    if (bits_in_buffer > 0) {
        out[out_idx++] = (buffer << (8 - bits_in_buffer)) & 0xFF;
    }
}

void BitPacker::unpack_dilithium_coefficients(int32_t* out, const uint8_t* in, size_t count) {
    // Unpack bytes into 24-bit coefficients
    size_t in_idx = 0;
    uint32_t buffer = 0;
    uint8_t bits_in_buffer = 0;
    
    for (size_t i = 0; i < count; i++) {
        // Accumulate bits until we have 24
        while (bits_in_buffer < 24 && in_idx < count * 3) {
            buffer = (buffer << 8) | in[in_idx++];
            bits_in_buffer += 8;
        }
        
        if (bits_in_buffer >= 24) {
            bits_in_buffer -= 24;
            uint32_t coeff = (buffer >> bits_in_buffer) & 0xFFFFFF;
            
            // Convert back to signed
            out[i] = (coeff >= 8388608) ? (coeff - 16777216) : coeff;
        }
    }
}

size_t BitPacker::kyber_packed_size(size_t coefficients) {
    // 12 bits per coefficient = 1.5 bytes
    return (coefficients * 3 + 1) / 2;
}

size_t BitPacker::dilithium_packed_size(size_t coefficients) {
    // 24 bits per coefficient = 3 bytes
    return coefficients * 3;
}

// MemoryOptimizer Implementation
bool MemoryOptimizer::use_external_ram() {
#ifdef PLATFORM_ESP32
    // Check if external RAM is available on ESP32
    return true; // Simplified for now
#else
    return false;
#endif
}

void MemoryOptimizer::optimize_for_stm32() {
#ifdef PLATFORM_STM32
    // STM32-specific optimizations
    // Reduce buffer sizes, disable features, etc.
#endif
}

void MemoryOptimizer::prevent_fragmentation() {
    // Platform-specific fragmentation prevention
#ifdef PLATFORM_ESP32
    // ESP32: Use heap_caps_malloc with specific capabilities
#elif defined(PLATFORM_STM32)
    // STM32: Use static allocation where possible
#endif
}

size_t MemoryOptimizer::get_largest_free_block() {
#ifdef PLATFORM_ESP32
    return heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT);
#elif defined(PLATFORM_STM32)
    // STM32: Simplified implementation
    return 1024;
#elif defined(PLATFORM_PC)
    return 65536;
#else
    return 0;
#endif
}

// MemoryMonitor Implementation
void MemoryMonitor::print_memory_usage() {
    size_t free_heap = 0;
    size_t min_free = 0;
    
#ifdef PLATFORM_ESP32
    free_heap = ESP.getFreeHeap();
    min_free = ESP.getMinFreeHeap();
#elif defined(PLATFORM_STM32)
    // STM32: Use custom heap tracking
    free_heap = MemoryOptimizer::get_largest_free_block();
    min_free = free_heap / 2; // Simplified
#elif defined(PLATFORM_PC)
    free_heap = 16000000; // 16MB
    min_free = 8000000;   // 8MB
#endif

    printf("=== MEMORY USAGE ===\n");
    printf("Platform: %s\n", Platform::get_platform_name());
    printf("Workspace Size: %d bytes\n", UNIFIED_WORKSPACE_SIZE);
    printf("Free Heap: %d bytes\n", free_heap);
    printf("Min Free Heap: %d bytes\n", min_free);
    printf("Workspace Free: %d bytes\n", UnifiedWorkspace::get_free_size());
    printf("===================\n");
}

void MemoryMonitor::log_memory_stats() {
    // Log memory statistics to storage
    char log_msg[128];
    snprintf(log_msg, sizeof(log_msg), "MEM: Free=%d, Min=%d, WS_Free=%d", 
             Platform::Memory->get_free_heap(),
             Platform::Memory->get_min_free_heap(),
             UnifiedWorkspace::get_free_size());
    
    if (Platform::Logger) {
        Platform::Logger->log_error("MEMORY_STATS", 0, strlen(log_msg));
    }
}

bool MemoryMonitor::check_memory_leak() {
    static size_t last_free_heap = 0;
    size_t current_free = Platform::Memory->get_free_heap();
    
    if (last_free_heap > 0) {
        size_t leak_amount = last_free_heap - current_free;
        if (leak_amount > 1024) { // 1KB threshold
            if (Platform::Logger) {
                Platform::Logger->log_error("MEMORY_LEAK", 0, leak_amount);
            }
            return true;
        }
    }
    
    last_free_heap = current_free;
    return false;
}

void MemoryMonitor::reset_peak_usage() {
#ifdef PLATFORM_ESP32
    ESP.resetMinMaxFreeHeap();
#endif
}

} // namespace Memory
} // namespace PQC
