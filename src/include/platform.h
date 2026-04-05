#ifndef PQC_PLATFORM_H
#define PQC_PLATFORM_H

/*
  PLATFORM-AGNOSTIC ABSTRACTION LAYER
  ------------------------------------
  ESP32 ve STM32F103C8T6 için ortak arayüz
*/

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// Platform Detection
#ifdef ARDUINO
  #ifdef ESP32
    #define PLATFORM_ESP32
  #elif defined(STM32F1xx) || defined(STM32F103xB)
    #define PLATFORM_STM32
  #endif
#else
  // PC Simulation
  #define PLATFORM_PC
#endif

// Memory Constraints per Platform
#ifdef PLATFORM_ESP32
  #define PLATFORM_RAM_SIZE 520000      // 520KB
  #define PLATFORM_MAX_WORKSPACE 16384  // 16KB unified workspace
  #define PLATFORM_HAS_HARDWARE_CRYPTO  1
  #define PLATFORM_HAS_FREERTOS 1
  #define PLATFORM_HAS_MULTICORE 1
#elif defined(PLATFORM_STM32)
  #define PLATFORM_RAM_SIZE 64000       // 64KB  
  #define PLATFORM_MAX_WORKSPACE 8192   // 8KB optimized workspace
  #define PLATFORM_HAS_HARDWARE_CRYPTO  0
  #define PLATFORM_HAS_FREERTOS 1
  #define PLATFORM_HAS_MULTICORE 0
#elif defined(PLATFORM_PC)
  #define PLATFORM_RAM_SIZE 16000000    // 16MB for testing
  #define PLATFORM_MAX_WORKSPACE 32768   // 32KB for stress testing
  #define PLATFORM_HAS_HARDWARE_CRYPTO  0
  #define PLATFORM_HAS_FREERTOS 0
  #define PLATFORM_HAS_MULTICORE 1
#endif

namespace PQC {
namespace Platform {

// Platform Information
struct PlatformInfo {
    const char* name;
    uint32_t ram_size;
    uint32_t max_workspace;
    bool has_hw_crypto;
    bool has_rtos;
    bool has_multicore;
    uint8_t cpu_cores;
};

// Base Platform Interface
class IPlatform {
public:
    virtual bool init() = 0;
    virtual void delay_ms(uint32_t ms) = 0;
    virtual uint32_t get_tick_ms() = 0;
    virtual bool get_device_mac(uint8_t* mac) = 0;
    virtual void secure_wipe(void* ptr, size_t len) = 0;
    virtual bool get_random_bytes(uint8_t* buf, size_t len) = 0;
    virtual const PlatformInfo& get_info() = 0;
};

// Memory Management Interface
class IMemoryManager {
public:
    virtual void* allocate_workspace(size_t size) = 0;
    virtual void free_workspace(void* ptr) = 0;
    virtual size_t get_free_heap() = 0;
    virtual size_t get_min_free_heap() = 0;
};

// Network Interface
class INetworkInterface {
public:
    virtual bool init() = 0;
    virtual bool send_packet(const uint8_t* target_mac, const uint8_t* data, size_t len) = 0;
    virtual bool receive_packet(uint8_t* source_mac, uint8_t* data, size_t* len) = 0;
    virtual bool is_packet_available() = 0;
    virtual void set_receive_callback(void (*callback)(const uint8_t* mac, const uint8_t* data, int len)) = 0;
};

// Storage Interface  
class IStorageInterface {
public:
    virtual bool init() = 0;
    virtual bool save_key(const char* key_name, const uint8_t* data, size_t len) = 0;
    virtual bool load_key(const char* key_name, uint8_t* data, size_t len) = 0;
    virtual bool save_data(const char* filename, const uint8_t* data, size_t len) = 0;
    virtual bool load_data(const char* filename, uint8_t* data, size_t* len) = 0;
    virtual bool delete_data(const char* filename) = 0;
};

// Logging Interface
class ILogInterface {
public:
    virtual bool init() = 0;
    virtual void log_security_incident(const char* type, const uint8_t* mac) = 0;
    virtual void log_error(const char* operation, uint32_t iteration, size_t leak_amount) = 0;
    virtual void print_logs() = 0;
    virtual void clear_logs() = 0;
    virtual bool has_logs() = 0;
};

// Platform Factory
class PlatformFactory {
public:
    static IPlatform* create_platform();
    static IMemoryManager* create_memory_manager();
    static INetworkInterface* create_network_interface();
    static IStorageInterface* create_storage_interface();
    static ILogInterface* create_log_interface();
};

// Global Platform Access
extern IPlatform* Platform;
extern IMemoryManager* Memory;
extern INetworkInterface* Network;
extern IStorageInterface* Storage;
extern ILogInterface* Logger;

// Utility Functions
bool initialize_platform();
void shutdown_platform();
const char* get_platform_name();
bool is_esp32_platform();
bool is_stm32_platform();
bool is_pc_platform();

} // namespace Platform
} // namespace PQC

#endif
