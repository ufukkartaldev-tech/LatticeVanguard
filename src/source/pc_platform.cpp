#include "../include/platform.h"

#ifdef PLATFORM_PC
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <random>

/*
  PC PLATFORM IMPLEMENTATION
  --------------------------
  Host-side (simulation) backend for the cross-platform factory. Mirrors the
  ESP32/STM32 backends so the desktop build can construct the same abstraction
  objects for development and testing.
*/

namespace PQC {
namespace Platform {

// PC Platform Implementation
class PCPlatform : public IPlatform {
private:
    PlatformInfo info;

public:
    PCPlatform() {
        info.name = "PC Simulation";
        info.ram_size = PLATFORM_RAM_SIZE;
        info.max_workspace = PLATFORM_MAX_WORKSPACE;
        info.has_hw_crypto = PLATFORM_HAS_HARDWARE_CRYPTO;
        info.has_rtos = PLATFORM_HAS_FREERTOS;
        info.has_multicore = PLATFORM_HAS_MULTICORE;
        info.cpu_cores = 1;
    }

    bool init() override { return true; }

    void delay_ms(uint32_t) override {}

    uint32_t get_tick_ms() override {
        return (uint32_t)(clock() * 1000 / CLOCKS_PER_SEC);
    }

    bool get_device_mac(uint8_t* mac) override {
        if (!mac) return false;
        static const uint8_t pc_mac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED};
        memcpy(mac, pc_mac, 6);
        return true;
    }

    void secure_wipe(void* ptr, size_t len) override {
        if (ptr && len > 0) {
            memset(ptr, 0xFF, len);
            memset(ptr, 0x00, len);
        }
    }

    bool get_random_bytes(uint8_t* buf, size_t len) override {
        if (!buf || len == 0) return false;
        std::random_device rd;
        size_t i = 0;
        while (i < len) {
            uint32_t r = rd();
            size_t chunk = (len - i < sizeof(r)) ? (len - i) : sizeof(r);
            memcpy(buf + i, &r, chunk);
            i += chunk;
        }
        return true;
    }

    const PlatformInfo& get_info() override { return info; }
};

// PC Memory Manager (standard heap)
class PCMemoryManager : public IMemoryManager {
public:
    void* allocate_workspace(size_t size) override { return malloc(size); }

    void free_workspace(void* ptr) override {
        if (ptr) free(ptr);
    }

    size_t get_free_heap() override { return PLATFORM_RAM_SIZE; }
    size_t get_min_free_heap() override { return PLATFORM_RAM_SIZE; }
};

// PC Network Interface (loopback stub)
class PCNetworkInterface : public INetworkInterface {
public:
    bool init() override { return true; }
    bool send_packet(const uint8_t*, const uint8_t*, size_t) override { return true; }
    bool receive_packet(uint8_t*, uint8_t*, size_t*) override { return false; }
    bool is_packet_available() override { return false; }
    void set_receive_callback(void (*)(const uint8_t*, const uint8_t*, int)) override {}
};

// PC Storage Interface (stub)
class PCStorageInterface : public IStorageInterface {
public:
    bool init() override { return true; }
    bool save_key(const char*, const uint8_t*, size_t) override { return false; }
    bool load_key(const char*, uint8_t*, size_t) override { return false; }
    bool save_data(const char*, const uint8_t*, size_t) override { return false; }
    bool load_data(const char*, uint8_t*, size_t*) override { return false; }
    bool delete_data(const char*) override { return false; }
};

// PC Log Interface (stdout)
class PCLogInterface : public ILogInterface {
public:
    bool init() override { return true; }

    void log_security_incident(const char* type, const uint8_t* mac) override {
        if (mac) {
            printf("[SECURITY] %s from %02X:%02X:%02X:%02X:%02X:%02X\n",
                   type, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        } else {
            printf("[SECURITY] %s from unknown source\n", type);
        }
    }

    void log_error(const char* operation, uint32_t iteration, size_t leak_amount) override {
        printf("[ERROR] %s at iteration %u, leak: %zu bytes\n",
               operation, iteration, leak_amount);
    }

    void print_logs() override { printf("[LOG] Printing stored logs...\n"); }
    void clear_logs() override { printf("[LOG] Clearing stored logs\n"); }
    bool has_logs() override { return false; }
};

// Factory implementations for PC
IPlatform* PlatformFactory::create_platform() { return new PCPlatform(); }
IMemoryManager* PlatformFactory::create_memory_manager() { return new PCMemoryManager(); }
INetworkInterface* PlatformFactory::create_network_interface() { return new PCNetworkInterface(); }
IStorageInterface* PlatformFactory::create_storage_interface() { return new PCStorageInterface(); }
ILogInterface* PlatformFactory::create_log_interface() { return new PCLogInterface(); }

} // namespace Platform
} // namespace PQC

#endif // PLATFORM_PC
