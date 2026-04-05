#include "../include/platform.h"
#include "../include/network_abstract.h"

#ifdef PLATFORM_ESP32
#include <Arduino.h>
#include <esp_now.h>
#include <WiFi.h>
#include <esp_log.h>

/*
  ESP32 NETWORK IMPLEMENTATION
  ---------------------------
  ESP-NOW transport backend for cross-platform abstraction
*/

namespace PQC {
namespace Network {

// ESP32 Transport Implementation
bool ESPNowTransport::init() {
    // Initialize WiFi in station mode
    WiFi.mode(WIFI_STA);
    
    // Get device MAC address
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    
    // Initialize ESP-NOW
    if (esp_now_init() != ESP_OK) {
        ESP_LOGE("ESP32_NET", "ESP-NOW initialization failed");
        return false;
    }
    
    // Register callbacks
    esp_now_register_recv_cb(on_data_recv_callback);
    esp_now_register_send_cb(on_data_sent_callback);
    
    ESP_LOGI("ESP32_NET", "ESP-NOW initialized successfully");
    ESP_LOGI("ESP32_NET", "Device MAC: %02X:%02X:%02X:%02X:%02X:%02X", 
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    
    return true;
}

bool ESPNowTransport::send_raw(const uint8_t* target_mac, const uint8_t* data, size_t len) {
    if (!target_mac || !data || len == 0 || len > NETWORK_MAX_PACKET_SIZE) {
        return false;
    }
    
    esp_err_t result = esp_now_send((uint8_t*)target_mac, (uint8_t*)data, len);
    return (result == ESP_OK);
}

bool ESPNowTransport::receive_raw(uint8_t* source_mac, uint8_t* data, size_t* len, uint32_t timeout_ms) {
    // ESP-NOW uses callback-based reception
    // This is a simplified implementation for synchronous use
    // In practice, data should be handled in callbacks
    return false; // Not implemented for synchronous use
}

bool ESPNowTransport::is_data_available() {
    // Check if there's data in the receive queue
    // This would need to be implemented with a queue system
    return false; // Simplified
}

void ESPNowTransport::set_receive_callback(void (*callback)(const uint8_t* mac, const uint8_t* data, int len)) {
    // Store callback for use in ESP-NOW receive callback
    // This would need to be implemented with a static callback pointer
}

bool ESPNowTransport::get_device_mac(uint8_t* mac) {
    if (!mac) return false;
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    return true;
}

// ESP-NOW Callbacks
void ESPNowTransport::on_data_sent_callback(const uint8_t* mac, esp_now_send_status_t status) {
    if (status == ESP_NOW_SEND_SUCCESS) {
        ESP_LOGD("ESP32_NET", "Packet sent successfully to %02X:%02X:%02X:%02X:%02X:%02X", 
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    } else {
        ESP_LOGE("ESP32_NET", "Packet send failed to %02X:%02X:%02X:%02X:%02X:%02X", 
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }
}

void ESPNowTransport::on_data_recv_callback(const uint8_t* mac, const uint8_t* data, int len) {
    ESP_LOGD("ESP32_NET", "Received %d bytes from %02X:%02X:%02X:%02X:%02X:%02X", 
             len, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    
    // This would forward to the NetworkManager
    // Implementation depends on the callback storage mechanism
}

// ESP32 Platform Implementation
class ESP32Platform : public IPlatform {
private:
    PlatformInfo info;
    
public:
    ESP32Platform() {
        info.name = "ESP32-WROOM-32";
        info.ram_size = PLATFORM_RAM_SIZE;
        info.max_workspace = PLATFORM_MAX_WORKSPACE;
        info.has_hw_crypto = PLATFORM_HAS_HARDWARE_CRYPTO;
        info.has_rtos = PLATFORM_HAS_FREERTOS;
        info.has_multicore = PLATFORM_HAS_MULTICORE;
        info.cpu_cores = 2;
    }
    
    bool init() override {
        ESP_LOGI("ESP32_PLATFORM", "Initializing ESP32 platform");
        
        // Initialize Serial if not already done
        Serial.begin(115200);
        delay(1000);
        
        ESP_LOGI("ESP32_PLATFORM", "ESP32 platform initialized");
        return true;
    }
    
    void delay_ms(uint32_t ms) override {
        delay(ms);
    }
    
    uint32_t get_tick_ms() override {
        return millis();
    }
    
    bool get_device_mac(uint8_t* mac) override {
        if (!mac) return false;
        esp_read_mac(mac, ESP_MAC_WIFI_STA);
        return true;
    }
    
    void secure_wipe(void* ptr, size_t len) override {
        if (ptr && len > 0) {
            // ESP32: Multiple pass clearing
            memset(ptr, 0xFF, len);
            memset(ptr, 0x00, len);
            memset(ptr, 0xAA, len);
            memset(ptr, 0x00, len);
        }
    }
    
    bool get_random_bytes(uint8_t* buf, size_t len) override {
        if (!buf || len == 0) return false;
        
        // ESP32: Use hardware random number generator
        esp_fill_random(buf, len);
        return true;
    }
    
    const PlatformInfo& get_info() override {
        return info;
    }
};

// ESP32 Memory Manager
class ESP32MemoryManager : public IMemoryManager {
public:
    void* allocate_workspace(size_t size) override {
        // ESP32: Try internal RAM first, then external if available
        void* ptr = heap_caps_malloc(size, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
        if (!ptr) {
            // Try external RAM
            ptr = heap_caps_malloc(size, MALLOC_CAP_EXTERNAL | MALLOC_CAP_8BIT);
        }
        return ptr;
    }
    
    void free_workspace(void* ptr) override {
        if (ptr) {
            heap_caps_free(ptr);
        }
    }
    
    size_t get_free_heap() override {
        return ESP.getFreeHeap();
    }
    
    size_t get_min_free_heap() override {
        return ESP.getMinFreeHeap();
    }
};

// ESP32 Storage Interface
class ESP32StorageInterface : public IStorageInterface {
public:
    bool init() override {
        ESP_LOGI("ESP32_STORAGE", "Initializing ESP32 storage");
        // Implementation would initialize NVS and LittleFS
        return true;
    }
    
    bool save_key(const char* key_name, const uint8_t* data, size_t len) override {
        // Implementation using NVS
        return false; // Simplified
    }
    
    bool load_key(const char* key_name, uint8_t* data, size_t len) override {
        // Implementation using NVS
        return false; // Simplified
    }
    
    bool save_data(const char* filename, const uint8_t* data, size_t len) override {
        // Implementation using LittleFS
        return false; // Simplified
    }
    
    bool load_data(const char* filename, uint8_t* data, size_t* len) override {
        // Implementation using LittleFS
        return false; // Simplified
    }
    
    bool delete_data(const char* filename) override {
        // Implementation using LittleFS
        return false; // Simplified
    }
};

// ESP32 Log Interface
class ESP32LogInterface : public ILogInterface {
public:
    bool init() override {
        ESP_LOGI("ESP32_LOG", "Initializing ESP32 logging");
        return true;
    }
    
    void log_security_incident(const char* type, const uint8_t* mac) override {
        if (mac) {
            ESP_LOGW("ESP32_LOG", "Security incident: %s from %02X:%02X:%02X:%02X:%02X:%02X", 
                     type, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        } else {
            ESP_LOGW("ESP32_LOG", "Security incident: %s from unknown source", type);
        }
    }
    
    void log_error(const char* operation, uint32_t iteration, size_t leak_amount) override {
        ESP_LOGE("ESP32_LOG", "Error in %s at iteration %u, leak: %zu bytes", 
                 operation, iteration, leak_amount);
    }
    
    void print_logs() override {
        ESP_LOGI("ESP32_LOG", "Printing stored logs...");
        // Implementation would read from storage and print
    }
    
    void clear_logs() override {
        ESP_LOGI("ESP32_LOG", "Clearing stored logs");
        // Implementation would clear storage
    }
    
    bool has_logs() override {
        return false; // Simplified
    }
};

// ESP32 Network Interface
class ESP32NetworkInterface : public INetworkInterface {
private:
    ESPNowTransport transport;
    
public:
    bool init() override {
        ESP_LOGI("ESP32_NET", "Initializing ESP32 network interface");
        return transport.init();
    }
    
    bool send_packet(const uint8_t* target_mac, const uint8_t* data, size_t len) override {
        return transport.send_raw(target_mac, data, len);
    }
    
    bool receive_packet(uint8_t* source_mac, uint8_t* data, size_t* len) override {
        return transport.receive_raw(source_mac, data, len, 1000);
    }
    
    bool is_packet_available() override {
        return transport.is_data_available();
    }
    
    void set_receive_callback(void (*callback)(const uint8_t* mac, const uint8_t* data, int len)) override {
        transport.set_receive_callback(callback);
    }
};

} // namespace Network
} // namespace PQC

// Factory implementations for ESP32
namespace PQC {
namespace Platform {

IPlatform* PlatformFactory::create_platform() {
    return new Network::ESP32Platform();
}

IMemoryManager* PlatformFactory::create_memory_manager() {
    return new Network::ESP32MemoryManager();
}

INetworkInterface* PlatformFactory::create_network_interface() {
    return new Network::ESP32NetworkInterface();
}

IStorageInterface* PlatformFactory::create_storage_interface() {
    return new Network::ESP32StorageInterface();
}

ILogInterface* PlatformFactory::create_log_interface() {
    return new Network::ESP32LogInterface();
}

} // namespace Platform
} // namespace PQC

#endif // PLATFORM_ESP32
