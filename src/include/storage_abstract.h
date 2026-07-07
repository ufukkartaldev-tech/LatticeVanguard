#ifndef PQC_STORAGE_ABSTRACT_H
#define PQC_STORAGE_ABSTRACT_H

/*
  CROSS-PLATFORM STORAGE ABSTRACTION
  ----------------------------------
  ESP32 (LittleFS/NVS) ve STM32 (EEPROM/SD Kart) için ortak arayüz
*/

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string>
#include "platform.h"

namespace PQC {
namespace Storage {

// Storage Limits per Platform
#ifdef PLATFORM_ESP32
  #define STORAGE_MAX_KEY_SIZE      32      // NVS key name limit
  #define STORAGE_MAX_VALUE_SIZE    512     // NVS value limit
  #define STORAGE_MAX_FILENAME_LEN  32      // LittleFS filename limit
  #define STORAGE_MAX_FILE_SIZE     4096    // LittleFS file limit
  #define STORAGE_HAS_ENCRYPTION    1       // Hardware encryption
#elif defined(PLATFORM_STM32)
  #define STORAGE_MAX_KEY_SIZE      16      // EEPROM optimization
  #define STORAGE_MAX_VALUE_SIZE    256     // EEPROM limit
  #define STORAGE_MAX_FILENAME_LEN  8       // 8.3 format for SD
  #define STORAGE_MAX_FILE_SIZE     2048    // SD card optimization
  #define STORAGE_HAS_ENCRYPTION    0       // Software encryption
#elif defined(PLATFORM_PC)
  #define STORAGE_MAX_KEY_SIZE      64      // PC unlimited
  #define STORAGE_MAX_VALUE_SIZE    4096    // PC unlimited
  #define STORAGE_MAX_FILENAME_LEN  256     // PC unlimited
  #define STORAGE_MAX_FILE_SIZE     65536   // PC unlimited
  #define STORAGE_HAS_ENCRYPTION    0       // File system encryption
#endif

// Storage Types
enum StorageType {
    STORAGE_KEY_VALUE = 0,  // For keys, settings
    STORAGE_FILE = 1,        // For logs, certificates
    STORAGE_SECURE = 2,      // For sensitive data
    STORAGE_TEMP = 3         // For temporary data
};

// Storage Result Codes
enum StorageResult {
    STORAGE_OK = 0,
    STORAGE_ERROR_NOT_FOUND = -1,
    STORAGE_ERROR_FULL = -2,
    STORAGE_ERROR_CORRUPT = -3,
    STORAGE_ERROR_PERMISSION = -4,
    STORAGE_ERROR_HARDWARE = -5,
    STORAGE_ERROR_INVALID = -6,
    STORAGE_ERROR_TIMEOUT = -7
};

// Storage Statistics
typedef struct {
    uint32_t total_space;
    uint32_t used_space;
    uint32_t free_space;
    uint32_t key_count;
    uint32_t file_count;
    uint32_t write_count;
    uint32_t read_count;
    uint32_t error_count;
} storage_stats_t;

// Abstract Storage Interface
class IStorageBackend {
public:
    virtual ~IStorageBackend() = default;
    
    // Core storage operations
    virtual StorageResult init() = 0;
    virtual StorageResult shutdown() = 0;
    virtual StorageResult format() = 0;
    virtual bool is_available() = 0;
    
    // Key-Value operations
    virtual StorageResult save_key(const char* key_name, const uint8_t* data, size_t len) = 0;
    virtual StorageResult load_key(const char* key_name, uint8_t* data, size_t* len) = 0;
    virtual StorageResult delete_key(const char* key_name) = 0;
    virtual bool key_exists(const char* key_name) = 0;
    
    // File operations
    virtual StorageResult save_file(const char* filename, const uint8_t* data, size_t len) = 0;
    virtual StorageResult load_file(const char* filename, uint8_t* data, size_t* len) = 0;
    virtual StorageResult delete_file(const char* filename) = 0;
    virtual StorageResult append_file(const char* filename, const uint8_t* data, size_t len) = 0;
    virtual bool file_exists(const char* filename) = 0;
    virtual size_t get_file_size(const char* filename) = 0;
    
    // Security operations
    virtual StorageResult secure_save(const char* name, const uint8_t* data, size_t len, const uint8_t* key) = 0;
    virtual StorageResult secure_load(const char* name, uint8_t* data, size_t* len, const uint8_t* key) = 0;
    
    // Maintenance
    virtual StorageResult defragment() = 0;
    virtual StorageResult verify_integrity() = 0;
    virtual StorageResult get_stats(storage_stats_t* stats) = 0;
    
    // Backend info
    virtual const char* get_backend_name() = 0;
    virtual uint32_t get_total_capacity() = 0;
    virtual bool supports_encryption() = 0;
    virtual bool is_volatile() = 0;
};

// High-Level Storage Manager
class StorageManager {
private:
    static IStorageBackend* backend;
    static storage_stats_t stats;
    static volatile bool initialized;
    
    // Encryption helpers
    static bool encrypt_data(const uint8_t* input, uint8_t* output, size_t len, const uint8_t* key);
    static bool decrypt_data(const uint8_t* input, uint8_t* output, size_t len, const uint8_t* key);
    
    // Validation helpers
    static bool validate_key_name(const char* key_name);
    static bool validate_filename(const char* filename);
    static uint8_t compute_checksum(const uint8_t* data, size_t len);
    
public:
    // Initialization
    static bool initialize(IStorageBackend* storage_backend);
    static void shutdown();
    static bool is_initialized();
    
    // Key-Value operations (with validation)
    static bool save_key(const char* key_name, const uint8_t* data, size_t len);
    static bool load_key(const char* key_name, uint8_t* data, size_t len);
    static bool delete_key(const char* key_name);
    static bool key_exists(const char* key_name);
    
    // File operations (with validation)
    static bool save_file(const char* filename, const uint8_t* data, size_t len);
    static bool load_file(const char* filename, uint8_t* data, size_t* len);
    static bool delete_file(const char* filename);
    static bool append_file(const char* filename, const uint8_t* data, size_t len);
    static bool file_exists(const char* filename);
    static size_t get_file_size(const char* filename);
    
    // Secure operations (automatic encryption)
    static bool secure_save_key(const char* key_name, const uint8_t* data, size_t len, const uint8_t* encryption_key);
    static bool secure_load_key(const char* key_name, uint8_t* data, size_t* len, const uint8_t* encryption_key);
    static bool secure_save_file(const char* filename, const uint8_t* data, size_t len, const uint8_t* encryption_key);
    static bool secure_load_file(const char* filename, uint8_t* data, size_t* len, const uint8_t* encryption_key);
    
    // Maintenance
    static bool defragment_storage();
    static bool verify_storage_integrity();
    static bool backup_storage();
    static bool restore_storage();
    
    // Statistics
    static const storage_stats_t& get_stats();
    static void reset_stats();
    static void print_stats();
    
    // Utilities
    static void list_all_keys();
    static void list_all_files();
    static bool clear_all_data();
};

// ESP32 LittleFS + NVS Backend
#ifdef PLATFORM_ESP32
class ESP32StorageBackend : public IStorageBackend {
private:
    bool nvs_initialized;
    bool littlefs_initialized;
    
    // NVS for key-value storage
    StorageResult nvs_save_key(const char* key_name, const uint8_t* data, size_t len);
    StorageResult nvs_load_key(const char* key_name, uint8_t* data, size_t* len);
    StorageResult nvs_delete_key(const char* key_name);
    
    // LittleFS for file storage
    StorageResult littlefs_save_file(const char* filename, const uint8_t* data, size_t len);
    StorageResult littlefs_load_file(const char* filename, uint8_t* data, size_t* len);
    StorageResult littlefs_delete_file(const char* filename);
    
public:
    StorageResult init() override;
    StorageResult shutdown() override;
    StorageResult format() override;
    bool is_available() override;
    
    StorageResult save_key(const char* key_name, const uint8_t* data, size_t len) override;
    StorageResult load_key(const char* key_name, uint8_t* data, size_t* len) override;
    StorageResult delete_key(const char* key_name) override;
    bool key_exists(const char* key_name) override;
    
    StorageResult save_file(const char* filename, const uint8_t* data, size_t len) override;
    StorageResult load_file(const char* filename, uint8_t* data, size_t* len) override;
    StorageResult delete_file(const char* filename) override;
    StorageResult append_file(const char* filename, const uint8_t* data, size_t len) override;
    bool file_exists(const char* filename) override;
    size_t get_file_size(const char* filename) override;
    
    StorageResult secure_save(const char* name, const uint8_t* data, size_t len, const uint8_t* key) override;
    StorageResult secure_load(const char* name, uint8_t* data, size_t* len, const uint8_t* key) override;
    
    StorageResult defragment() override;
    StorageResult verify_integrity() override;
    StorageResult get_stats(storage_stats_t* stats) override;
    
    const char* get_backend_name() override { return "ESP32 (LittleFS + NVS)"; }
    uint32_t get_total_capacity() override { return 1024 * 1024; } // 1MB typical
    bool supports_encryption() override { return true; }
    bool is_volatile() override { return false; }
};
#endif

// STM32 EEPROM + SD Card Backend
#ifdef PLATFORM_STM32
class STM32StorageBackend : public IStorageBackend {
private:
    bool eeprom_initialized;
    bool sdcard_initialized;
    
    // EEPROM for key-value storage (small, fast)
    StorageResult eeprom_save_key(const char* key_name, const uint8_t* data, size_t len);
    StorageResult eeprom_load_key(const char* key_name, uint8_t* data, size_t* len);
    StorageResult eeprom_delete_key(const char* key_name);
    
    // SD Card for file storage (large, persistent)
    StorageResult sd_save_file(const char* filename, const uint8_t* data, size_t len);
    StorageResult sd_load_file(const char* filename, uint8_t* data, size_t* len);
    StorageResult sd_delete_file(const char* filename);
    
    // Software encryption
    bool software_encrypt(const uint8_t* input, uint8_t* output, size_t len, const uint8_t* key);
    bool software_decrypt(const uint8_t* input, uint8_t* output, size_t len, const uint8_t* key);
    
public:
    StorageResult init() override;
    StorageResult shutdown() override;
    StorageResult format() override;
    bool is_available() override;
    
    StorageResult save_key(const char* key_name, const uint8_t* data, size_t len) override;
    StorageResult load_key(const char* key_name, uint8_t* data, size_t* len) override;
    StorageResult delete_key(const char* key_name) override;
    bool key_exists(const char* key_name) override;
    
    StorageResult save_file(const char* filename, const uint8_t* data, size_t len) override;
    StorageResult load_file(const char* filename, uint8_t* data, size_t* len) override;
    StorageResult delete_file(const char* filename) override;
    StorageResult append_file(const char* filename, const uint8_t* data, size_t len) override;
    bool file_exists(const char* filename) override;
    size_t get_file_size(const char* filename) override;
    
    StorageResult secure_save(const char* name, const uint8_t* data, size_t len, const uint8_t* key) override;
    StorageResult secure_load(const char* name, uint8_t* data, size_t* len, const uint8_t* key) override;
    
    StorageResult defragment() override;
    StorageResult verify_integrity() override;
    StorageResult get_stats(storage_stats_t* stats) override;
    
    const char* get_backend_name() override { return "STM32 (EEPROM + SD)"; }
    uint32_t get_total_capacity() override { return 32 * 1024 * 1024; } // 32MB SD card
    bool supports_encryption() override { return false; }
    bool is_volatile() override { return false; }
};
#endif

// PC File System Backend
#ifdef PLATFORM_PC
class PCStorageBackend : public IStorageBackend {
private:
    std::string storage_directory;
    
    // File system operations
    std::string get_key_path(const char* key_name);
    std::string get_file_path(const char* filename);
    
public:
    PCStorageBackend(const std::string& directory = "./pqc_storage");
    
    StorageResult init() override;
    StorageResult shutdown() override;
    StorageResult format() override;
    bool is_available() override;
    
    StorageResult save_key(const char* key_name, const uint8_t* data, size_t len) override;
    StorageResult load_key(const char* key_name, uint8_t* data, size_t* len) override;
    StorageResult delete_key(const char* key_name) override;
    bool key_exists(const char* key_name) override;
    
    StorageResult save_file(const char* filename, const uint8_t* data, size_t len) override;
    StorageResult load_file(const char* filename, uint8_t* data, size_t* len) override;
    StorageResult delete_file(const char* filename) override;
    StorageResult append_file(const char* filename, const uint8_t* data, size_t len) override;
    bool file_exists(const char* filename) override;
    size_t get_file_size(const char* filename) override;
    
    StorageResult secure_save(const char* name, const uint8_t* data, size_t len, const uint8_t* key) override;
    StorageResult secure_load(const char* name, uint8_t* data, size_t* len, const uint8_t* key) override;
    
    StorageResult defragment() override;
    StorageResult verify_integrity() override;
    StorageResult get_stats(storage_stats_t* stats) override;
    
    const char* get_backend_name() override { return "PC File System"; }
    uint32_t get_total_capacity() override { return 1024 * 1024 * 1024; } // 1GB
    bool supports_encryption() override { return false; }
    bool is_volatile() override { return false; }
};
#endif

// Factory function
IStorageBackend* create_storage_backend();

} // namespace Storage
} // namespace PQC

#endif
