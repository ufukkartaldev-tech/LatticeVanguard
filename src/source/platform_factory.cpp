#include "../include/platform.h"
#include "../include/workspace_unified.h"
#include "../include/network_abstract.h"
#include "../include/storage_abstract.h"

/*
  PLATFORM FACTORY IMPLEMENTATION
  -------------------------------
  Cross-platform initialization and factory functions
*/

namespace PQC {
namespace Platform {

// Global platform instances
IPlatform* Platform = nullptr;
IMemoryManager* Memory = nullptr;
INetworkInterface* Network = nullptr;
IStorageInterface* Storage = nullptr;
ILogInterface* Logger = nullptr;

// Platform Factory Implementation
IPlatform* PlatformFactory::create_platform() {
#ifdef PLATFORM_ESP32
    return new ESP32Platform();
#elif defined(PLATFORM_STM32)
    return new STM32Platform();
#elif defined(PLATFORM_PC)
    return new PCPlatform();
#else
    #error "Unsupported platform"
    return nullptr;
#endif
}

IMemoryManager* PlatformFactory::create_memory_manager() {
#ifdef PLATFORM_ESP32
    return new ESP32MemoryManager();
#elif defined(PLATFORM_STM32)
    return new STM32MemoryManager();
#elif defined(PLATFORM_PC)
    return new PCMemoryManager();
#else
    return nullptr;
#endif
}

INetworkInterface* PlatformFactory::create_network_interface() {
#ifdef PLATFORM_ESP32
    return new ESP32NetworkInterface();
#elif defined(PLATFORM_STM32)
    return new STM32NetworkInterface();
#elif defined(PLATFORM_PC)
    return new PCNetworkInterface();
#else
    return nullptr;
#endif
}

IStorageInterface* PlatformFactory::create_storage_interface() {
#ifdef PLATFORM_ESP32
    return new ESP32StorageInterface();
#elif defined(PLATFORM_STM32)
    return new STM32StorageInterface();
#elif defined(PLATFORM_PC)
    return new PCStorageInterface();
#else
    return nullptr;
#endif
}

ILogInterface* PlatformFactory::create_log_interface() {
#ifdef PLATFORM_ESP32
    return new ESP32LogInterface();
#elif defined(PLATFORM_STM32)
    return new STM32LogInterface();
#elif defined(PLATFORM_PC)
    return new PCLogInterface();
#else
    return nullptr;
#endif
}

// Platform Initialization
bool initialize_platform() {
    // Create platform instances
    Platform = PlatformFactory::create_platform();
    if (!Platform) return false;
    
    Memory = PlatformFactory::create_memory_manager();
    Network = PlatformFactory::create_network_interface();
    Storage = PlatformFactory::create_storage_interface();
    Logger = PlatformFactory::create_log_interface();
    
    // Initialize all subsystems
    if (!Platform->init()) return false;
    if (!Memory->init()) return false;
    if (!Network->init()) return false;
    if (!Storage->init()) return false;
    if (!Logger->init()) return false;
    
    // Initialize unified workspace
    if (!Memory::UnifiedWorkspace::allocate()) {
        return false;
    }
    
    return true;
}

void shutdown_platform() {
    // Cleanup in reverse order
    if (Logger) {
        Logger->log_error("SYSTEM_SHUTDOWN", 0, 0);
        delete Logger;
        Logger = nullptr;
    }
    
    if (Storage) {
        delete Storage;
        Storage = nullptr;
    }
    
    if (Network) {
        delete Network;
        Network = nullptr;
    }
    
    if (Memory) {
        Memory::UnifiedWorkspace::deallocate();
        delete Memory;
        Memory = nullptr;
    }
    
    if (Platform) {
        delete Platform;
        Platform = nullptr;
    }
}

// Utility Functions
const char* get_platform_name() {
#ifdef PLATFORM_ESP32
    return "ESP32-WROOM-32";
#elif defined(PLATFORM_STM32)
    return "STM32F103C8T6";
#elif defined(PLATFORM_PC)
    return "PC Simulation";
#else
    return "Unknown";
#endif
}

bool is_esp32_platform() {
#ifdef PLATFORM_ESP32
    return true;
#else
    return false;
#endif
}

bool is_stm32_platform() {
#ifdef PLATFORM_STM32
    return true;
#else
    return false;
#endif
}

bool is_pc_platform() {
#ifdef PLATFORM_PC
    return true;
#else
    return false;
#endif
}

} // namespace Platform
} // namespace PQC
