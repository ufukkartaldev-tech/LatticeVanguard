#include "../include/health.h"
#include "../include/pqc_config.h"
#include <string.h>
#include "../include/csprng.h"

#ifdef ARDUINO
#include <Arduino.h>
#include <cmath> // log2 için
#include "esp_flash_encrypt.h"
#include "esp_secure_boot.h"
#include "esp_efuse.h"
#include "esp_efuse_table.h"

namespace PQC {
namespace System {

void HealthMonitor::report_state(const char* operation_name, uint32_t duration_us) {
    size_t free_ram = ESP.getFreeHeap();
    size_t min_ever_ram = ESP.getMinFreeHeap();
    #ifndef PQC_SILENT_MODE
    Serial.println("\n--- [HEALTH MONITOR] ---");
    Serial.print("Operasyon: "); Serial.println(operation_name);
    Serial.print("Sure     : "); Serial.print(duration_us); Serial.println(" us");
    Serial.print("RAM Bos  : "); Serial.print(free_ram / 1024.0); Serial.println(" KB");
    Serial.print("RAM Min  : "); Serial.print(min_ever_ram / 1024.0); Serial.println(" KB (Sistem Stresi)");
    Serial.print("CPU Freq : "); Serial.print(getCpuFrequencyMhz()); Serial.println(" MHz");
    Serial.println("------------------------");
    #endif
}

size_t HealthMonitor::get_free_ram() {
    return ESP.getFreeHeap();
}

size_t HealthMonitor::get_min_free_ram() {
    return ESP.getMinFreeHeap();
}

void HealthMonitor::print_performance_table() {
    // RAM tasarrufu için raporlama devredışı bırakıldı.
}

// Shannon Entropisi: Rastgelelik Kalite Testi (Gümüshane Usulü Zar Kontrolü)
float HealthMonitor::check_rng_entropy() {
    uint8_t buffer[128]; // 1024 bit örneklem
    PQC::System::CSPRNG::randombytes(buffer, 128);
    
    float entropy = calculate_shannon_entropy(buffer, 128);
    // Maksimum entropi 8.0 bit/byte'dır. 0.0-1.0 arasına normalize ederken 8'e bölüyoruz.
    return (entropy / 8.0f); 
}

float HealthMonitor::calculate_shannon_entropy(const uint8_t* data, size_t len) {
    uint32_t freq[256] = {0};
    for(size_t i=0; i<len; i++) freq[data[i]]++;
    
    float ent = 0;
    for(int i=0; i<256; i++) {
        if (freq[i] > 0) {
            float p = (float)freq[i] / (float)len;
            ent -= p * log2f(p);
        }
    }
    return ent;
}

bool HealthMonitor::is_flash_encrypted() {
    #ifdef ARDUINO
    return esp_flash_encryption_enabled();
    #else
    return false;
    #endif
}

bool HealthMonitor::is_secure_boot_active() {
    #ifdef ARDUINO
    return esp_secure_boot_enabled();
    #else
    return false;
    #endif
}

} // namespace System
} // namespace PQC

#else
// PC Mock Implementation
namespace PQC {
namespace System {
void HealthMonitor::report_state(const char* n, uint32_t d) { printf("[PC HEALTH] %s: %u us\n", n, d); }
size_t HealthMonitor::get_free_ram() { return 0; }
size_t HealthMonitor::get_min_free_ram() { return 0; }
bool HealthMonitor::is_hardware_salt_active() { return false; }
void HealthMonitor::print_performance_table() { printf("[PC] System report only available on ESP32 hardware.\n"); }
}
}
#endif
