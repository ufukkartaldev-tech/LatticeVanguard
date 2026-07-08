#include "../include/security.h"
#include "../include/health.h"
#include "../include/storage.h"
#include "../include/blackbox.h"
#include <string.h>

#ifdef ARDUINO
#include <Arduino.h>
#else
#include "../include/pc_compat.h"
#endif

namespace PQC {
namespace Security {

volatile int SecurityOfficer::failed_attempts = 0;
volatile uint32_t SecurityOfficer::last_fail_time = 0;
volatile bool SecurityOfficer::system_locked_1 = false;
volatile uint32_t SecurityOfficer::system_locked_2 = 0;

void SecurityOfficer::init() {
    failed_attempts = 0;
    last_fail_time = 0;
    system_locked_1 = false;
    system_locked_2 = 0;
}

void SecurityOfficer::check_entropy_lock() {
    using PQC::System::HealthMonitor;
    float quality = HealthMonitor::check_rng_entropy();
    
    // Esik deger: %75 (%100 normalize uzerinden 0.75)
    if (quality < 0.75f) {
        #if defined(ARDUINO) && !defined(PQC_SILENT_MODE)
        Serial.print("!!! KRITIK GUVENLIK ACIGI: RNG Entropisi cok dusuk: %");
        Serial.println(quality * 100.0);
        #endif
        panic_wipe();
    }
}

void SecurityOfficer::report_signature_result(bool success) {
    if (success) {
        if (failed_attempts > 0) failed_attempts--;
    } else {
        failed_attempts++;
        uint32_t now = millis();
        
        // Kara Kutuya kaydet
        PQC::System::BlackBox::log_security_incident("SIGNATURE_FAILURE");

        if (now - last_fail_time < 30000) {
           if (failed_attempts > 50) {
               PQC::System::BlackBox::log_security_incident("FLOOD_ATTACK_DETECTED");
               panic_wipe();
               return;
           }
        } else {
           failed_attempts /= 2;
        }
        last_fail_time = now;

        if (failed_attempts >= 100) {
            panic_wipe();
        }
    }
}

void SecurityOfficer::panic_wipe() {
    system_locked_1 = true;
    system_locked_2 = LOCK_MAGIC_VAL;
    
    // Kara Kutuya 'Self-Destruct' emaresi birak
    PQC::System::BlackBox::log_security_incident("PANIC_WIPE_TRIGGERED");

    #if defined(ARDUINO) && !defined(PQC_SILENT_MODE)
    Serial.println("\n#############################################");
    Serial.println("# !!! PANIK MODU: GUVENLIK IHLALI TESPITI !!! #");
    Serial.println("# Tüm Anahtarlar NVS Bellekten Siliniyor!     #");
    Serial.println("###############################################");
    #endif

    // Fiziksel İmha (KeyVault Wipe)
    PQC::System::KeyVault::destroy_vault();
}

bool SecurityOfficer::is_system_locked() {
    // Redundant Check: İki kontrol de geçmeli (Fault Injection Koruması)
    return (system_locked_1 == true) || (system_locked_2 == LOCK_MAGIC_VAL);
}

// Constant-Time Comparison (Timing Attack Koruması)
bool SecurityOfficer::verify_const_time(const uint8_t* a, const uint8_t* b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (a[i] ^ b[i]);
    }
    return (diff == 0);
}

// Fault Injection / Glitch Koruması
bool SecurityOfficer::secure_compare(const uint8_t* a, const uint8_t* b, size_t len) {
    bool res1 = verify_const_time(a, b, len);
    
    volatile int dummy = 0;
    for(int i=0; i<10; i++) dummy++;

    bool res2 = verify_const_time(a, b, len);

    if (res1 != res2) {
        #if defined(ARDUINO) && !defined(PQC_SILENT_MODE)
        Serial.println("!!! GUVENLIK IHLALI: Hata Verdirme (Fault Injection) Algilandi !!!");
        #endif
        panic_wipe();
        return false;
    }

    return res1;
}

} // namespace Security
} // namespace PQC
