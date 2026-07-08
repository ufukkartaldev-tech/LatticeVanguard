#include "../include/ota.h"
#include "../include/dilithium.h"
#include "../include/security.h"
#include "../include/fips202.h"
#include <string.h>

#ifdef ARDUINO
#include <Arduino.h>
#else
#include "../include/pc_compat.h"
#endif

namespace PQC {
namespace System {

uint8_t OTAGuard::root_public_key[1312];
bool OTAGuard::pk_set = false;

static keccak_state ota_hash_state;
static uint8_t active_signature[2420];
static bool verification_active = false;

void OTAGuard::set_root_pk(const uint8_t* pk) {
    memcpy(root_public_key, pk, 1312);
    pk_set = true;
}

bool OTAGuard::begin_streaming_verification(const uint8_t* signature) {
    if (!pk_set) return false;
    memcpy(active_signature, signature, 2420);
    shake256_init(&ota_hash_state);
    verification_active = true;
    return true;
}

void OTAGuard::process_firmware_chunk(const uint8_t* chunk, size_t len) {
    if (verification_active && chunk && len > 0) {
        shake256_absorb(&ota_hash_state, chunk, len);
    }
}

bool OTAGuard::complete_streaming_verification() {
    if (!verification_active) return false;
    verification_active = false;
    
    uint8_t fw_hash[32];
    shake256_squeeze(fw_hash, 32, &ota_hash_state);

    #ifndef PQC_SILENT_MODE
    Serial.println("OTA: Guncelleme paketi Dilithium (DSA) ile [Streaming] dogrulaniyor...");
    #endif

    // Dilithium doğrulaması - Mesajın kendisi yerine 32 byte'lik SHAKE-256 hash'ini doğruluyoruz.
    int res = PQC::DSA::Dilithium2::verify(NULL, active_signature, 2420, fw_hash, 32, root_public_key);

    if (res == 0) {
        #ifndef PQC_SILENT_MODE
        Serial.println("OTA SUCCESS: Guncelleme imzasi gecerli. Yazilim orijinaldir.");
        #endif
        return true;
    } else {
        #ifndef PQC_SILENT_MODE
        Serial.println("!!! OTA SECURITY ALERT: GECERSIZ IMZA! Sahte guncelleme paketi tespit edildi.");
        #endif
        Security::SecurityOfficer::report_signature_result(false);
        return false;
    }
}

bool OTAGuard::verify_update(const uint8_t* update_data, size_t total_len) {
    if (!pk_set) {
        #ifndef PQC_SILENT_MODE
        Serial.println("OTA ERROR: Root Public Key not set! Cannot verify.");
        #endif
        return false;
    }

    if (total_len <= 2420) return false; // Sadece imza veya boş veri
    
    const uint8_t* signature = update_data;
    const uint8_t* firmware = update_data + 2420;
    size_t firmware_len = total_len - 2420;

    if (!begin_streaming_verification(signature)) return false;
    process_firmware_chunk(firmware, firmware_len);
    return complete_streaming_verification();
}

} // namespace System
} // namespace PQC
