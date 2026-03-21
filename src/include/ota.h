#ifndef PQC_OTA_H
#define PQC_OTA_H

#include <stdint.h>
#include <stddef.h>

namespace PQC {
namespace System {

/**
 * OTAGuard (LatticeVanguard OTA Protection)
 * Uzaktan güncellemeleri Dilithium ile doğrular.
 * Bu sayede sahte yazılım yüklenmesi (Firmware Hijacking) imkansız hale gelir.
 */
class OTAGuard {
public:
    // Streaming OTA Validation API
    static bool begin_streaming_verification(const uint8_t* signature);
    static void process_firmware_chunk(const uint8_t* chunk, size_t len);
    static bool complete_streaming_verification();
    
    // Legacy support
    static bool verify_update(const uint8_t* update_data, size_t total_len);

    // Root Kamu Anahtarını hazırla (Genellikle üretimde bir kez gömülür)
    static void set_root_pk(const uint8_t* pk);

private:
    static uint8_t root_public_key[1312];
    static bool pk_set;
};

} // namespace System
} // namespace PQC

#endif
