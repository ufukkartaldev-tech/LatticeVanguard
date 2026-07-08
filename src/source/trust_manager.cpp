#include "../include/trust_manager.h"
#include "../include/dilithium.h"
#include "../include/network.h"
#include "../include/storage.h"
#include <string.h>

#ifdef ARDUINO
#include <Arduino.h>
#else
#include "../include/pc_compat.h"
#endif

namespace PQC {
namespace Security {

bool TrustManager::admin_mode = false;

void TrustManager::set_admin_mode(bool enable) {
    admin_mode = enable;
}

bool TrustManager::is_admin() {
    return admin_mode;
}

void TrustManager::request_admission(const uint8_t* admin_mac) {
    #ifndef PQC_SILENT_MODE
    Serial.println("TRUST: Admin'den ag katilim sertifikasi isteniyor...");
    #endif
    
    // Kendi PK'mızı ve MAC'imizi gönderen bir paket hazırla
    uint8_t my_pk[1312];
    if (PQC::System::KeyVault::load_key("K_DILI_PK", my_pk, 1312)) {
        // MSG_HANDSHAKE_REQ gönderimi (Implementation logic in network task)
        // Şimdilik sadece logluyoruz, network task bu tipe göre özel davranacak.
    }
}

bool TrustManager::issue_certificate(uint8_t* cert_out, const uint8_t* device_mac, const uint8_t* device_pk, const uint8_t* admin_sk) {
    uint8_t auth_payload[6 + 1312];
    memcpy(auth_payload, device_mac, 6);
    memcpy(auth_payload + 6, device_pk, 1312);
    
    size_t sig_len = 0;
    // Admin, cihazın MAC ve PK birleşimini imzalar.
    int res = PQC::DSA::Dilithium2::sign(nullptr, cert_out, &sig_len, auth_payload, sizeof(auth_payload), admin_sk);
    return (res == 0);
}

bool TrustManager::verify_certificate(const uint8_t* cert, const uint8_t* device_mac, const uint8_t* device_pk, const uint8_t* admin_pk) {
    uint8_t auth_payload[6 + 1312];
    memcpy(auth_payload, device_mac, 6);
    memcpy(auth_payload + 6, device_pk, 1312);
    
    // Sertifika (imza) doğrulaması
    int res = PQC::DSA::Dilithium2::verify(nullptr, cert, 2420, auth_payload, sizeof(auth_payload), admin_pk);
    return (res == 0);
}

} // namespace Security
} // namespace PQC
