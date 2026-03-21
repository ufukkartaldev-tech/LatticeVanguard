#include "../include/network_privacy.h"
#include "../include/encryption.h"
#include "../include/fips202.h"
#include <string.h>

#ifdef ARDUINO
#include <Arduino.h>
#endif

namespace PQC {
namespace Network {

uint8_t NetworkPrivacy::network_master_key[32];
uint8_t NetworkPrivacy::current_epoch_key[32];
uint32_t NetworkPrivacy::last_epoch_id = 0xFFFFFFFF;
bool NetworkPrivacy::key_set = false;

void NetworkPrivacy::set_network_master_key(const uint8_t key[32]) {
    memcpy(network_master_key, key, 32);
    // İlk anahtarı üret (Epoch 0)
    update_epoch_key(0);
    key_set = true;
}

void NetworkPrivacy::update_epoch_key(uint32_t epoch_id) {
    if (epoch_id == last_epoch_id) return;

    // LatticeVanguard Solution: Moving Target Defense (Key Rotation)
    // EpochID geliştikçe yeni anahtar = SHA3(MasterKey | EpochID)
    uint8_t input[36];
    memcpy(input, network_master_key, 32);
    memcpy(input + 32, &epoch_id, 4);
    
    sha3_256(current_epoch_key, input, 36);
    last_epoch_id = epoch_id;

    #if defined(ARDUINO) && !defined(PQC_SILENT_MODE)
    Serial.print("STEALTH: Anahtar rotasyonu yapildi. Yeni Epoch: "); 
    Serial.println(epoch_id);
    #endif
}

void NetworkPrivacy::wrap(fragment_packet_t* out, const packet_header_t* header, const uint8_t* payload, size_t payload_len) {
    if (!key_set) return;

    // Göndermeden önce epoch kontrolü (global_msg_id'ye göre)
    update_epoch_key(header->msg_id / 1000); // Her 1000 mesajda bir anahtar değişir

    #ifdef ARDUINO
    for(int i=0; i<12; i++) out->iv[i] = (uint8_t)esp_random();
    #else
    for(int i=0; i<12; i++) out->iv[i] = (uint8_t)rand();
    #endif

    uint8_t plain[sizeof(packet_header_t) + 210]; 
    size_t header_len = sizeof(packet_header_t);
    memcpy(plain, header, header_len);
    if (payload && payload_len > 0) {
        memcpy(plain + header_len, payload, payload_len);
    }

    PQC::Symmetric::AES256GCM::encrypt(out->data, out->auth_tag, plain, header_len + payload_len, current_epoch_key, out->iv);
}

bool NetworkPrivacy::unwrap(packet_header_t* header, uint8_t* payload, const fragment_packet_t* in) {
    if (!key_set) return false;

    // Not: Alıcı tarafta epochID'yi bilmiyoruz (çünkü header şifreli).
    // Basitleştirmek için alıcı tarafın epoch'u beklenen msg_id üzerinden tahmin ettiğini varsayalım.
    uint8_t plain[250];
    int res = PQC::Symmetric::AES256GCM::decrypt(plain, in->data, 222, in->auth_tag, current_epoch_key, in->iv);
    
    if (res != 0) return false;

    memcpy(header, plain, sizeof(packet_header_t));
    if (header->payload_len > 0) {
        memcpy(payload, plain + sizeof(packet_header_t), header->payload_len);
    }
    return true;
}

} // namespace Network
} // namespace PQC
