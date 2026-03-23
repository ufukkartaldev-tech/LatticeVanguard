#ifndef ARDUINO
#include <stdio.h>
#endif

#include "../include/network_privacy.h"
#include "../include/encryption.h"
#include "../include/fips202.h"
#include "../include/workspace.h"
#include <string.h>

#ifdef ARDUINO
#include <Arduino.h>
#endif

namespace PQC {
namespace Network {

using namespace PQC::Memory;

uint8_t NetworkPrivacy::network_master_key[32];
uint8_t NetworkPrivacy::current_epoch_key[32];
uint32_t NetworkPrivacy::last_epoch_id = 0xFFFFFFFF;
bool NetworkPrivacy::key_set = false;

void NetworkPrivacy::set_network_master_key(const uint8_t key[32]) {
    memcpy(network_master_key, key, 32);
    update_epoch_key(0);
    key_set = true;
}

void NetworkPrivacy::update_epoch_key(uint32_t epoch_id) {
    if (epoch_id == last_epoch_id) return;
    uint8_t input[36];
    memcpy(input, network_master_key, 32);
    memcpy(input + 32, &epoch_id, 4);
    sha3_256(current_epoch_key, input, 36);
    last_epoch_id = epoch_id;
}

void NetworkPrivacy::wrap(fragment_packet_t* out, const packet_header_t* header, const uint8_t* payload, size_t payload_len) {
    if (!key_set) return;

    // Her şeyi önce sıfırlayalım, veri sızıntılarını ve auth_tag check sorunlarını çözer
    memset(out, 0, sizeof(fragment_packet_t));

    // AAD olarak header'ı düz metin formunda Struct'a aktar.
    memcpy(&out->header, header, sizeof(packet_header_t));

    update_epoch_key(header->msg_id / 1000);

    // Hardware Nonce Hybrid logic
    PQC::Symmetric::Nonce::generate(out->iv, header->msg_id);

    uint8_t* plain_payload = network_workspace.encryption_buffer; 
    if (payload && payload_len > 0) {
        memcpy(plain_payload, payload, payload_len);
    }

    // AES-256-GCM Şifreleme (Sadece payload) ve AAD olarak header
    PQC::Symmetric::AES256GCM::encrypt(
        out->payload, 
        out->auth_tag, 
        plain_payload, 
        payload_len, 
        current_epoch_key, 
        out->iv, 
        (const uint8_t*)&out->header, /* AAD */
        sizeof(packet_header_t)      /* AAD len */
    );
}

bool NetworkPrivacy::unwrap(packet_header_t* header, uint8_t* payload, const fragment_packet_t* in) {
    if (!key_set) return false;

    // Header artık şifresiz geldiği için doğrudan okuyabiliriz: Tavuk-Yumurta çözümü!
    update_epoch_key(in->header.msg_id / 1000);

    uint8_t* plain_payload = network_workspace.encryption_buffer; 
    size_t payload_len = in->header.payload_len;

    if (payload_len > 176) {
        return false;
    }

    // AES şifre çözücü - payload kadarını çözeceğiz, header'ı da AAD olarak doğrulayacağız.
    int res = PQC::Symmetric::AES256GCM::decrypt(
        plain_payload, 
        in->payload, 
        payload_len, 
        in->auth_tag, 
        current_epoch_key, 
        in->iv, 
        (const uint8_t*)&in->header, /* AAD */
        sizeof(packet_header_t)      /* AAD len */
    );
    
    if (res != 0) return false;

    // Bütünlük başarılıysa verileri dışarı aktar
    memcpy(header, &in->header, sizeof(packet_header_t));
    if (payload_len > 0) {
        memcpy(payload, plain_payload, payload_len);
    }
    return true;
}

} // namespace Network
} // namespace PQC
