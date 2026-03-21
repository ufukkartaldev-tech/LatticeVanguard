#ifndef ARDUINO
#include <stdio.h>
#define esp_random() rand()
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

    update_epoch_key(header->msg_id / 1000);

    // Hardware Nonce Hybrid logic
    PQC::Symmetric::Nonce::generate(out->iv, header->msg_id);

    uint8_t* plain = network_workspace.encryption_buffer; 
    size_t header_len = sizeof(packet_header_t);
    memcpy(plain, header, header_len);
    if (payload && payload_len > 0) {
        memcpy(plain + header_len, payload, payload_len);
    }

    // AES-256-GCM Encryption
    PQC::Symmetric::AES256GCM::encrypt(out->data, out->auth_tag, plain, header_len + payload_len, current_epoch_key, out->iv);
}

bool NetworkPrivacy::unwrap(packet_header_t* header, uint8_t* payload, const fragment_packet_t* in) {
    if (!key_set) return false;

    uint8_t* plain = network_workspace.encryption_buffer; 
    // Not: Alıcı tarafta epochID'yi bilmiyoruz, şimdilik current_epoch_key kullanıyoruz.
    // Gerçekte header içinden bir ipucu çıkarılabilir veya deneme yapılabilir.
    int res = PQC::Symmetric::AES256GCM::decrypt(plain, in->data, 190, in->auth_tag, current_epoch_key, in->iv);
    
    if (res != 0) return false;

    memcpy(header, plain, sizeof(packet_header_t));
    if (header->payload_len > 0) {
        memcpy(payload, plain + sizeof(packet_header_t), header->payload_len);
    }
    return true;
}

} // namespace Network
} // namespace PQC
