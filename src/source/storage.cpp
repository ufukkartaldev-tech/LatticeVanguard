#include "../include/storage.h"
#include "../include/encryption.h"
#include "../include/fips202.h"
#include "../include/security.h"
#include "../include/csprng.h"
#include <string.h>

#ifdef ARDUINO
#include <Arduino.h>
#include <nvs_flash.h>
#include <nvs.h>
#include "esp_system.h"
#include "esp_mac.h"
#include "esp_random.h"
#include "esp_efuse.h"
#include "esp_efuse_table.h"

namespace PQC {
namespace System {

uint8_t KeyVault::master_vault_key[32];

bool KeyVault::init() {
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }

    Security::SecurityOfficer::check_entropy_lock();
    generate_master_key(); // Cihazin kimligini ve gizli tuzu kullanarak kasanin anahtarini uret.
    
    return (err == ESP_OK);
}

void KeyVault::generate_master_key() {
    uint8_t mac[6];
    uint8_t secret_salt[32];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);

    // LatticeVanguard Solution: Salt value read from eFuse (Hardware) instead of NVS (Flash).
    // eFuse dışarıdan okunamaz hale getirilebilir, böylece Flash Dump anahtarı ele veremez.
    bool hardware_secure = false;
    #ifdef ARDUINO
    esp_efuse_read_field_blob(ESP_EFUSE_USER_DATA, secret_salt, 256);
    
    // eFuse boş mu kontrol et (Geliştirme aşaması için NVS fallback)
    uint32_t check = 0;
    for(int i=0; i<32; i++) check |= secret_salt[i];
    if (check != 0) hardware_secure = true;
    #endif

    if (!hardware_secure) {
        nvs_handle_t nvs_handle;
        if (nvs_open("pqc_sys", NVS_READWRITE, &nvs_handle) == ESP_OK) {
            size_t salt_len = 32;
            if (nvs_get_blob(nvs_handle, "vault_salt", secret_salt, &salt_len) != ESP_OK) {
                PQC::System::CSPRNG::randombytes(secret_salt, 32);
                nvs_set_blob(nvs_handle, "vault_salt", secret_salt, 32);
                nvs_commit(nvs_handle);
            }
            nvs_close(nvs_handle);
        } else {
            memset(secret_salt, 0xA5, 32);
        }
    }
    
    // MASTER KEY DERIVATION: MAC + Secret Salt 
    // SHA3-256 kullanarak MAC ve Salt'ı birbirine karıştır (Brute-force'u zorlaştır)
    uint8_t input_material[38];
    memcpy(input_material, mac, 6);
    memcpy(input_material + 6, secret_salt, 32);
    
    sha3_256(master_vault_key, input_material, 38);
}

bool KeyVault::save_key(const char* key_name, const uint8_t* key_data, size_t len) {
    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open("pqc_vault", NVS_READWRITE, &nvs_handle);
    if (err != ESP_OK) return false;

    // 1. Şifreleme (Encryption)
    // Şifreli veri yapısı: [IV (12)] | [TAG (16)] | [CIPHERTEXT (len)]
    uint8_t iv[12];
    PQC::System::CSPRNG::randombytes(iv, 12);

    uint8_t tag[16];
    uint8_t* encrypted_blob = (uint8_t*)malloc(len + 12 + 16);
    if (!encrypted_blob) { nvs_close(nvs_handle); return false; }

    memcpy(encrypted_blob, iv, 12);
    
    // AES-256-GCM ile anahtarı şifrele (Hibrit Güvenlik: PQC anahtarını klasik AES ile sakla)
    PQC::Symmetric::AES256GCM::encrypt(encrypted_blob + 28, tag, key_data, len, master_vault_key, iv);
    memcpy(encrypted_blob + 12, tag, 16);

    // 2. NVS'e Kayıt (Blobu kaydet)
    err = nvs_set_blob(nvs_handle, key_name, encrypted_blob, len + 28);
    if (err == ESP_OK) err = nvs_commit(nvs_handle);

    free(encrypted_blob);
    nvs_close(nvs_handle);
    
    #ifndef PQC_SILENT_MODE
    if (err == ESP_OK) Serial.printf("KEYVAULT: '%s' başarıyla şifrelendi ve gömme kasaya (NVS) kilitlendi.\n", key_name);
    #endif
    return (err == ESP_OK);
}

bool KeyVault::load_key(const char* key_name, uint8_t* out_data, size_t len) {
    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open("pqc_vault", NVS_READONLY, &nvs_handle);
    if (err != ESP_OK) return false;

    size_t blob_len = len + 28;
    uint8_t* encrypted_blob = (uint8_t*)malloc(blob_len);
    if (!encrypted_blob) { nvs_close(nvs_handle); return false; }

    err = nvs_get_blob(nvs_handle, key_name, encrypted_blob, &blob_len);
    if (err == ESP_OK) {
        uint8_t iv[12], tag[16];
        memcpy(iv, encrypted_blob, 12);
        memcpy(tag, encrypted_blob + 12, 16);
        
        // Deşifreleme (Decryption)
        int decrypt_res = PQC::Symmetric::AES256GCM::decrypt(out_data, encrypted_blob + 28, len, tag, master_vault_key, iv);
        
        if (decrypt_res != 0) {
            #ifndef PQC_SILENT_MODE
            Serial.println("KASA HATASI: Anahtar deşifre edilemedi! Doğruluk (Integrity) hatası.");
            #endif
            err = ESP_FAIL;
        }
    }

    free(encrypted_blob);
    nvs_close(nvs_handle);
    return (err == ESP_OK);
}

void KeyVault::get_master_key_for_log(uint8_t out[32]) {
    memcpy(out, master_vault_key, 32);
}

bool KeyVault::destroy_vault() {
    nvs_handle_t h;
    
    // 1. Ana Kasa (Gizli Anahtarlar)
    if (nvs_open("pqc_vault", NVS_READWRITE, &h) == ESP_OK) {
        nvs_erase_all(h); nvs_commit(h); nvs_close(h);
    }
    
    // 2. Peer Kamu Anahtarları
    if (nvs_open("pqc_peers", NVS_READWRITE, &h) == ESP_OK) {
        nvs_erase_all(h); nvs_commit(h); nvs_close(h);
    }

    // 3. Sistem Ayarları ve Admin Root PK
    if (nvs_open("pqc_sys", NVS_READWRITE, &h) == ESP_OK) {
        nvs_erase_all(h); nvs_commit(h); nvs_close(h);
    }

    #ifndef PQC_SILENT_MODE
    Serial.println("KASA: Tüm ağ ve anahtar verileri saniyeler içinde imha edildi (Panic Wipe).");
    #endif
    return true;
}

bool KeyVault::save_config_uint32(const char* name, uint32_t value) {
    nvs_handle_t h;
    if (nvs_open("pqc_sys", NVS_READWRITE, &h) != ESP_OK) return false;
    nvs_set_u32(h, name, value);
    nvs_commit(h);
    nvs_close(h);
    return true;
}

bool KeyVault::load_config_uint32(const char* name, uint32_t* value) {
    nvs_handle_t h;
    if (nvs_open("pqc_sys", NVS_READONLY, &h) != ESP_OK) return false;
    esp_err_t err = nvs_get_u32(h, name, value);
    nvs_close(h);
    return (err == ESP_OK);
}

bool KeyVault::is_peer_trusted(const uint8_t* mac) {
    nvs_handle_t nvs_handle;
    if (nvs_open("pqc_peers", NVS_READONLY, &nvs_handle) == ESP_OK) {
        char mac_str[13];
        sprintf(mac_str, "%02X%02X%02X%02X%02X%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        size_t required_len = 0;
        esp_err_t err = nvs_get_blob(nvs_handle, mac_str, NULL, &required_len);
        nvs_close(nvs_handle);
        return (err == ESP_OK && required_len > 0);
    }
    return false;
}

bool KeyVault::get_peer_public_key(const uint8_t* mac, uint8_t* pk_out) {
    nvs_handle_t h;
    if (nvs_open("pqc_peers", NVS_READONLY, &h) != ESP_OK) return false;
    
    char key[13];
    snprintf(key, 13, "%02X%02X%02X%02X%02X%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    
    size_t pk_len = 1312;
    esp_err_t err = nvs_get_blob(h, key, pk_out, &pk_len);
    nvs_close(h);
    return (err == ESP_OK);
}

bool KeyVault::save_admin_pk(const uint8_t* pk) {
    nvs_handle_t h;
    if (nvs_open("pqc_sys", NVS_READWRITE, &h) != ESP_OK) return false;
    nvs_set_blob(h, "admin_pk", pk, 1312);
    nvs_commit(h);
    nvs_close(h);
    return true;
}

bool KeyVault::get_admin_pk(uint8_t* pk_out) {
    nvs_handle_t h;
    if (nvs_open("pqc_sys", NVS_READONLY, &h) != ESP_OK) return false;
    size_t len = 1312;
    esp_err_t err = nvs_get_blob(h, "admin_pk", pk_out, &len);
    nvs_close(h);
    return (err == ESP_OK);
}
void KeyVault::add_trusted_peer(const uint8_t* mac, const uint8_t* public_key) {
    nvs_handle_t nvs_handle;
    if (nvs_open("pqc_peers", NVS_READWRITE, &nvs_handle) == ESP_OK) {
        char mac_str[13];
        sprintf(mac_str, "%02X%02X%02X%02X%02X%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        nvs_set_blob(nvs_handle, mac_str, public_key, 1312);
        nvs_commit(nvs_handle);
        nvs_close(nvs_handle);
    }
}

} // namespace System
} // namespace PQC

#else
// PC Mock Implementation
namespace PQC {
namespace System {
uint8_t KeyVault::master_vault_key[32];
bool KeyVault::init() { return true; }
bool KeyVault::save_key(const char* n, const uint8_t* d, size_t l) { printf("[STORAGE MOCK] Key saved: %s\n", n); return true; }
bool KeyVault::load_key(const char* n, uint8_t* o, size_t l) { printf("[STORAGE MOCK] Key loaded: %s\n", n); return true; }
bool KeyVault::destroy_vault() { return true; }
void KeyVault::generate_master_key() {}
}
}
#endif
