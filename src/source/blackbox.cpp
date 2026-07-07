#include "../include/blackbox.h"
#include <string.h>
#include <stdio.h>

#ifdef ARDUINO
#include <Arduino.h>
#include <FS.h>
#include "../include/encryption.h"
#include "../include/storage.h"
#include "../include/csprng.h"

namespace PQC {
namespace System {

const char* BlackBox::LOG_PATH = "/GumusLog.bin"; // Uzantiyi bin yaptik

bool BlackBox::init() {
    if (!LittleFS.begin(true)) {
        #ifndef PQC_SILENT_MODE
        Serial.println("BLACKBOX ERROR: LittleFS initialization failed!");
        #endif
        return false;
    }
    return true;
}

void BlackBox::log_security_incident(const char* type, const uint8_t* mac) {
    char plain[128];
    if (mac) {
        snprintf(plain, sizeof(plain), "[SECURITY] %s | Attacker: %02X:%02X:%02X:%02X:%02X:%02X", 
                 type, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    } else {
        snprintf(plain, sizeof(plain), "[SECURITY] %s | Unknown Source", type);
    }

    uint8_t iv[12];
    PQC::System::CSPRNG::randombytes(iv, 12);
    uint8_t tag[16], cipher[128], master[32];
    size_t len = strlen(plain);

    // Kasa anahtarını al (Sadece yetkili Admin çözebilir)
    KeyVault::get_master_key_for_log(master); 
    PQC::Symmetric::AES256GCM::encrypt(cipher, tag, (const uint8_t*)plain, len, master, iv);

    File log = LittleFS.open(LOG_PATH, FILE_APPEND);
    if (log) {
        log.write(iv, 12);
        log.write(tag, 16);
        log.write((uint8_t*)&len, sizeof(size_t));
        log.write(cipher, len);
        log.close();
    }
}

void BlackBox::log_error(const char* operation, uint32_t iteration, size_t leak_amount) {
    char plain_text[128];
    snprintf(plain_text, sizeof(plain_text), "[FATAL] Op:%s | It:%u | Leak:%zu", operation, iteration, leak_amount);
    
    uint8_t iv[12];
    PQC::System::CSPRNG::randombytes(iv, 12);
    uint8_t tag[16], cipher[128], master[32];
    size_t plain_len = strlen(plain_text);
    
    KeyVault::get_master_key_for_log(master);
    PQC::Symmetric::AES256GCM::encrypt(cipher, tag, (const uint8_t*)plain_text, plain_len, master, iv);

    File log = LittleFS.open(LOG_PATH, FILE_APPEND);
    if (log) {
        log.write(iv, 12);
        log.write(tag, 16);
        log.write((uint8_t*)&plain_len, sizeof(size_t));
        log.write(cipher, plain_len);
        log.close();
    }
}

void BlackBox::print_saved_logs() {
    if (!LittleFS.exists(LOG_PATH)) return;

    #ifndef PQC_SILENT_MODE
    Serial.println("\n===== BLACKBOX (KARA KUTU) SIFRELI KAYITLAR =====");
    File log = LittleFS.open(LOG_PATH, FILE_READ);
    if (log) {
        while (log.available()) {
            uint8_t iv[12], tag[16], cipher[128], plain[128];
            size_t plain_len;
            log.read(iv, 12);
            log.read(tag, 16);
            log.read((uint8_t*)&plain_len, sizeof(size_t));
            log.read(cipher, plain_len);
            
            uint8_t master[32];
            KeyVault::get_master_key_for_log(master);
            if (PQC::Symmetric::AES256GCM::decrypt(plain, cipher, plain_len, tag, master, iv) == 0) {
                plain[plain_len] = '\0';
                Serial.println((char*)plain);
            }
        }
        log.close();
    }
    Serial.println("==============================================");
    #endif
}

void BlackBox::clear_logs() {
    if (LittleFS.remove(LOG_PATH)) {
        Serial.println("BLACKBOX: Persistent logs cleared.");
    }
}

bool BlackBox::has_past_errors() {
    return LittleFS.exists(LOG_PATH);
}

} // namespace System
} // namespace PQC

#else
// PC Mock Implementation
namespace PQC {
namespace System {
const char* BlackBox::LOG_PATH = "";
bool BlackBox::init() { return true; }
void BlackBox::log_security_incident(const char* type, const uint8_t* mac) { (void)mac; printf("[BLACKBOX MOCK] Security incident: %s\n", type); }
void BlackBox::log_error(const char* op, uint32_t it, size_t l) { printf("[BLACKBOX MOCK] Error: %s at %u leak %zu\n", op, it, l); }
void BlackBox::print_saved_logs() { printf("[BLACKBOX MOCK] No hardware logs on PC.\n"); }
void BlackBox::clear_logs() {}
bool BlackBox::has_past_errors() { return false; }
}
}
#endif
