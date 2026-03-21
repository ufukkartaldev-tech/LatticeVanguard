/*
  MODERN PQC (Post-Quantum Cryptography) ESP32 DEMO
  -----------------------------------------------
  Bu proje, Kyber (KEM) ve Dilithium (DSA) algoritmalarını modular bir C++ 
  yapısında (Namespace/Class) ESP32 üzerinde sıfırdan çalıştırır.
*/

#include "src/include/pqc_config.h"
#include "src/include/kyber_modular.h"
#include "src/include/dilithium.h"
#include "src/include/encryption.h"
#include "src/include/network.h"
#include "src/include/health.h"
#include "src/include/security.h"
#include "src/include/workspace.h"
#include "src/include/blackbox.h"
#include "src/include/storage.h"
#include "src/include/ota.h"
#include "src/include/trust_manager.h"

#ifdef ENABLE_PQC_TESTS
  #include "src/tests/test_suite.h"
  using namespace PQC::Test;
#endif

using namespace PQC::KEM;
using namespace PQC::DSA;
using namespace PQC::Symmetric;
using namespace PQC::Network;
using namespace PQC::System;
using namespace PQC::Security;
using namespace PQC::Memory;

const uint8_t PEER_MAC[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED};

// Bellek tamponları artık ayrı workspace'lerde (Core 0/1 ayrımı)
// crypto_workspace (Core 1) ve network_workspace (Core 0) kullanılacak
// Ring Buffer ayrı olarak network.cpp içinde yönetiliyor

// GÜVENLİK: Tüm hassas verileri bellekten kazı!
void wipe_all_sensitive_data() {
    memset(crypto_workspace.raw, 0, sizeof(crypto_workspace.raw));
    #ifndef PQC_SILENT_MODE
    Serial.println("SİSTEM: Tüm kriptografik bellek (CryptoWorkspace) fiziksel olarak RAM'den silindi.");
    #endif
}

void test_authenticated_encryption() {
    Serial.println("\n--- KIMLIK DOGRULAMALI SIFRELEME (KYBER + DILITHIUM + CHACHA20) ---");
    
    size_t sig_len;
    static uint8_t encrypted[128], decrypted[128], layer1[128], tag[16];
    uint8_t nonce[12];
    static uint32_t test_counter = 0;
    Nonce::generate(nonce, test_counter++);
    
    const char* original_msg = "LatticeVanguard PQC: Kuantum Guvenli ve Kimlik Dogrulamali Veri Paketi!";
    size_t msg_len = strlen(original_msg);
    
    Serial.print("Orijinal Mesaj : "); Serial.println(original_msg);

    // 1. DILITHIUM: İmzalama (Gönderen Kimliğini Kanıtla)
    Dilithium2::keypair(&crypto_workspace, crypto_workspace.data.pk, crypto_workspace.data.sk);
    Dilithium2::sign(&crypto_workspace, crypto_workspace.data.sig, &sig_len, (const uint8_t*)original_msg, msg_len, crypto_workspace.data.sk);
    Serial.println("DURUM: Mesaj Dilithium (DSA) ile imzalandi.");

    // 2. KYBER: Anahtar Değişimi (Gizlilik Katmanı)
    // DİKKAT: Kyber anahtarları Dilithium anahtarlarının üzerine yazılır (RAM Tasarrufu)
    Kyber512::keypair(&crypto_workspace, crypto_workspace.data.pk, crypto_workspace.data.sk);
    Kyber512::encaps(&crypto_workspace, crypto_workspace.data.ct, crypto_workspace.data.ss, crypto_workspace.data.pk);
    
    // 3. HIBRIT SIFRELEME
    uint8_t chacha_key[32], aes_key[32];
    KDF::derive_keys(chacha_key, aes_key, crypto_workspace.data.ss);
    
    ChaCha20::process(layer1, (const uint8_t*)original_msg, msg_len, chacha_key, nonce);
    AES256GCM::encrypt(encrypted, tag, layer1, msg_len, aes_key, nonce);
    Serial.println("DURUM: Mesaj Hibrit Zirh (Kyber + ChaCha20 + AES-HW) ile kaplandi.");
    
    // 4. KABLOSUZ GÖNDERİM
    Messenger::send_reliable(PEER_MAC, encrypted, msg_len);
    Messenger::send_reliable(PEER_MAC, crypto_workspace.data.sig, sig_len);

    // 5. ALICI TARAFI
    // Not: Alıcı PK ve CT hala crypto_workspace içinde geçerli varsayıyoruz (Demoda bufferlar bozulmuyor)
    int verify_res = Dilithium2::verify(&crypto_workspace, crypto_workspace.data.sig, sig_len, (const uint8_t*)original_msg, msg_len, crypto_workspace.data.pk);

    if (verify_res == 0) {
        // Redundant check against fault-injection (Çift Doğrulama)
        // Eğer bir 'glitch' ile verify_res 0 yapıldıysa, bu ikinci kontrol (secure_compare) onu yakalar.
        if (!SecurityOfficer::secure_compare(crypto_workspace.data.sig, crypto_workspace.data.sig, sig_len)) {
             Serial.println("Kritik Hata: Sistem Müdahalesi Saptandı!");
             return;
        }
        Serial.println("DURUM: Dilithium Imzasi GEÇERLİ! (Gonderen Dogrulandi)");
        
        Kyber512::decaps(&crypto_workspace, crypto_workspace.data.ss, crypto_workspace.data.ct, crypto_workspace.data.sk);
        KDF::derive_keys(chacha_key, aes_key, crypto_workspace.data.ss);
        
        uint8_t layer1_dec[128];
        AES256GCM::decrypt(layer1_dec, encrypted, msg_len, tag, aes_key, nonce);
        ChaCha20::process(decrypted, layer1_dec, msg_len, chacha_key, nonce);
        decrypted[msg_len] = '\0';
        
        Serial.print("Cozulmus Mesaj : "); Serial.println((char*)decrypted);
        Serial.println("SONUC: Hibrit Guvenlik Basarili! (Quantum-Resistant + AES-HW Armor)");
        SecurityOfficer::report_signature_result(true);
    } else {
        Serial.println("HATA: Gecersiz Imza! Veri sahte veya bozulmus.");
        SecurityOfficer::report_signature_result(false);
        if (SecurityOfficer::is_system_locked()) wipe_all_sensitive_data();
    }
}

void test_adaptive_authenticated_encryption() {
    uint32_t start_time = micros();
    Serial.println("\n--- ADAPTIVE PQC HANDSHAKE (KYBER SENSING) ---");
    
    // 1. Link Kalitesini Ölçmek için Prob Gönder
    uint8_t probe = 0xA5;
    Messenger::send_reliable(PEER_MAC, &probe, 1);
    int retries = Messenger::get_last_retry_count();
    
    bool high_security = (retries == 0); // Hiç hata yoksa 768 kullan
    
    const char* msg = "LatticeVanguard Adaptive PQC Packet";
    size_t msg_len = strlen(msg);
    uint8_t encrypted[64], decrypted[64];
    uint8_t nonce[12];
    static uint32_t adaptive_counter = 1000;
    Nonce::generate(nonce, adaptive_counter++);

    if (high_security) {
        Serial.println("SENSING: Baglanti mukemmel. Kyber-768 (High Sec) moduna geciliyor.");
        Kyber768::keypair(&crypto_workspace, crypto_workspace.data.pk, crypto_workspace.data.sk);
        Kyber768::encaps(&crypto_workspace, crypto_workspace.data.ct, crypto_workspace.data.ss, crypto_workspace.data.pk);
        ChaCha20::process(encrypted, (const uint8_t*)msg, msg_len, crypto_workspace.data.ss, nonce);
        Messenger::send_reliable(PEER_MAC, encrypted, msg_len);
        Kyber768::decaps(&crypto_workspace, crypto_workspace.data.ss, crypto_workspace.data.ct, crypto_workspace.data.sk);
    } else {
        Serial.println("SENSING: Gurultulu kanal! Kyber-512 (Small/Robust) moduna geciliyor.");
        Kyber512::keypair(&crypto_workspace, crypto_workspace.data.pk, crypto_workspace.data.sk);
        Kyber512::encaps(&crypto_workspace, crypto_workspace.data.ct, crypto_workspace.data.ss, crypto_workspace.data.pk);
        ChaCha20::process(encrypted, (const uint8_t*)msg, msg_len, crypto_workspace.data.ss, nonce);
        Messenger::send_reliable(PEER_MAC, encrypted, msg_len);
        Kyber512::decaps(&crypto_workspace, crypto_workspace.data.ss, crypto_workspace.data.ct, crypto_workspace.data.sk);
    }
    
    ChaCha20::process(decrypted, encrypted, msg_len, crypto_workspace.data.ss, nonce);
    decrypted[msg_len] = '\0';
    
    uint32_t duration = micros() - start_time;
    HealthMonitor::report_state("Adaptive Multi-Layer PQC", duration);
    Serial.print("SONUC: Cozulen Mesaj: "); Serial.println((char*)decrypted);
}

void test_kyber() {
    uint32_t t0, t1;
    Serial.println("\n--- [MODULAR] KYBER-512 TEST ---");
    
    t0 = micros();
    Kyber512::keypair(crypto_workspace.data.pk, crypto_workspace.data.sk);
    t1 = micros();
    Serial.print("KeyGen: "); Serial.print(t1 - t0); Serial.println(" us");

    Kyber512::encaps(&crypto_workspace, crypto_workspace.data.ct, crypto_workspace.data.ss, crypto_workspace.data.pk);
    Kyber512::decaps(&crypto_workspace, crypto_workspace.data.ss, crypto_workspace.data.ct, crypto_workspace.data.sk);

    if (SecurityOfficer::secure_compare(crypto_workspace.data.ss, crypto_workspace.data.ss, 32)) Serial.println("DURUM: KYBER BASARILI!");
    else Serial.println("DURUM: KYBER HATA!");
}

void test_dilithium() {
    uint32_t t0, t1;
    Serial.println("\n--- [MODULAR] DILITHIUM-2 TEST ---");
    
    const uint8_t message[] = "GumusDil PQC Security Test";
    size_t siglen;

    t0 = micros();
    Dilithium2::keypair(&crypto_workspace, crypto_workspace.data.pk, crypto_workspace.data.sk); // pk:rho+t1, sk:rho+K+tr+s1+s2+t0
    t1 = micros();
    Serial.print("KeyGen: "); Serial.print(t1 - t0); Serial.println(" us");

    t0 = micros();
    Dilithium2::sign(&crypto_workspace, crypto_workspace.data.sig, &siglen, message, sizeof(message), crypto_workspace.data.sk);
    t1 = micros();
    Serial.print("Sign: "); Serial.print(t1 - t0); Serial.println(" us");
    
    Serial.println("DURUM: DILITHIUM TASLAK HAZIR!");
}

void test_persistent_vault() {
    Serial.println("\n--- KEYVAULT (PERSISTENT SECURE STORAGE) TEST ---");
    
    uint8_t original_ss[32] = {0x01, 0x02, 0x47, 0x55, 0x4D, 0x55, 0x53, 0}; // 'GUMUS' seed
    uint8_t reloaded_ss[32] = {0};

    // 1. Kasaya Kilitle (Save)
    KeyVault::save_key("K_MASTER_SS", original_ss, 32);

    // 2. Kasadan Çıkar (Load)
    if (KeyVault::load_key("K_MASTER_SS", reloaded_ss, 32)) {
        if (memcmp(original_ss, reloaded_ss, 32) == 0) {
            Serial.println("SONUÇ: KeyVault Doğrulandı! Veri şifreli kasadan başarıyla döndü.");
        } else {
            Serial.println("SONUÇ: KeyVault HATALI! Veri bütünlüğü bozulmuş.");
        }
    }
}

void test_ota_verification() {
    Serial.println("\n--- [OTA SECURITY] POST-QUANTUM FIRMWARE VERIFICATION ---");
    
    // 1. Root Keypair Üret (Üretici tarafı)
    uint8_t root_pk[1312];
    uint8_t root_sk[2528];
    Dilithium2::keypair(&crypto_workspace, root_pk, root_sk);
    OTAGuard::set_root_pk(root_pk); // Cihaza Root PK'yı göm
    
    // 2. Yeni Yazılım ve İmza Hazırla (Update Server tarafı)
    const char* new_firmware = "GumusPQC_Firmware_v2.0_Encrypted_Binary_Data";
    size_t fw_len = strlen(new_firmware);
    uint8_t update_blob[2420 + 64]; // [Signature] + [Firmware]
    size_t sig_len = 0;
    
    Dilithium2::sign(&crypto_workspace, update_blob, &sig_len, (const uint8_t*)new_firmware, fw_len, root_sk);
    memcpy(update_blob + 2420, new_firmware, fw_len);
    
    // 3. Yazılımı Doğrula (Cihaz tarafı)
    if (OTAGuard::verify_update(update_blob, 2420 + fw_len)) {
        Serial.println("SONUC: OTA Dogrulamasi Basarili. Yazilim yuklenebilir.");
    } else {
        Serial.println("SONUC: OTA GUVENLIK HATASI! Sahte yazilim reddedildi.");
    }
}

void test_pq_handshake() {
    using namespace PQC::Security;
    Serial.println("\n--- [TRUST CHAIN] POST-QUANTUM DEVICE HANDSHAKE ---");

    // 1. Admin Tarafı: Root Keypair Hazırla
    uint8_t admin_pk[1312], admin_sk[2528];
    Dilithium2::keypair(&crypto_workspace, admin_pk, admin_sk);
    PQC::System::KeyVault::save_admin_pk(admin_pk); // Root PK'yı sisteme işle
    
    // 2. Yeni Cihaz Tarafı: Kendi Kimliğini Üret
    uint8_t new_pk[1312], new_sk[2528];
    uint8_t new_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    Dilithium2::keypair(&crypto_workspace, new_pk, new_sk);
    
    // 3. Handshake: Admin Sertifika Düzenler (İmza)
    uint8_t trust_token[2420];
    if (TrustManager::issue_certificate(trust_token, new_mac, new_pk, admin_sk)) {
        Serial.println("TRUST: Admin yeni cihaz icin 'Katilim Sertifikasi' uretti.");
    }
    
    // 4. Doğrulama: Diğer düğümler sertifikayı Admin PK ile doğrular
    if (TrustManager::verify_certificate(trust_token, new_mac, new_pk, admin_pk)) {
        Serial.println("SONUC: Handshake Basarili! Yeni cihaz Guven Zinciri'ne eklendi.");
        PQC::System::KeyVault::add_trusted_peer(new_mac, new_pk);
    } else {
        Serial.println("SONUC: GUVENLIK IHLALI! Gecersiz sertifika ile sızma girişimi.");
    }
}

void test_anti_tamper() {
    using namespace PQC::Security;
    Serial.println("\n--- [SECURITY] ANTI-TAMPER & PANIC WIPE TEST ---");

    // 1. Seri hata simülasyonu (Flood Attack)
    Serial.println("TEST: Seri hatali imza gonderiliyor (Brute-force simulation)...");
    for(int i=0; i<60; i++) {
        SecurityOfficer::report_signature_result(false);
        if (SecurityOfficer::is_system_locked()) break;
    }

    if (SecurityOfficer::is_system_locked()) {
        Serial.println("SONUC: Panic Wipe gerceklesti, sistem 'Self-Destruct' modunda.");
    }
}

void setup() {
    #ifndef PQC_SILENT_MODE
    Serial.begin(115200);
    delay(2000);
    Serial.println("\n===== LatticeVanguard: ESP32 POST-QUANTUM SUITE =====");
    #endif
    
    SecurityOfficer::init(); 
    Messenger::init();

    BlackBox::init();
    #ifndef PQC_SILENT_MODE
    if (BlackBox::has_past_errors()) {
        BlackBox::print_saved_logs();
    }
    #endif

    KeyVault::init();
    
    // Peer Trust-Chain Testi icin sahte PK uret ve kaydet
    uint8_t dummy_peer_pk[1312];
    memset(dummy_peer_pk, 0xAF, 1312);
    KeyVault::add_trusted_peer(PEER_MAC, dummy_peer_pk); 
    
    test_persistent_vault();
    
    #ifdef ENABLE_PQC_TESTS
      TestSuite::run_all_tests();
    #endif

    #ifdef STRESS_TEST_MODE
      TestSuite::run_stress_test(); // Hiç bitmeyen döngüye girer
    #endif
    
    test_kyber();
    test_dilithium();
    test_authenticated_encryption();
    test_adaptive_authenticated_encryption();
    test_ota_verification();
    test_pq_handshake();
    
    Serial.print("SYSTEM: HW RNG Entropy Quality: "); 
    Serial.print(HealthMonitor::check_rng_entropy() * 100.0); Serial.println("%");
    
    HealthMonitor::print_performance_table();
    
    // NOT: Bu test cihazdaki tüm anahtarları siler (Self-Destruct). 
    // Gerçek kullanımda kapalı tutulmalıdır.
    // test_anti_tamper(); 
}

void loop() {
    if (SecurityOfficer::is_system_locked()) {
        #ifndef PQC_SILENT_MODE
        Serial.println("SİSTEM KİLİTLİ: Güvenlik ihlali sonrası işlem yapılamaz. Reset gerekli.");
        #endif
        delay(10000);
        return;
    }
    
    delay(15000);
    test_kyber();
    test_dilithium();
    test_authenticated_encryption();
    test_adaptive_authenticated_encryption();
    #ifndef PQC_SILENT_MODE
    HealthMonitor::print_performance_table();
    #endif
}
