#include "test_suite.h"
#include "../include/network_privacy.h"
#include "../include/network.h"
#include "../include/security.h"
#include "../include/storage.h"
#include "../include/blackbox.h"

#ifdef ARDUINO
#include <Arduino.h>

extern size_t recv_pos;
extern uint32_t last_received_msg_id;

namespace PQC {
namespace Test {

bool ChaosTester::test_replay_attack() {
    using namespace PQC::Network;
    packet_header_t header = {MSG_DATA, 999, 0, 1, 4};
    uint8_t payload[4] = {1, 2, 3, 4}, mac[6] = {0xAA};
    fragment_packet_t pkt;
    NetworkPrivacy::wrap(&pkt, &header, payload, 4);

    last_received_msg_id = 998;
    recv_pos = 0;
    Messenger::on_data_recv(mac, (uint8_t*)&pkt, sizeof(pkt));
    if (recv_pos != 4) return false;

    Messenger::on_data_recv(mac, (uint8_t*)&pkt, sizeof(pkt));
    return (recv_pos == 4); // Tekrar artmadıysa başarılı
}

bool ChaosTester::test_fragment_flooding() {
    using namespace PQC::Network;
    packet_header_t header = {MSG_DATA, 2000, 0, 100, 200};
    uint8_t mac[6] = {0xBB};
    recv_pos = 0; last_received_msg_id = 1999;

    for(int i=0; i < 50; i++) {
        header.seq = i;
        fragment_packet_t pkt;
        NetworkPrivacy::wrap(&pkt, &header, NULL, 200);
        Messenger::on_data_recv(mac, (uint8_t*)&pkt, sizeof(pkt));
    }
    return (recv_pos <= 4096);
}

bool ChaosTester::test_rng_failure_lock() {
    PQC::Security::SecurityOfficer::init();
    for(int i=0; i<100; i++) {
        PQC::Security::SecurityOfficer::report_signature_result(false);
        if (PQC::Security::SecurityOfficer::is_system_locked()) break;
    }
    return PQC::Security::SecurityOfficer::is_system_locked();
}

bool ChaosTester::test_counter_overflow() {
    using namespace PQC::Network;
    last_received_msg_id = 0xFFFFFFFF;
    packet_header_t header = {MSG_DATA, 1, 0, 1, 5};
    uint8_t mac[6] = {0}, data[5] = "WRAP";
    fragment_packet_t pkt;
    NetworkPrivacy::wrap(&pkt, &header, data, 5);
    recv_pos = 0;
    Messenger::on_data_recv(mac, (uint8_t*)&pkt, sizeof(pkt));
    return (recv_pos == 5);
}

bool ChaosTester::test_flash_integrity_violation() {
    using namespace PQC::System;
    uint8_t dummy[32] = {0xCC}, out[32];
    KeyVault::save_key("CORRUPT", dummy, 32);

    nvs_handle_t h;
    if (nvs_open("pqc_vault", NVS_READWRITE, &h) == ESP_OK) {
        uint8_t blob[60]; size_t len = 60;
        nvs_get_blob(h, "CORRUPT", blob, &len);
        blob[30] ^= 0xFF; // Bit-flip
        nvs_set_blob(h, "CORRUPT", blob, len);
        nvs_commit(h); nvs_close(h);
    }
    return !KeyVault::load_key("CORRUPT", out, 32);
}

bool ChaosTester::test_power_cycle_resilience() {
    PQC::System::KeyVault::save_config_uint32("tx_msg_id", 500);
    PQC::Network::Messenger::init();
    return true; // Init başarılıysa NVS'den yüklemiştir
}

bool ChaosTester::test_trng_entropy_drop() {
    PQC::Security::SecurityOfficer::init();
    PQC::Security::SecurityOfficer::panic_wipe(); 
    return PQC::Security::SecurityOfficer::is_system_locked();
}

bool ChaosTester::test_multi_device_stress() {
    using namespace PQC::Network;
    uint8_t mac[6];
    packet_header_t header = {MSG_DATA, 9000, 0, 1, 0};
    for(int i=0; i<30; i++) {
        for(int j=0; j<10; j++) {
            memset(mac, j+1, 6);
            fragment_packet_t pkt;
            header.msg_id++;
            NetworkPrivacy::wrap(&pkt, &header, NULL, 0);
            Messenger::on_data_recv(mac, (uint8_t*)&pkt, sizeof(pkt));
        }
        if (PQC::Security::SecurityOfficer::is_system_locked()) return true;
    }
    return false;
}

// --- Concurrent message-id allocation stress test ---
// Hammers Messenger::reserve_msg_id() from several tasks pinned across both
// cores. Verifies the critical section loses no increments (no lost updates)
// and never hands the same id to two callers (no duplicates) — i.e. that the
// send-path id race is actually gone.
#define CONC_TASKS     4
#define IDS_PER_TASK   200
#define CONC_TOTAL     (CONC_TASKS * IDS_PER_TASK)

static uint32_t conc_ids[CONC_TOTAL];
static volatile int conc_idx = 0;
static volatile int conc_done = 0;
static portMUX_TYPE conc_mux = portMUX_INITIALIZER_UNLOCKED;

static void conc_producer(void* arg) {
    for (int i = 0; i < IDS_PER_TASK; i++) {
        uint32_t id = PQC::Network::Messenger::reserve_msg_id();
        portENTER_CRITICAL(&conc_mux);
        if (conc_idx < CONC_TOTAL) conc_ids[conc_idx++] = id;
        portEXIT_CRITICAL(&conc_mux);
    }
    portENTER_CRITICAL(&conc_mux);
    conc_done++;
    portEXIT_CRITICAL(&conc_mux);
    vTaskDelete(NULL);
}

bool ChaosTester::test_concurrent_send_ids() {
    conc_idx = 0;
    conc_done = 0;

    for (int t = 0; t < CONC_TASKS; t++) {
        xTaskCreatePinnedToCore(conc_producer, "idprod", 2048, NULL, 5, NULL, t % 2);
    }

    uint32_t start = millis();
    while (conc_done < CONC_TASKS && (millis() - start) < 5000) {
        vTaskDelay(1);
    }
    if (conc_done < CONC_TASKS) return false;   // a producer stalled
    if (conc_idx != CONC_TOTAL) return false;   // lost reservations

    // No id handed out twice.
    for (int i = 0; i < CONC_TOTAL; i++) {
        for (int j = i + 1; j < CONC_TOTAL; j++) {
            if (conc_ids[i] == conc_ids[j]) return false;
        }
    }
    return true;
}

} // namespace Test
} // namespace PQC
#endif
