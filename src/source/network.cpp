#include "../include/network_privacy.h"
#include "../include/security.h"
#include "../include/encryption.h"
#include "../include/fips202.h"
#include "../include/blackbox.h"
#include <string.h>

#ifdef ARDUINO
#include <Arduino.h>
#include "esp_log.h"

namespace PQC {
namespace Network {

using namespace PQC::Memory;
using namespace PQC::Security;

// --- GÜVENLİK KATI: Modül Seviyesinde İzole Değişkenler ---
static ring_buffer_t network_ring_buffer = {0};
static SemaphoreHandle_t ring_buffer_mutex = NULL;
static SemaphoreHandle_t hmac_mutex = NULL;
static portMUX_TYPE ring_buffer_spinlock = portMUX_INITIALIZER_UNLOCKED;
static QueueHandle_t network_queue = NULL;

static peer_record_t peer_registry[MAX_PEERS];
static blacklist_t blacklist[MAX_PEERS];
static uint32_t global_msg_id = 1000;
static volatile bool messenger_busy = false;
static volatile bool last_send_ok = false;
static volatile bool ack_received = false;

static uint8_t LOCAL_MAC[6];
static uint8_t HMAC_SECRET[32] = {0x41, 0x47, 0x5F, 0x46, 0x49, 0x52, 0x45, 0x57, 0x41, 0x4C, 0x4C, 0x5F, 0x4B, 0x45, 0x59, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

struct network_msg_t {
    uint8_t target_mac[6];
    uint8_t final_mac[6];
    uint8_t data[4096];
    size_t len;
};

// Task Prototypes
void network_task(void* pvParameters);
void crypto_task(void* pvParameters);

// --- Public API ---

bool Messenger::init() {
    WiFi.mode(WIFI_STA);
    esp_read_mac(LOCAL_MAC, ESP_MAC_WIFI_STA);

    if (esp_now_init() != ESP_OK) return false;
    
    esp_now_register_recv_cb(Messenger::on_data_recv);
    esp_now_register_send_cb(Messenger::on_data_sent);

    ring_buffer_mutex = xSemaphoreCreateMutex();
    hmac_mutex = xSemaphoreCreateMutex();
    memset(peer_registry, 0, sizeof(peer_registry));
    memset(blacklist, 0, sizeof(blacklist));

    using PQC::System::KeyVault;
    KeyVault::load_config_uint32("tx_msg_id", &global_msg_id);

    network_queue = xQueueCreate(2, sizeof(network_msg_t));
    xTaskCreatePinnedToCore(network_task, "NetTask", 4096, NULL, 5, NULL, 0); 
    xTaskCreatePinnedToCore(crypto_task, "CryptoTask", 4096, NULL, 4, NULL, 1);
    
    return true;
}

void Messenger::on_data_sent(const uint8_t* mac, esp_now_send_status_t status) {
    last_send_ok = (status == ESP_NOW_SEND_SUCCESS);
}

bool Messenger::compute_hmac(uint8_t* out, const uint8_t* hmac_input, size_t len, const uint8_t* key) {
    if (xSemaphoreTake(hmac_mutex, 10 / portTICK_PERIOD_MS) != pdTRUE) {
        ESP_LOGE("PQC_NETWORK", "HMAC Mutex alinmadi, islem iptal!");
        return false;
    }

    // SİBER SAVUNMA: HMAC-SHA3-256 Firewall
    // Bu işlem, paketi PQC işlemlerine sokmadan önce 'kapıdaki güvenlik' olarak çalışır. 
    // İmza uymuyorsa paket anında CPU'ya yük bindirmeden drop edilir. (DoS Koruması)
    uint8_t ipad[64], opad[64], inner_hash[32];
    for (int i = 0; i < 64; i++) {
        uint8_t k = (i < 32) ? key[i] : 0;
        ipad[i] = k ^ 0x36;
        opad[i] = k ^ 0x5C;
    }
    
    uint8_t* blob = network_workspace.temp_buffer; // Isolated Workspace logic
    memcpy(blob, ipad, 64);
    memcpy(blob + 64, hmac_input, len);
    sha3_256(inner_hash, blob, len + 64);
    
    memcpy(blob, opad, 64);
    memcpy(blob + 64, inner_hash, 32);
    sha3_256(out, blob, 64 + 32);

    xSemaphoreGive(hmac_mutex);
    return true;
}

bool Messenger::is_blacklisted(const uint8_t* mac) {
    for (int i = 0; i < MAX_PEERS; i++) {
        if (memcmp(blacklist[i].mac, mac, 6) == 0) {
            if (millis() < blacklist[i].expiry) return true;
            memset(&blacklist[i], 0, sizeof(blacklist_t));
            return false;
        }
    }
    return false;
}

void Messenger::handle_blacklist(const uint8_t* mac, bool success) {
    if (success) {
        for (int i = 0; i < MAX_PEERS; i++) {
            if (memcmp(blacklist[i].mac, mac, 6) == 0) { blacklist[i].failures = 0; return; }
        }
    } else {
        // ADAPTIVE RATE LIMITING: 3 hata yapan MAC'e 60 saniye engel.
        // Brute-force ve DoS saldırganlarını CPU'yu yormadan sistemden dışlar.
        for (int i = 0; i < MAX_PEERS; i++) {
            if (memcmp(blacklist[i].mac, mac, 6) == 0 || (blacklist[i].expiry == 0 && blacklist[i].failures == 0)) {
                memcpy(blacklist[i].mac, mac, 6);
                blacklist[i].failures++;
                if (blacklist[i].failures >= 3) {
                    blacklist[i].expiry = millis() + 60000;
                    PQC::System::BlackBox::log_security_incident("MAC_BLACKLISTED", mac);
                }
                return;
            }
        }
    }
}

bool Messenger::check_replay(const uint8_t* mac, uint32_t msg_id) {
    // SLIDING WINDOW ANTI-REPLAY: Her peer için msg_id takibi.
    peer_record_t* peer = NULL;
    for (int i = 0; i < MAX_PEERS; i++) {
        if (memcmp(peer_registry[i].mac, mac, 6) == 0) { peer = &peer_registry[i]; break; }
    }

    if (!peer) {
        for (int i = 0; i < MAX_PEERS; i++) {
            if (peer_registry[i].last_seen == 0) {
                peer = &peer_registry[i];
                memcpy(peer->mac, mac, 6);
                peer->last_msg_id = msg_id;
                peer->window = 1;
                peer->last_seen = millis();
                return true;
            }
        }
        return true; 
    }

    peer->last_seen = millis();
    if (msg_id > peer->last_msg_id) {
        uint32_t diff = msg_id - peer->last_msg_id;
        if (diff < WINDOW_SIZE) peer->window = (peer->window << diff) | 1;
        else peer->window = 1;
        peer->last_msg_id = msg_id;
        return true;
    } else {
        uint32_t diff = peer->last_msg_id - msg_id;
        if (diff >= WINDOW_SIZE) return false;
        if (peer->window & (1ULL << diff)) return false; 
        peer->window |= (1ULL << diff);
        return true;
    }
}

void Messenger::on_data_recv(const uint8_t* mac, const uint8_t* incomingData, int len) {
    if (len < (int)sizeof(fragment_packet_t)) return;
    if (is_blacklisted(mac)) return;

    fragment_packet_t* pkt = (fragment_packet_t*)incomingData;
    
    // 2. CRYPTOGRAPHIC FIREWALL (HMAC Check)
    uint8_t calculated_hmac[32];
    uint8_t hmac_source[12 + 190];
    memcpy(hmac_source, pkt->iv, 12);
    memcpy(hmac_source + 12, pkt->data, 190);
    if (!compute_hmac(calculated_hmac, hmac_source, 12 + 190, HMAC_SECRET)) {
        ESP_LOGE("PQC_NETWORK", "HMAC was dropped due to mutex timeout!");
        return;
    }

    if (!SecurityOfficer::secure_compare(pkt->hmac, calculated_hmac, 32)) {
        handle_blacklist(mac, false);
        return; 
    }

    packet_header_t header;
    uint8_t* payload = network_workspace.packet_buffer; 

    if (!NetworkPrivacy::unwrap(&header, payload, pkt)) {
        handle_blacklist(mac, false);
        return;
    }

    if (!check_replay(mac, header.msg_id)) return;

    handle_blacklist(mac, true);

    if (header.type == MSG_ACK) { ack_received = true; return; }

    if (header.type == MSG_DATA) {
        uint16_t p_len = header.payload_len;
        if (Messenger::ring_buffer_write((uint8_t*)&p_len, 2)) {
            Messenger::ring_buffer_write(payload, p_len);
            Messenger::send_ack(mac, header.msg_id, header.seq);
        }
    }
}

bool Messenger::send_reliable(const uint8_t* peer_mac, const uint8_t* data, size_t len) {
    if (len > 4096) return false;
    network_msg_t next_msg;
    memcpy(next_msg.target_mac, peer_mac, 6);
    memcpy(next_msg.final_mac, peer_mac, 6);
    memcpy(next_msg.data, data, len);
    next_msg.len = len;
    global_msg_id++;
    if (xQueueSend(network_queue, &next_msg, 0) == pdPASS) return true;
    return false;
}

void Messenger::send_ack(const uint8_t* mac, uint32_t msg_id, uint8_t seq) {
    packet_header_t ack_h;
    ack_h.type = MSG_ACK; memcpy(ack_h.final_dest, mac, 6);
    ack_h.msg_id = msg_id; ack_h.seq = seq; ack_h.total = 1; ack_h.payload_len = 0;
    
    fragment_packet_t ack_p;
    NetworkPrivacy::wrap(&ack_p, &ack_h, NULL, 0);
    uint8_t h_in[12 + 190];
    memcpy(h_in, ack_p.iv, 12); memcpy(h_in + 12, ack_p.data, 190);
    if (!Messenger::compute_hmac(ack_p.hmac, h_in, 12 + 190, HMAC_SECRET)) {
        ESP_LOGE("PQC_NETWORK", "Cannot compute HMAC for ACK!");
        return;
    }
    
    esp_now_send((uint8_t*)mac, (uint8_t*)&ack_p, sizeof(ack_p));
}

void network_task(void* pvParameters) {
    network_msg_t m;
    packet_header_t h;
    fragment_packet_t p;

    while (true) {
        if (xQueueReceive(network_queue, &m, portMAX_DELAY) == pdPASS) {
            messenger_busy = true;
            int total = (m.len + PQC_PAYLOAD_SIZE - 1) / PQC_PAYLOAD_SIZE;
            
            for (uint8_t i = 0; i < total; i++) {
                size_t c_len = (m.len - (i * PQC_PAYLOAD_SIZE) < PQC_PAYLOAD_SIZE) ? 
                                m.len - (i * PQC_PAYLOAD_SIZE) : PQC_PAYLOAD_SIZE;
                h.type = MSG_DATA;
                memcpy(h.final_dest, m.final_mac, 6); 
                h.msg_id = global_msg_id;
                h.seq = i;
                h.total = total;
                h.payload_len = (uint8_t)c_len;
                
                NetworkPrivacy::wrap(&p, &h, m.data + (i * PQC_PAYLOAD_SIZE), c_len);
                
                uint8_t src[12 + 190];
                memcpy(src, p.iv, 12); memcpy(src + 12, p.data, 190);
                if (!Messenger::compute_hmac(p.hmac, src, 12 + 190, HMAC_SECRET)) {
                    ESP_LOGE("PQC_NETWORK", "Cannot compute HMAC for MSG_DATA!");
                    continue;
                }

                for (int r = 0; r < 3; r++) {
                    ack_received = false;
                    esp_now_send(m.target_mac, (uint8_t*)&p, sizeof(p));
                    uint32_t s = millis();
                    while (millis() - s < 250) { if (ack_received) break; vTaskDelay(1); }
                    if (ack_received) break;
                }
            }
            messenger_busy = false;
        }
    }
}

void crypto_task(void* pvParameters) {
    uint8_t* work_ptr = network_workspace.encryption_buffer; 
    size_t work_len;
    while (true) {
        if (Messenger::ring_buffer_has_data()) {
            work_len = RING_BUFFER_SIZE;
            if (Messenger::ring_buffer_read(work_ptr, &work_len)) {
                // Burada PQC deşifreleme ve imza doğruma yapılabilir
                memset(work_ptr, 0, work_len);
            }
        }
        vTaskDelay(10 / portTICK_PERIOD_MS);
    }
}

bool Messenger::ring_buffer_write(const uint8_t* data, size_t len) {
    if (len > RING_BUFFER_SIZE) return false;
    
    portENTER_CRITICAL(&ring_buffer_spinlock);
    uint32_t next_head = (network_ring_buffer.head + len) & RING_BUFFER_MASK;
    if (next_head == network_ring_buffer.tail) {
        portEXIT_CRITICAL(&ring_buffer_spinlock);
        return false;
    }
    
    if (next_head > network_ring_buffer.head) {
        memcpy(network_ring_buffer.buffer + network_ring_buffer.head, data, len);
    } else {
        size_t first = RING_BUFFER_SIZE - network_ring_buffer.head;
        memcpy(network_ring_buffer.buffer + network_ring_buffer.head, data, first);
        memcpy(network_ring_buffer.buffer, data + first, len - first);
    }
    network_ring_buffer.head = next_head;
    portEXIT_CRITICAL(&ring_buffer_spinlock);
    return true;
}

bool Messenger::ring_buffer_read(uint8_t* data, size_t* len) {
    if (xSemaphoreTake(ring_buffer_mutex, portMAX_DELAY) == pdTRUE) {
        portENTER_CRITICAL(&ring_buffer_spinlock);
        bool empty = (network_ring_buffer.head == network_ring_buffer.tail);
        portEXIT_CRITICAL(&ring_buffer_spinlock);

        if (empty) { xSemaphoreGive(ring_buffer_mutex); return false; }
        
        uint16_t message_length;
        uint32_t t = network_ring_buffer.tail;
        
        // Circular buffer read for length
        if (t + 2 > RING_BUFFER_SIZE) {
            memcpy(&message_length, network_ring_buffer.buffer + t, RING_BUFFER_SIZE - t);
            memcpy(((uint8_t*)&message_length) + (RING_BUFFER_SIZE - t), network_ring_buffer.buffer, 2 - (RING_BUFFER_SIZE - t));
            t = 2 - (RING_BUFFER_SIZE - t);
        } else {
            memcpy(&message_length, network_ring_buffer.buffer + t, 2);
            t += 2;
        }
        
        if (message_length > *len) { xSemaphoreGive(ring_buffer_mutex); return false; }
        
        // Circular buffer read for data
        if (t + message_length > RING_BUFFER_SIZE) {
            size_t f = RING_BUFFER_SIZE - t;
            memcpy(data, network_ring_buffer.buffer + t, f);
            memcpy(data + f, network_ring_buffer.buffer, message_length - f);
            t = message_length - f;
        } else {
            memcpy(data, network_ring_buffer.buffer + t, message_length);
            t += message_length;
        }
        
        portENTER_CRITICAL(&ring_buffer_spinlock);
        network_ring_buffer.tail = t;
        portEXIT_CRITICAL(&ring_buffer_spinlock);
        
        *len = message_length;
        xSemaphoreGive(ring_buffer_mutex);
        return true;
    }
    return false;
}

bool Messenger::ring_buffer_has_data() { 
    portENTER_CRITICAL(&ring_buffer_spinlock);
    bool has_data = (network_ring_buffer.head != network_ring_buffer.tail);
    portEXIT_CRITICAL(&ring_buffer_spinlock);
    return has_data;
}
bool Messenger::is_busy() { return messenger_busy; }

} // namespace Network
} // namespace PQC

#endif
