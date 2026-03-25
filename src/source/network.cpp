#include "../include/network_privacy.h"
#include "../include/security.h"
#include "../include/encryption.h"
#include "../include/fips202.h"
#include "../include/blackbox.h"
#include "../include/csprng.h"
#include <string.h>

#ifdef ARDUINO
#include <Arduino.h>
#include "esp_log.h"

namespace PQC {
namespace Network {

using namespace PQC::Memory;
using namespace PQC::Security;

// --- GÜVENLİK KATI: Modül Seviyesinde İzole Değişkenler ---
static MessageBufferHandle_t network_msg_buffer = NULL;
static SemaphoreHandle_t hmac_mutex = NULL;
static QueueHandle_t network_queue = NULL;
static QueueHandle_t recv_queue = NULL;

#define RECV_POOL_SIZE 10
static raw_packet_t recv_pool[RECV_POOL_SIZE];
static QueueHandle_t free_recv_queue = NULL;

#define SEND_POOL_SIZE 5
struct network_msg_buffer_t {
    network_msg_t msg;
    uint8_t payload[4096];
};
static network_msg_buffer_t send_pool[SEND_POOL_SIZE];
static QueueHandle_t free_send_queue = NULL;

struct raw_packet_t {
    uint8_t mac[6];
    uint8_t data[250];
    int len;
};

static peer_record_t peer_registry[MAX_PEERS];
static blacklist_t blacklist[MAX_PEERS];
static uint32_t global_msg_id = 1000;
static volatile bool messenger_busy = false;
static volatile bool last_send_ok = false;
static TaskHandle_t network_task_handle = NULL;
static volatile uint32_t expected_ack_id = 0;
static volatile uint8_t expected_ack_seq = 0;

static uint8_t LOCAL_MAC[6];
static uint8_t HMAC_SECRET[32] = {0}; // Silinen Hardcoded Key (System::KeyVault üzerinden NVS'ten yüklenecek)

struct network_msg_t {
    uint8_t target_mac[6];
    uint8_t final_mac[6];
    uint8_t* data;
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

    network_msg_buffer = xMessageBufferCreate(RING_BUFFER_SIZE);
    if (network_msg_buffer == NULL) return false;

    hmac_mutex = xSemaphoreCreateMutex();
    memset(peer_registry, 0, sizeof(peer_registry));
    memset(blacklist, 0, sizeof(blacklist));

    using PQC::System::KeyVault;
    KeyVault::load_config_uint32("tx_msg_id", &global_msg_id);

    // Hardcoded anahtar temizliği ve eFuse/NVS tabanlı mimari
    if (!KeyVault::load_key("hmac_secret", HMAC_SECRET, 32)) {
        PQC::System::CSPRNG::randombytes(HMAC_SECRET, 32);
        KeyVault::save_key("hmac_secret", HMAC_SECRET, 32);
        ESP_LOGW("PQC_NETWORK", "HMAC_SECRET not found in NVS! Generated and securely stored a new random key.");
    }

    free_recv_queue = xQueueCreate(RECV_POOL_SIZE, sizeof(raw_packet_t*));
    for (int i = 0; i < RECV_POOL_SIZE; i++) {
        raw_packet_t* ptr = &recv_pool[i];
        xQueueSend(free_recv_queue, &ptr, 0);
    }
    recv_queue = xQueueCreate(RECV_POOL_SIZE, sizeof(raw_packet_t*));

    free_send_queue = xQueueCreate(SEND_POOL_SIZE, sizeof(network_msg_buffer_t*));
    for (int i = 0; i < SEND_POOL_SIZE; i++) {
        network_msg_buffer_t* ptr = &send_pool[i];
        ptr->msg.data = ptr->payload;
        xQueueSend(free_send_queue, &ptr, 0);
    }
    network_queue = xQueueCreate(SEND_POOL_SIZE, sizeof(network_msg_buffer_t*));
    xTaskCreatePinnedToCore(network_task, "NetTask", 4096, NULL, 5, &network_task_handle, 0); 
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

static inline uint32_t get_mac_hash(const uint8_t* mac) {
    // Ultra-Fast O(1) MAC Hashing (Sabit hesaplama, Döngü yok)
    // DoS / CPU Exhaustion saldırılarını O(1) zaman ile kırmak için
    uint32_t hash = 5381;
    hash = ((hash << 5) + hash) ^ mac[0];
    hash = ((hash << 5) + hash) ^ mac[1];
    hash = ((hash << 5) + hash) ^ mac[2];
    hash = ((hash << 5) + hash) ^ mac[3];
    hash = ((hash << 5) + hash) ^ mac[4];
    hash = ((hash << 5) + hash) ^ mac[5];
    return hash % MAX_PEERS;
}

bool Messenger::is_blacklisted(const uint8_t* mac) {
    uint32_t idx = get_mac_hash(mac); // O(1) Lookup
    if (blacklist[idx].failures > 0 || blacklist[idx].expiry > 0) {
        if (memcmp(blacklist[idx].mac, mac, 6) == 0) {
            if (millis() < blacklist[idx].expiry) return true;
            memset(&blacklist[idx], 0, sizeof(blacklist_t));
        }
    }
    return false;
}

void Messenger::handle_blacklist(const uint8_t* mac, bool success) {
    uint32_t idx = get_mac_hash(mac);
    if (success) {
        if (memcmp(blacklist[idx].mac, mac, 6) == 0) {
            blacklist[idx].failures = 0;
            blacklist[idx].expiry = 0;
        }
    } else {
        // O(1) Direct Map (Collision handled by overwrite since it's an ephemeral firewall)
        if (memcmp(blacklist[idx].mac, mac, 6) != 0) {
            memcpy(blacklist[idx].mac, mac, 6);
            blacklist[idx].failures = 0;
            blacklist[idx].expiry = 0;
        }
        
        blacklist[idx].failures++;
        if (blacklist[idx].failures >= 3) {
            blacklist[idx].expiry = millis() + 60000;
            PQC::System::BlackBox::log_security_incident("MAC_BLACKLISTED", mac);
        }
    }
}

bool Messenger::check_replay(const uint8_t* mac, uint32_t msg_id) {
    uint32_t idx = get_mac_hash(mac); // O(1) Cache Address
    peer_record_t* peer = &peer_registry[idx];

    // Sabit zamanda (O(1)) Anti-Replay kontrolü
    if (memcmp(peer->mac, mac, 6) != 0) {
        // Yeni bir peer (veya hash çarpışması) - Yapıyı yeniden ayarla
        memcpy(peer->mac, mac, 6);
        peer->last_msg_id = msg_id;
        peer->window = 1;
        peer->last_seen = millis();
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
    if (len < (int)sizeof(fragment_packet_t) || len > 250) return;
    
    // Yüksek öncelikli ISR / WiFi System Task bağlamı. 
    // Mutex (xSemaphoreTake) beklemesi yapmadan veriyi kuyruğa atıp çıkıyoruz.
    raw_packet_t* raw_ptr = NULL;
    if (xQueueReceiveFromISR(free_recv_queue, &raw_ptr, NULL) == pdPASS) {
        memcpy(raw_ptr->mac, mac, 6);
        memcpy(raw_ptr->data, incomingData, len);
        raw_ptr->len = len;

        // Kuyruğa atılmazsa veri düşer (DOS / Flood koruması)
        if (xQueueSendFromISR(recv_queue, &raw_ptr, NULL) != pdPASS) {
            xQueueSendFromISR(free_recv_queue, &raw_ptr, NULL);
        }
    }
}

bool Messenger::send_reliable(const uint8_t* peer_mac, const uint8_t* data, size_t len) {
    if (len > 4096) return false;
    network_msg_buffer_t* next_buf = NULL;
    if (xQueueReceive(free_send_queue, &next_buf, 0) != pdPASS) return false; // Pool exhausted
    
    memcpy(next_buf->msg.target_mac, peer_mac, 6);
    memcpy(next_buf->msg.final_mac, peer_mac, 6);
    memcpy(next_buf->payload, data, len);
    next_buf->msg.len = len;
    global_msg_id++;
    
    if (xQueueSend(network_queue, &next_buf, 0) == pdPASS) return true;
    
    xQueueSend(free_send_queue, &next_buf, 0);
    return false;
}

void Messenger::send_ack(const uint8_t* mac, uint32_t msg_id, uint8_t seq) {
    packet_header_t ack_h;
    ack_h.type = MSG_ACK; memcpy(ack_h.final_dest, mac, 6);
    ack_h.msg_id = msg_id; ack_h.seq = seq; ack_h.total = 1; ack_h.payload_len = 0;
    
    fragment_packet_t ack_p;
    NetworkPrivacy::wrap(&ack_p, &ack_h, NULL, 0);
    if (!Messenger::compute_hmac(ack_p.hmac, (const uint8_t*)&ack_p, 250 - 32, HMAC_SECRET)) {
        ESP_LOGE("PQC_NETWORK", "Cannot compute HMAC for ACK!");
        return;
    }
    
    esp_now_send((uint8_t*)mac, (uint8_t*)&ack_p, sizeof(ack_p));
}

void network_task(void* pvParameters) {
    network_msg_buffer_t* m_buf;
    packet_header_t h;
    fragment_packet_t p;

    while (true) {
        if (xQueueReceive(network_queue, &m_buf, portMAX_DELAY) == pdPASS) {
            network_msg_t* m = &m_buf->msg;
            messenger_busy = true;
            int total = (m->len + PQC_PAYLOAD_SIZE - 1) / PQC_PAYLOAD_SIZE;
            
            for (uint8_t i = 0; i < total; i++) {
                size_t c_len = (m->len - (i * PQC_PAYLOAD_SIZE) < PQC_PAYLOAD_SIZE) ? 
                                m->len - (i * PQC_PAYLOAD_SIZE) : PQC_PAYLOAD_SIZE;
                h.type = MSG_DATA;
                memcpy(h.final_dest, m->final_mac, 6); 
                h.msg_id = global_msg_id;
                h.seq = i;
                h.total = total;
                h.payload_len = (uint8_t)c_len;
                
                NetworkPrivacy::wrap(&p, &h, m->data + (i * PQC_PAYLOAD_SIZE), c_len);
                
                if (!Messenger::compute_hmac(p.hmac, (const uint8_t*)&p, 250 - 32, HMAC_SECRET)) {
                    ESP_LOGE("PQC_NETWORK", "Cannot compute HMAC for MSG_DATA!");
                    continue;
                }

                expected_ack_id = h.msg_id;
                expected_ack_seq = h.seq;

                for (int r = 0; r < 3; r++) {
                    xTaskNotifyStateClear(network_task_handle);
                    esp_now_send(m->target_mac, (uint8_t*)&p, sizeof(p));
                    
                    uint32_t notified_value = 0;
                    if (xTaskNotifyWait(0x00, 0xFFFFFFFF, &notified_value, 250 / portTICK_PERIOD_MS) == pdTRUE) {
                        break;
                    }
                }
            }
            xQueueSend(free_send_queue, &m_buf, 0);
            messenger_busy = false;
        }
    }
}

void crypto_task(void* pvParameters) {
    raw_packet_t* raw_ptr = NULL;
    uint8_t* work_ptr = network_workspace.encryption_buffer; 
    size_t work_len;
    while (true) {
        // Gelen paketlerin kuyruktan alınıp rahatça (Mutex engeli olmadan WiFi Task'ı bekletmeden) işlenmesi
        if (xQueueReceive(recv_queue, &raw_ptr, 10 / portTICK_PERIOD_MS) == pdPASS) {
            if (!Messenger::is_blacklisted(raw_ptr->mac)) {
                fragment_packet_t* pkt = (fragment_packet_t*)raw_ptr->data;
                
                // 2. CRYPTOGRAPHIC FIREWALL (HMAC Check) - Burada güvenle Mutex alınıyor
                uint8_t calculated_hmac[32];
                if (!Messenger::compute_hmac(calculated_hmac, (const uint8_t*)pkt, 250 - 32, HMAC_SECRET)) {
                    ESP_LOGE("PQC_NETWORK", "HMAC was dropped due to mutex timeout!");
                } else if (!SecurityOfficer::secure_compare(pkt->hmac, calculated_hmac, 32)) {
                    Messenger::handle_blacklist(raw_ptr->mac, false);
                } else {
                    packet_header_t header;
                    uint8_t* payload = network_workspace.packet_buffer; 

                    if (!NetworkPrivacy::unwrap(&header, payload, pkt)) {
                        Messenger::handle_blacklist(raw_ptr->mac, false);
                    } else if (Messenger::check_replay(raw_ptr->mac, header.msg_id)) {
                        Messenger::handle_blacklist(raw_ptr->mac, true);

                        if (header.type == MSG_ACK) { 
                            if (header.msg_id == expected_ack_id && header.seq == expected_ack_seq) {
                                if (network_task_handle != NULL) {
                                    xTaskNotify(network_task_handle, 1, eSetBits);
                                }
                            }
                        } else if (header.type == MSG_DATA) {
                            if (Messenger::ring_buffer_write(payload, header.payload_len)) {
                                Messenger::send_ack(raw_ptr->mac, header.msg_id, header.seq);
                            }
                        }
                    }
                }
            }
            xQueueSend(free_recv_queue, &raw_ptr, 0);
        }

        if (Messenger::ring_buffer_has_data()) {
            work_len = RING_BUFFER_SIZE;
            if (Messenger::ring_buffer_read(work_ptr, &work_len)) {
                // Burada PQC deşifreleme ve imza doğruma yapılabilir
                memset(work_ptr, 0, work_len);
            }
        }
    }
}

bool Messenger::ring_buffer_write(const uint8_t* data, size_t len) {
    if (network_msg_buffer == NULL) return false;
    size_t written = xMessageBufferSend(network_msg_buffer, data, len, 0);
    return (written == len);
}

bool Messenger::ring_buffer_read(uint8_t* data, size_t* len) {
    if (network_msg_buffer == NULL) return false;
    size_t received = xMessageBufferReceive(network_msg_buffer, data, *len, 0);
    if (received > 0) {
        *len = received;
        return true;
    }
    return false;
}

bool Messenger::ring_buffer_has_data() { 
    if (network_msg_buffer == NULL) return false;
    return xMessageBufferIsEmpty(network_msg_buffer) == pdFALSE;
}
bool Messenger::is_busy() { return messenger_busy; }

} // namespace Network
} // namespace PQC

#endif
