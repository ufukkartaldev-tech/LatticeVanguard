#ifndef PQC_NETWORK_H
#define PQC_NETWORK_H

#include <stdint.h>
#include <stddef.h>

#ifdef ARDUINO
#include <esp_now.h>
#include <WiFi.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#endif

#include "workspace.h"

namespace PQC {
namespace Network {

#define PQC_MAX_PACKET_SIZE 250
#define PQC_PAYLOAD_SIZE    176 

// Ring Buffer Constants
#define RING_BUFFER_SIZE 16384
#define RING_BUFFER_MASK (RING_BUFFER_SIZE - 1)
#define MAX_FRAGMENTS 32
#define MAX_PEERS 8
#define WINDOW_SIZE 64      // Sliding window size (bits)

enum PacketType { MSG_DATA = 0, MSG_ACK = 1, MSG_HANDSHAKE_REQ = 2, MSG_HANDSHAKE_CERT = 3, MSG_AUTH = 4, MSG_NACK = 5 };

typedef struct {
    uint8_t type;
    uint8_t final_dest[6];
    uint32_t msg_id;      // Unique Message ID for Replay Protection
    uint8_t seq;
    uint8_t total;
    uint8_t payload_len;
} __attribute__((packed)) packet_header_t;

/**
 * FragmentPacket (Cryptographic Firewall Layer)
 * --------------------------------------------
 * Bu yapı, her paketi hem AES-GCM ile şifreler hem de HMAC-SHA3-256 ile imzalar.
 * Geçersiz imzalı paketler CPU'nun PQC motorlarını yormadan 'Firewall' katmanında atılır.
 */
typedef struct {
    uint8_t iv[12]; 
    uint8_t hmac[32];     // FIREWALL: HMAC-SHA3-256 (CPU DOS koruması)
    uint8_t auth_tag[16];   // AES-GCM Authenticator
    uint8_t data[190];      // Encrypted Header + Payload
} __attribute__((packed, aligned(4))) fragment_packet_t;

// Anti-Replay Sliding Window (Multi-Device Track)
typedef struct {
    uint8_t mac[6];
    uint32_t last_msg_id;
    uint64_t window;      // Bitmask for sliding window
    uint32_t last_seen;   // Keepalive tracker
} peer_record_t;

// Blacklist Tracker
typedef struct {
    uint8_t mac[6];
    uint8_t failures;
    uint32_t expiry;      // Timestamp for blacklist lift
} blacklist_t;

// Ring Buffer structure (Core 0 to Core 1 bridge)
typedef struct {
    uint8_t buffer[RING_BUFFER_SIZE];
    volatile uint32_t head;
    volatile uint32_t tail;
    uint32_t active_msg_id;
    uint8_t expected_seq;
    uint8_t total_fragments;
    bool session_active;
} ring_buffer_t;

class Messenger {
public:
    static bool init();
    
    // Core 0 (Network Task)
    static bool send_reliable(const uint8_t* peer_mac, const uint8_t* data, size_t len);
    static bool is_busy();

#ifdef ARDUINO
    static void on_data_recv(const uint8_t* mac, const uint8_t* incomingData, int len);
    static void on_data_sent(const uint8_t* mac, esp_now_send_status_t status);
#endif

    // Core 1 (Crypto Task)
    static bool ring_buffer_read(uint8_t* data, size_t* len);
    static bool ring_buffer_has_data();
    
    // Security Health
    static int get_last_retry_count();
    static bool is_blacklisted(const uint8_t* mac);

private:
    static void handle_blacklist(const uint8_t* mac, bool success);
    static bool check_replay(const uint8_t* mac, uint32_t msg_id);
    static void compute_hmac(uint8_t* out, const uint8_t* data, size_t len, const uint8_t* key);
};

} // namespace Network
} // namespace PQC

#endif
