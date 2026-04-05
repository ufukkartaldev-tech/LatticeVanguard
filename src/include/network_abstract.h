#ifndef PQC_NETWORK_ABSTRACT_H
#define PQC_NETWORK_ABSTRACT_H

/*
  CROSS-PLATFORM NETWORK ABSTRACTION
  ----------------------------------
  ESP32 (ESP-NOW) ve STM32 (UART/SPI) için ortak arayüz
*/

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "platform.h"
#include "workspace_unified.h"

namespace PQC {
namespace Network {

// Network Configuration per Platform
#ifdef PLATFORM_ESP32
  #define NETWORK_MAX_PACKET_SIZE    250     // ESP-NOW limit
  #define NETWORK_BROADCAST_ADDR     {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
  #define NETWORK_RETRY_COUNT        3
  #define NETWORK_TIMEOUT_MS         1000
#elif defined(PLATFORM_STM32)
  #define NETWORK_MAX_PACKET_SIZE    256     // UART buffer limit
  #define NETWORK_BROADCAST_ADDR     {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
  #define NETWORK_RETRY_COUNT        5       // UART more reliable
  #define NETWORK_TIMEOUT_MS         500
#elif defined(PLATFORM_PC)
  #define NETWORK_MAX_PACKET_SIZE    512     // PC simulation
  #define NETWORK_BROADCAST_ADDR     {0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED}
  #define NETWORK_RETRY_COUNT        1
  #define NETWORK_TIMEOUT_MS         100
#endif

// Packet Types (Platform Independent)
enum PacketType {
    MSG_DATA = 0,
    MSG_ACK = 1, 
    MSG_HANDSHAKE_REQ = 2,
    MSG_HANDSHAKE_CERT = 3,
    MSG_AUTH = 4,
    MSG_NACK = 5,
    MSG_HEARTBEAT = 6
};

// Standard Packet Header (All Platforms)
typedef struct {
    uint8_t type;              // PacketType enum
    uint8_t final_dest[6];     // Final destination MAC
    uint32_t msg_id;           // Unique message ID
    uint8_t seq;               // Sequence number
    uint8_t total;             // Total fragments
    uint8_t payload_len;       // Payload length
    uint16_t checksum;         // Header checksum
} __attribute__((packed)) packet_header_t;

// Encrypted Packet Structure
typedef struct {
    packet_header_t header;     // 14 bytes (plaintext AAD)
    uint8_t iv[12];           // AES-GCM IV
    uint8_t auth_tag[16];     // AES-GCM tag
    uint8_t payload[NETWORK_MAX_PACKET_SIZE - 42]; // Encrypted payload
    uint8_t hmac[32];         // HMAC-SHA3-256 (firewall)
} __attribute__((packed, aligned(4))) secure_packet_t;

// Network Statistics
typedef struct {
    uint32_t packets_sent;
    uint32_t packets_received;
    uint32_t packets_dropped;
    uint32_t retries;
    uint32_t hmac_failures;
    uint32_t replay_attacks;
    uint32_t blacklist_hits;
    uint32_t uptime_ms;
} network_stats_t;

// Peer Management
typedef struct {
    uint8_t mac[6];
    uint32_t last_seen;
    uint32_t packets_sent;
    uint32_t packets_received;
    uint8_t failures;
    bool is_trusted;
    bool is_blacklisted;
} peer_record_t;

// Abstract Network Interface
class INetworkTransport {
public:
    virtual ~INetworkTransport() = default;
    
    // Core transport functions
    virtual bool init() = 0;
    virtual bool send_raw(const uint8_t* target_mac, const uint8_t* data, size_t len) = 0;
    virtual bool receive_raw(uint8_t* source_mac, uint8_t* data, size_t* len, uint32_t timeout_ms) = 0;
    virtual bool is_data_available() = 0;
    virtual void set_receive_callback(void (*callback)(const uint8_t* mac, const uint8_t* data, int len)) = 0;
    
    // Transport-specific functions
    virtual const char* get_transport_name() = 0;
    virtual uint32_t get_max_packet_size() = 0;
    virtual bool is_broadcast_supported() = 0;
    virtual bool get_device_mac(uint8_t* mac) = 0;
};

// High-level Network Manager
class NetworkManager {
private:
    static INetworkTransport* transport;
    static peer_record_t peer_table[32];  // Support up to 32 peers
    static network_stats_t stats;
    static volatile bool initialized;
    
    // Security functions
    static bool compute_hmac(uint8_t* hmac, const uint8_t* data, size_t len, const uint8_t* key);
    static bool verify_packet_integrity(const secure_packet_t* packet);
    static bool is_replay_attack(const uint8_t* mac, uint32_t msg_id);
    static void update_peer_record(const uint8_t* mac, bool success);
    
public:
    // Initialization
    static bool initialize(INetworkTransport* transport_impl);
    static void shutdown();
    static bool is_initialized();
    
    // Core messaging
    static bool send_packet(const uint8_t* target_mac, const uint8_t* data, size_t len);
    static bool receive_packet(uint8_t* source_mac, uint8_t* data, size_t* len, uint32_t timeout_ms = 100);
    static bool send_encrypted(const uint8_t* target_mac, const uint8_t* data, size_t len, const uint8_t* key);
    static bool receive_encrypted(uint8_t* source_mac, uint8_t* data, size_t* len, const uint8_t* key);
    
    // Reliability
    static bool send_reliable(const uint8_t* target_mac, const uint8_t* data, size_t len);
    static bool send_ack(const uint8_t* mac, uint32_t msg_id, uint8_t seq);
    
    // Peer management
    static bool add_trusted_peer(const uint8_t* mac);
    static bool remove_peer(const uint8_t* mac);
    static bool is_peer_trusted(const uint8_t* mac);
    static bool blacklist_peer(const uint8_t* mac);
    static bool is_peer_blacklisted(const uint8_t* mac);
    
    // Statistics and monitoring
    static const network_stats_t& get_stats();
    static void reset_stats();
    static void print_stats();
    static uint8_t get_peer_count();
    static peer_record_t* get_peer_list();
    
    // Utilities
    static void get_broadcast_mac(uint8_t* mac);
    static bool mac_equal(const uint8_t* mac1, const uint8_t* mac2);
    static void copy_mac(uint8_t* dest, const uint8_t* src);
    static void print_mac(const uint8_t* mac);
};

// ESP-NOW Transport Implementation
#ifdef PLATFORM_ESP32
class ESPNowTransport : public INetworkTransport {
private:
    static void on_data_sent_callback(const uint8_t* mac, esp_now_send_status_t status);
    static void on_data_recv_callback(const uint8_t* mac, const uint8_t* data, int len);
    
public:
    bool init() override;
    bool send_raw(const uint8_t* target_mac, const uint8_t* data, size_t len) override;
    bool receive_raw(uint8_t* source_mac, uint8_t* data, size_t* len, uint32_t timeout_ms) override;
    bool is_data_available() override;
    void set_receive_callback(void (*callback)(const uint8_t* mac, const uint8_t* data, int len)) override;
    
    const char* get_transport_name() override { return "ESP-NOW"; }
    uint32_t get_max_packet_size() override { return NETWORK_MAX_PACKET_SIZE; }
    bool is_broadcast_supported() override { return true; }
    bool get_device_mac(uint8_t* mac) override;
};
#endif

// UART Transport Implementation (STM32)
#ifdef PLATFORM_STM32
class UARTTransport : public INetworkTransport {
private:
    uint8_t rx_buffer[NETWORK_MAX_PACKET_SIZE];
    volatile size_t rx_pos;
    volatile bool packet_ready;
    uint8_t current_mac[6];
    
    // UART protocol framing
    static const uint8_t START_BYTE = 0xAA;
    static const uint8_t ESCAPE_BYTE = 0x55;
    static const uint8_t END_BYTE = 0x55;
    
    bool send_byte(uint8_t byte);
    bool receive_byte(uint8_t* byte, uint32_t timeout_ms);
    bool send_frame(const uint8_t* data, size_t len);
    bool receive_frame(uint8_t* data, size_t* len);
    
public:
    bool init() override;
    bool send_raw(const uint8_t* target_mac, const uint8_t* data, size_t len) override;
    bool receive_raw(uint8_t* source_mac, uint8_t* data, size_t* len, uint32_t timeout_ms) override;
    bool is_data_available() override;
    void set_receive_callback(void (*callback)(const uint8_t* mac, const uint8_t* data, int len)) override;
    
    const char* get_transport_name() override { return "UART"; }
    uint32_t get_max_packet_size() override { return NETWORK_MAX_PACKET_SIZE; }
    bool is_broadcast_supported() override { return false; }
    bool get_device_mac(uint8_t* mac) override;
};
#endif

// PC Simulation Transport
#ifdef PLATFORM_PC
class PCTransport : public INetworkTransport {
private:
    // Simulate network with loopback or TCP sockets
    int server_socket;
    int client_socket;
    bool is_server;
    
public:
    bool init() override;
    bool send_raw(const uint8_t* target_mac, const uint8_t* data, size_t len) override;
    bool receive_raw(uint8_t* source_mac, uint8_t* data, size_t* len, uint32_t timeout_ms) override;
    bool is_data_available() override;
    void set_receive_callback(void (*callback)(const uint8_t* mac, const uint8_t* data, int len)) override;
    
    const char* get_transport_name() override { return "PC Simulation"; }
    uint32_t get_max_packet_size() override { return NETWORK_MAX_PACKET_SIZE; }
    bool is_broadcast_supported() override { return true; }
    bool get_device_mac(uint8_t* mac) override;
};
#endif

// Factory function
INetworkTransport* create_network_transport();

} // namespace Network
} // namespace PQC

#endif
