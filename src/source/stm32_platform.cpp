#include "../include/platform.h"
#include "../include/network_abstract.h"

#ifdef PLATFORM_STM32
#include <stm32f1xx_hal.h>
#include <stm32f1xx_hal_uart.h>
#include <stm32f1xx_hal_spi.h>
#include <stm32f1xx_hal_i2c.h>
#include <string.h>

/*
  STM32 NETWORK IMPLEMENTATION
  ---------------------------
  UART transport backend for cross-platform abstraction
*/

namespace PQC {
namespace Network {

// STM32 UART Transport Implementation
UART_HandleTypeDef huart1;
static volatile bool uart_data_available = false;
static volatile uint8_t uart_rx_buffer[NETWORK_MAX_PACKET_SIZE];
static volatile size_t uart_rx_pos = 0;
static void (*uart_receive_callback)(const uint8_t* mac, const uint8_t* data, int len) = nullptr;

bool UARTTransport::init() {
    // Initialize UART1 (PA9/PA10 for STM32F103)
    __HAL_RCC_USART1_CLK_ENABLE();
    __HAL_RCC_GPIOA_CLK_ENABLE();
    
    // Configure UART pins
    GPIO_InitTypeDef GPIO_InitStruct = {0};
    GPIO_InitStruct.Pin = GPIO_PIN_9;  // TX
    GPIO_InitStruct.Mode = GPIO_MODE_AF_PP;
    GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_HIGH;
    GPIO_InitStruct.Pull = GPIO_NOPULL;
    HAL_GPIO_Init(GPIOA, &GPIO_InitStruct);
    
    GPIO_InitStruct.Pin = GPIO_PIN_10; // RX
    GPIO_InitStruct.Mode = GPIO_MODE_INPUT;
    GPIO_InitStruct.Pull = GPIO_NOPULL;
    HAL_GPIO_Init(GPIOA, &GPIO_InitStruct);
    
    // Configure UART
    huart1.Instance = USART1;
    huart1.Init.BaudRate = 115200;
    huart1.Init.WordLength = UART_WORDLENGTH_8B;
    huart1.Init.StopBits = UART_STOPBITS_1;
    huart1.Init.Parity = UART_PARITY_NONE;
    huart1.Init.Mode = UART_MODE_TX_RX;
    huart1.Init.HwFlowCtl = UART_HWCONTROL_NONE;
    huart1.Init.OverSampling = UART_OVERSAMPLING_16;
    
    if (HAL_UART_Init(&huart1) != HAL_OK) {
        return false;
    }
    
    // Start receive interrupt
    HAL_UART_Receive_IT(&huart1, (uint8_t*)uart_rx_buffer, 1);
    
    return true;
}

bool UARTTransport::send_byte(uint8_t byte) {
    return HAL_UART_Transmit(&huart1, &byte, 1, 100) == HAL_OK;
}

bool UARTTransport::receive_byte(uint8_t* byte, uint32_t timeout_ms) {
    return HAL_UART_Receive(&huart1, byte, 1, timeout_ms) == HAL_OK;
}

bool UARTTransport::send_frame(const uint8_t* data, size_t len) {
    if (!data || len == 0 || len > NETWORK_MAX_PACKET_SIZE) {
        return false;
    }
    
    // Send start byte
    if (!send_byte(START_BYTE)) return false;
    
    // Send data with escaping
    for (size_t i = 0; i < len; i++) {
        uint8_t byte = data[i];
        if (byte == START_BYTE || byte == ESCAPE_BYTE || byte == END_BYTE) {
            if (!send_byte(ESCAPE_BYTE)) return false;
            byte ^= 0x20; // Toggle bit 5
        }
        if (!send_byte(byte)) return false;
    }
    
    // Send end byte
    if (!send_byte(END_BYTE)) return false;
    
    return true;
}

bool UARTTransport::receive_frame(uint8_t* data, size_t* len) {
    static uint8_t frame_buffer[NETWORK_MAX_PACKET_SIZE];
    static size_t frame_pos = 0;
    static bool escaping = false;
    static bool in_frame = false;
    
    // Process received byte
    uint8_t byte = uart_rx_buffer[uart_rx_pos - 1];
    
    if (byte == START_BYTE) {
        frame_pos = 0;
        escaping = false;
        in_frame = true;
        return false; // Frame not complete yet
    }
    
    if (!in_frame) return false;
    
    if (byte == END_BYTE) {
        if (frame_pos > 0) {
            memcpy(data, frame_buffer, frame_pos);
            *len = frame_pos;
            in_frame = false;
            return true;
        }
        in_frame = false;
        return false;
    }
    
    if (byte == ESCAPE_BYTE) {
        escaping = true;
        return false;
    }
    
    if (escaping) {
        byte ^= 0x20; // Toggle bit 5 back
        escaping = false;
    }
    
    if (frame_pos < NETWORK_MAX_PACKET_SIZE) {
        frame_buffer[frame_pos++] = byte;
    }
    
    return false;
}

bool UARTTransport::send_raw(const uint8_t* target_mac, const uint8_t* data, size_t len) {
    if (!target_mac || !data || len == 0) {
        return false;
    }
    
    // Create packet with MAC address
    uint8_t packet[NETWORK_MAX_PACKET_SIZE];
    memcpy(packet, target_mac, 6);
    memcpy(packet + 6, data, len);
    size_t total_len = 6 + len;
    
    return send_frame(packet, total_len);
}

bool UARTTransport::receive_raw(uint8_t* source_mac, uint8_t* data, size_t* len, uint32_t timeout_ms) {
    uint32_t start_time = HAL_GetTick();
    
    while ((HAL_GetTick() - start_time) < timeout_ms) {
        if (uart_data_available) {
            uart_data_available = false;
            
            size_t frame_len;
            if (receive_frame(data, &frame_len)) {
                if (frame_len >= 6) {
                    memcpy(source_mac, data, 6);
                    memmove(data, data + 6, frame_len - 6);
                    *len = frame_len - 6;
                    return true;
                }
            }
        }
        HAL_Delay(1);
    }
    
    return false;
}

bool UARTTransport::is_data_available() {
    return uart_data_available;
}

void UARTTransport::set_receive_callback(void (*callback)(const uint8_t* mac, const uint8_t* data, int len)) {
    uart_receive_callback = callback;
}

bool UARTTransport::get_device_mac(uint8_t* mac) {
    if (!mac) return false;
    
    // STM32: Generate MAC from unique ID
    uint32_t uid[3];
    uid[0] = HAL_GetUIDw0();
    uid[1] = HAL_GetUIDw1();
    uid[2] = HAL_GetUIDw2();
    
    // Create 6-byte MAC from 12-byte unique ID
    mac[0] = (uid[0] >> 24) & 0xFF;
    mac[1] = (uid[0] >> 16) & 0xFF;
    mac[2] = (uid[0] >> 8) & 0xFF;
    mac[3] = uid[0] & 0xFF;
    mac[4] = (uid[1] >> 24) & 0xFF;
    mac[5] = (uid[1] >> 16) & 0xFF;
    
    // Set locally administered bit
    mac[0] |= 0x02;
    
    return true;
}

// UART receive interrupt callback
void HAL_UART_RxCpltCallback(UART_HandleTypeDef *huart) {
    if (huart->Instance == USART1) {
        uart_data_available = true;
        uart_rx_pos = (uart_rx_pos + 1) % NETWORK_MAX_PACKET_SIZE;
        
        // Restart receive interrupt
        HAL_UART_Receive_IT(&huart1, (uint8_t*)&uart_rx_buffer[uart_rx_pos], 1);
        
        // Call user callback if data is complete
        if (uart_receive_callback && uart_data_available) {
            uint8_t source_mac[6];
            uint8_t data[NETWORK_MAX_PACKET_SIZE];
            size_t len;
            
            UARTTransport* transport = static_cast<UARTTransport*>(Network::create_network_transport());
            if (transport->receive_raw(source_mac, data, &len, 0)) {
                uart_receive_callback(source_mac, data, len);
            }
        }
    }
}

// STM32 Platform Implementation
class STM32Platform : public IPlatform {
private:
    PlatformInfo info;
    
public:
    STM32Platform() {
        info.name = "STM32F103C8T6";
        info.ram_size = PLATFORM_RAM_SIZE;
        info.max_workspace = PLATFORM_MAX_WORKSPACE;
        info.has_hw_crypto = PLATFORM_HAS_HARDWARE_CRYPTO;
        info.has_rtos = PLATFORM_HAS_FREERTOS;
        info.has_multicore = PLATFORM_HAS_MULTICORE;
        info.cpu_cores = 1;
    }
    
    bool init() override {
        // Initialize HAL
        HAL_Init();
        
        // Configure system clock
        SystemClock_Config();
        
        // Initialize systick
        HAL_SYSTICK_Config(HAL_RCC_GetHCLKFreq() / 1000);
        
        return true;
    }
    
    void delay_ms(uint32_t ms) override {
        HAL_Delay(ms);
    }
    
    uint32_t get_tick_ms() override {
        return HAL_GetTick();
    }
    
    bool get_device_mac(uint8_t* mac) override {
        if (!mac) return false;
        
        // Generate MAC from unique ID
        uint32_t uid[3];
        uid[0] = HAL_GetUIDw0();
        uid[1] = HAL_GetUIDw1();
        uid[2] = HAL_GetUIDw2();
        
        mac[0] = (uid[0] >> 24) & 0xFF;
        mac[1] = (uid[0] >> 16) & 0xFF;
        mac[2] = (uid[0] >> 8) & 0xFF;
        mac[3] = uid[0] & 0xFF;
        mac[4] = (uid[1] >> 24) & 0xFF;
        mac[5] = (uid[1] >> 16) & 0xFF;
        mac[0] |= 0x02; // Locally administered
        
        return true;
    }
    
    void secure_wipe(void* ptr, size_t len) override {
        if (ptr && len > 0) {
            // STM32: Simple clearing (no hardware acceleration)
            memset(ptr, 0x00, len);
            memset(ptr, 0xFF, len);
            memset(ptr, 0x00, len);
        }
    }
    
    bool get_random_bytes(uint8_t* buf, size_t len) override {
        if (!buf || len == 0) return false;
        
        // STM32: Use ADC as entropy source (simplified)
        ADC_HandleTypeDef hadc1;
        hadc1.Instance = ADC1;
        hadc1.Init.ScanConvMode = DISABLE;
        hadc1.Init.ContinuousConvMode = ENABLE;
        hadc1.Init.DiscontinuousConvMode = DISABLE;
        hadc1.Init.ExternalTrigConv = ADC_SOFTWARE_START;
        hadc1.Init.DataAlign = ADC_DATAALIGN_RIGHT;
        hadc1.Init.NbrOfConversion = 1;
        
        HAL_ADC_Init(&hadc1);
        HAL_ADC_Start(&hadc1);
        
        for (size_t i = 0; i < len; i++) {
            uint16_t adc_value;
            HAL_ADC_PollForConversion(&hadc1, 10);
            adc_value = HAL_ADC_GetValue(&hadc1);
            buf[i] = (uint8_t)(adc_value & 0xFF);
        }
        
        HAL_ADC_Stop(&hadc1);
        return true;
    }
    
    const PlatformInfo& get_info() override {
        return info;
    }
    
private:
    void SystemClock_Config() {
        RCC_OscInitTypeDef RCC_OscInitStruct = {0};
        RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};
        
        RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSE;
        RCC_OscInitStruct.HSEState = RCC_HSE_ON;
        RCC_OscInitStruct.HSEPredivValue = RCC_HSE_PREDIV_DIV1;
        RCC_OscInitStruct.HSIState = RCC_HSI_ON;
        RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
        RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSE;
        RCC_OscInitStruct.PLL.PLLMUL = RCC_PLL_MUL9;
        HAL_RCC_OscConfig(&RCC_OscInitStruct);
        
        RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                                      |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2;
        RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
        RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
        RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV2;
        RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;
        HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_2);
    }
};

// STM32 Memory Manager
class STM32MemoryManager : public IMemoryManager {
public:
    void* allocate_workspace(size_t size) override {
        return malloc(size);
    }
    
    void free_workspace(void* ptr) override {
        if (ptr) {
            free(ptr);
        }
    }
    
    size_t get_free_heap() override {
        // STM32: Simplified heap tracking
        extern char _end;
        extern char *__brkval;
        char *brkval = __brkval ? __brkval : &_end;
        char sp;
        return (size_t)&sp - (size_t)brkval;
    }
    
    size_t get_min_free_heap() override {
        // STM32: Not tracking minimum
        return get_free_heap();
    }
};

// STM32 Storage Interface
class STM32StorageInterface : public IStorageInterface {
public:
    bool init() override {
        // Initialize EEPROM emulation and SD card
        return true;
    }
    
    bool save_key(const char* key_name, const uint8_t* data, size_t len) override {
        // Implementation using EEPROM emulation
        return false; // Simplified
    }
    
    bool load_key(const char* key_name, uint8_t* data, size_t len) override {
        // Implementation using EEPROM emulation
        return false; // Simplified
    }
    
    bool save_data(const char* filename, const uint8_t* data, size_t len) override {
        // Implementation using SD card
        return false; // Simplified
    }
    
    bool load_data(const char* filename, uint8_t* data, size_t* len) override {
        // Implementation using SD card
        return false; // Simplified
    }
    
    bool delete_data(const char* filename) override {
        // Implementation using SD card
        return false; // Simplified
    }
};

// STM32 Log Interface
class STM32LogInterface : public ILogInterface {
public:
    bool init() override {
        return true;
    }
    
    void log_security_incident(const char* type, const uint8_t* mac) override {
        if (mac) {
            printf("[SECURITY] %s from %02X:%02X:%02X:%02X:%02X:%02X\n", 
                   type, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        } else {
            printf("[SECURITY] %s from unknown source\n", type);
        }
    }
    
    void log_error(const char* operation, uint32_t iteration, size_t leak_amount) override {
        printf("[ERROR] %s at iteration %u, leak: %zu bytes\n", 
               operation, iteration, leak_amount);
    }
    
    void print_logs() override {
        printf("[LOG] Printing stored logs...\n");
    }
    
    void clear_logs() override {
        printf("[LOG] Clearing stored logs\n");
    }
    
    bool has_logs() override {
        return false;
    }
};

// STM32 Network Interface
class STM32NetworkInterface : public INetworkInterface {
private:
    UARTTransport transport;
    
public:
    bool init() override {
        return transport.init();
    }
    
    bool send_packet(const uint8_t* target_mac, const uint8_t* data, size_t len) override {
        return transport.send_raw(target_mac, data, len);
    }
    
    bool receive_packet(uint8_t* source_mac, uint8_t* data, size_t* len) override {
        return transport.receive_raw(source_mac, data, len, 500);
    }
    
    bool is_packet_available() override {
        return transport.is_data_available();
    }
    
    void set_receive_callback(void (*callback)(const uint8_t* mac, const uint8_t* data, int len)) override {
        transport.set_receive_callback(callback);
    }
};

} // namespace Network
} // namespace PQC

// Factory implementations for STM32
namespace PQC {
namespace Platform {

IPlatform* PlatformFactory::create_platform() {
    return new Network::STM32Platform();
}

IMemoryManager* PlatformFactory::create_memory_manager() {
    return new Network::STM32MemoryManager();
}

INetworkInterface* PlatformFactory::create_network_interface() {
    return new Network::STM32NetworkInterface();
}

IStorageInterface* PlatformFactory::create_storage_interface() {
    return new Network::STM32StorageInterface();
}

ILogInterface* PlatformFactory::create_log_interface() {
    return new Network::STM32LogInterface();
}

} // namespace Platform
} // namespace PQC

#endif // PLATFORM_STM32
