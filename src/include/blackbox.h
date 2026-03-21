#ifndef PQC_BLACKBOX_H
#define PQC_BLACKBOX_H

#include <stdint.h>
#include <stddef.h>

namespace PQC {
namespace System {

/**
 * BlackBox (LatticeVanguard Secure Logging)
 * Beklenmedik hataları, RAM sızıntılarını ve sistem çökmelerini 
 * Flash (LittleFS) üzerine kaydeder. Cihaz kapansa bile hata izi silinmez.
 */
class BlackBox {
public:
    static bool init();
    
    // Hata Kayıt (Flash'a yaz)
    static void log_error(const char* operation, uint32_t iteration, size_t leak_amount);

    // Güvenlik Olayı Kayıt (Hacker hamlelerini kaydet)
    static void log_security_incident(const char* incident_type, const uint8_t* attacker_mac = nullptr);
    
    // Geçmiş Kayıtları Oku (Seri porttan bas)
    static void print_saved_logs();
    
    // Kayıtları Temizle
    static void clear_logs();

    // Mevcut durum
    static bool has_past_errors();

private:
    static const char* LOG_PATH;
};

} // namespace System
} // namespace PQC

#endif
