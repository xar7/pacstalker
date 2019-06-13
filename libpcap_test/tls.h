#ifndef TLS_H
#define TLS_H

#define TLS_BEGIN_SIZE (4096)
#define TLS_APPLICATION_DATA (0x17)

struct tlshdr {
    uint8_t type;
    uint16_t legacy_version;
    uint16_t length;
}__attribute__((packed));

#endif /* TLS_H */
