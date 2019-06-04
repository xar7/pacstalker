#ifndef TLS_H
#define TLS_H

struct tlshdr {
    uint8_t type;
    uint16_t legacy_version;
    uint16_t length;
};

#endif /* TLS_H */
