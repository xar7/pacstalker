#ifndef TLS_H
#define TLS_H

struct tlshdr {
    unsigned int type : 1;
    unsigned int legacy_version : 2;
    unsigned int length : 2;
};

#endif /* TLS_H */
