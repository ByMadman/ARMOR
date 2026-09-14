#ifndef ARMOR_RC4_H
#define ARMOR_RC4_H

#include "armor_base.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _ARMOR_RC4 {
    au8 s[256];
    au8 i;
    au8 j;
} ARMOR_RC4;

void armor_rc4_init(ARMOR_RC4* st, const void* key, size_t keyLen);
au8  armor_rc4_next(ARMOR_RC4* st);
void armor_rc4_apply(ARMOR_RC4* st, void* data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* ARMOR_RC4_H */
