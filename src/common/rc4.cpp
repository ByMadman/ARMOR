#include "rc4.h"

void armor_rc4_init(ARMOR_RC4* st, const void* key, size_t keyLen)
{
    const au8* k = (const au8*)key;
    au32 i, j = 0;
    au8 tmp;

    for (i = 0; i < 256; i++) st->s[i] = (au8)i;
    for (i = 0; i < 256; i++) {
        j = (j + st->s[i] + k[i % keyLen]) & 0xFF;
        tmp = st->s[i];
        st->s[i] = st->s[j];
        st->s[j] = tmp;
    }
    st->i = 0;
    st->j = 0;
}

au8 armor_rc4_next(ARMOR_RC4* st)
{
    au8 tmp;
    st->i = (au8)(st->i + 1);
    st->j = (au8)(st->j + st->s[st->i]);
    tmp = st->s[st->i];
    st->s[st->i] = st->s[st->j];
    st->s[st->j] = tmp;
    return st->s[(au8)(st->s[st->i] + st->s[st->j])];
}

void armor_rc4_apply(ARMOR_RC4* st, void* data, size_t len)
{
    au8* p = (au8*)data;
    size_t n;
    for (n = 0; n < len; n++) p[n] ^= armor_rc4_next(st);
}
