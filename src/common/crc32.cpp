#include "crc32.h"

au32 armor_crc32_update(au32 crc, const void* data, size_t len)
{
    static const au32 kPoly = 0xEDB88320u;
    const au8* p = (const au8*)data;
    au32 i;
    size_t n;

    crc = ~crc;
    for (n = 0; n < len; n++) {
        crc ^= p[n];
        for (i = 0; i < 8; i++)
            crc = (crc >> 1) ^ (kPoly & (au32)(-(ai32)(crc & 1)));
    }
    return ~crc;
}

au32 armor_crc32(const void* data, size_t len)
{
    return armor_crc32_update(0, data, len);
}
