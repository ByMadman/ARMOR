#ifndef ARMOR_CRC32_H
#define ARMOR_CRC32_H

#include "armor_base.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 标准 CRC-32 (IEEE 802.3)。
   不使用静态表，避免在外壳中产生可写全局量；表在栈上生成，调用开销可忽略。 */
au32 armor_crc32(const void* data, size_t len);
au32 armor_crc32_update(au32 crc, const void* data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* ARMOR_CRC32_H */
