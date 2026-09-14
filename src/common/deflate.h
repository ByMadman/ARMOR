#ifndef ARMOR_DEFLATE_H
#define ARMOR_DEFLATE_H

/* ARMOR 内部压缩格式：DEFLATE 兼容的固定哈夫曼块（BFINAL=1，BTYPE=01 / 00）。
   - 使用固定哈夫曼表，无需在数据流里保存树，解码端实现很小；
   - 支持 BTYPE=00（未压缩存储块）作为压缩无收益时的回退；
   - 外壳只需要 armor_decompress，可用 ARMOR_DECOMPRESS_ONLY 裁剪掉编码器。 */

#include "armor_base.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 压缩所需临时内存（哈希链）。level 取值 1..9 */
size_t armor_compress_scratch(int level);

/* 返回压缩后字节数，0 表示失败（输出缓冲区不足）。
   dstCap 建议按 srcLen + srcLen/8 + 128 分配。 */
size_t armor_compress(const void* src, size_t srcLen, void* dst, size_t dstCap,
                      int level, void* scratch, size_t scratchBytes);

/* 解压，返回输出字节数，0 表示失败 */
size_t armor_decompress(const void* src, size_t srcLen, void* dst, size_t dstCap);

#ifdef __cplusplus
}
#endif

#endif /* ARMOR_DEFLATE_H */
