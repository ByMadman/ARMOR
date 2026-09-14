#ifndef ARMOR_PACKFMT_H
#define ARMOR_PACKFMT_H

/* 打包格式定义：打包器与运行时外壳共用，结构体必须完全一致。
   打包器可构建为 Win32 或 x64，外壳则有 x86 / x64 两份映像，
   因此本头文件里的整数宽度必须显式固定，不能依赖 size_t / 指针宽度。 */

#include "armor_base.h"

#define ARMOR_MAGIC   0x524D5241u /* "ARMR" */
#define ARMOR_VERSION 2u          /* v2：imageBase 升为 64 位，新增 machine/is64 */

/* 标志位 */
#define ARMOR_F_ENCRYPT     0x00000001u /* 载荷使用 RC4 加密 */
#define ARMOR_F_ANTIDUMP    0x00000002u /* 还原后混淆 PE 头 */
#define ARMOR_F_HAS_TLS     0x00000004u /* 存在 TLS 目录 */
#define ARMOR_F_ANTIDBG_EXIT 0x00000010u /* 检测到调试器直接退出 */
#define ARMOR_F_ANTIDBG_FAKE 0x00000020u /* 检测到调试器后行为异常 */
#define ARMOR_F_CHECK_CRC   0x00000040u /* 解包前校验载荷 CRC */
#define ARMOR_F_HIDE_FEAT   0x00000080u /* 需要对易语言特征区域解密 */
#define ARMOR_F_KEEP_RSRC   0x00000100u /* 原资源节未压缩，跳过还原 */
#define ARMOR_F_ANTIDBG_L2  0x00000200u /* 反调试增强等级（窗口/进程名/计时） */
#define ARMOR_F_IS_DLL      0x00000400u /* 目标是 DLL：保留导入/导出/重定位表，外壳按 DllMain 语义运行 */

/* 机器类型（与 IMAGE_FILE_MACHINE_* 一致，避免本头文件依赖 windows.h） */
#define ARMOR_MACH_I386  0x014Cu
#define ARMOR_MACH_AMD64 0x8664u
#define ARMOR_MACH_ARM64 0xAA64u
#define ARMOR_MACH_ARMNT 0x01C4u

/* 基址重定位类型（与 IMAGE_REL_BASED_* 一致） */
#define ARMOR_RELOC_ABSOLUTE 0u  /* 填充项，忽略 */
#define ARMOR_RELOC_HIGHLOW  3u  /* 32 位绝对地址加增量（PE32） */
#define ARMOR_RELOC_DIR64    10u /* 64 位绝对地址加增量（PE32+） */

/* 重定位项打包：RVA 占低 28 位（限 256MB，外壳映像远小于此），类型占高 4 位。
   这样 mkstub 只需输出一个 au32 数组，外壳与打包器解码方式完全一致。 */
#define ARMOR_RELOC_PACK(rva, type) (((au32)(rva) & 0x0FFFFFFFu) | ((au32)(type) << 28))
#define ARMOR_RELOC_RVA(v)          ((v) & 0x0FFFFFFFu)
#define ARMOR_RELOC_TYPE(v)         ((v) >> 28)

/* 重定位项加增量：按类型决定改写的宽度 */
static inline void armor_reloc_apply(void* p, au32 type, au64 delta)
{
    if (type == ARMOR_RELOC_HIGHLOW)
        armor_wr32(p, (au32)(armor_rd32(p) + (au32)delta));
    else if (type == ARMOR_RELOC_DIR64)
        armor_wr64(p, armor_rd64(p) + delta);
}

/* 节区描述符：chars 为 0 表示该节已经就位，外壳无需还原 */
typedef struct _ARMOR_SECTION {
    au32 rva;
    au32 vsize;
    au32 chars;
} ARMOR_SECTION;

/* 需要运行时解密的特征区域（易语言特征隐藏） */
typedef struct _ARMOR_HIDE_ENT {
    au32 rva;
    au32 len;
} ARMOR_HIDE_ENT;

typedef struct _ARMOR_HEADER {
    au32 magic;
    au32 version;
    au32 flags;
    au32 headerSize; /* 本结构 + 后续表的总字节数 */

    au64 imageBase; /* 原始映像的首选基址（x64 下是 64 位值） */
    au32 oepRva;    /* 原始入口点 RVA */
    au32 headersSize; /* 需要还原的 PE 头字节数 */

    au32 machine;   /* IMAGE_FILE_MACHINE_*（ARMOR_MACH_*） */
    au32 is64;      /* 1 = PE32+（x64），0 = PE32（x86） */
    au32 sectionCount;
    au32 sectionsRva; /* ARMOR_SECTION 数组（打包后映像 RVA） */

    au32 payloadRva;
    au32 payloadSize;   /* 压缩并加密后的大小 */
    au32 unpackedSize;  /* 解压后原始扁平映像大小 */
    au32 hideCount;

    au32 hideRva; /* ARMOR_HIDE_ENT 数组 */
    au32 tlsIndexRva;    /* 打包后映像中 TLS 索引槽的 RVA */
    au32 tlsOrigIndexRva; /* 原始映像中 AddressOfIndex 的 RVA */
    au32 tlsCallbackRva;  /* 原始映像中 TLS 回调数组的 RVA，0 表示无 */

    au32 tlsRawRva;       /* 打包后映像中 TLS 原始数据副本的 RVA */
    au32 tlsRawSize;
    au32 tlsZeroFill;
    au32 payloadCrc; /* 加密后载荷的 CRC32 */

    au32 headerCrc;  /* 本结构 headerCrc 置 0 时的 CRC32 */
    au8  key[16]; /* RC4 密钥 */
    au32 reserved[4];
} ARMOR_HEADER;

/* Stub 参数块，打包器在生成时写入 .apar 节 */
#define ARMOR_STUB_MAGIC0 0x9A7F31C5u
#define ARMOR_STUB_MAGIC1 0x1D0B4E77u
#define ARMOR_STUB_MAGIC2 0x53AC9E21u
#define ARMOR_STUB_MAGIC3 0x7E5D0B93u

/* 特征隐藏区域的密钥派生：打包器与外壳必须完全一致 */
static inline void armor_hide_key(au8 out[16], const au8 master[16], au32 rva, au32 len)
{
    au32 i;
    for (i = 0; i < 16; i++) {
        au8 a = (au8)((rva >> ((i * 5) & 24)) & 0xFF);
        au8 b = (au8)((len >> ((i * 3) & 24)) & 0xFF);
        out[i] = (au8)(master[i] ^ a ^ b ^ (au8)(i * 37 + (rva & 0xFF)));
    }
}

typedef struct _ARMOR_STUB_PARAMS {
    au32 magic[4];
    au32 headerRva;  /* ARMOR_HEADER 相对映像基址的 RVA */
    au32 stubRva;    /* Stub 扁平映像在打包后映像中的 RVA */
    au32 reserved[2];
} ARMOR_STUB_PARAMS;

#endif /* ARMOR_PACKFMT_H */
