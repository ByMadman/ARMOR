#ifndef ARMOR_BASE_H
#define ARMOR_BASE_H

/* 基础类型与无 CRT 依赖的内存/字节序工具。
   该头文件同时被打包器（使用 CRT）与运行时外壳 Stub（不使用 CRT）包含，
   因此不能引入任何库函数依赖。 */

#include <stddef.h>

typedef unsigned char      au8;
typedef unsigned short     au16;
typedef unsigned int       au32;
typedef unsigned long long au64;
typedef int                ai32;

#define ARMOR_MIN(a, b) (((a) < (b)) ? (a) : (b))
#define ARMOR_MAX(a, b) (((a) > (b)) ? (a) : (b))

static inline au32 armor_align_up(au32 v, au32 a) { return (v + (a - 1)) & ~(a - 1); }

static inline au64 armor_align_up64(au64 v, au64 a) { return (v + (a - 1)) & ~(a - 1); }

static inline au16 armor_rd16(const void* p)
{
    const au8* b = (const au8*)p;
    return (au16)((au32)b[0] | ((au32)b[1] << 8));
}

static inline au32 armor_rd32(const void* p)
{
    const au8* b = (const au8*)p;
    return (au32)b[0] | ((au32)b[1] << 8) | ((au32)b[2] << 16) | ((au32)b[3] << 24);
}

static inline void armor_wr16(void* p, au16 v)
{
    au8* b = (au8*)p;
    b[0] = (au8)(v & 0xFF);
    b[1] = (au8)((v >> 8) & 0xFF);
}

static inline void armor_wr32(void* p, au32 v)
{
    au8* b = (au8*)p;
    b[0] = (au8)(v & 0xFF);
    b[1] = (au8)((v >> 8) & 0xFF);
    b[2] = (au8)((v >> 16) & 0xFF);
    b[3] = (au8)((v >> 24) & 0xFF);
}

static inline au64 armor_rd64(const void* p)
{
    return (au64)armor_rd32(p) | ((au64)armor_rd32((const au8*)p + 4) << 32);
}

static inline void armor_wr64(void* p, au64 v)
{
    armor_wr32(p, (au32)(v & 0xFFFFFFFFu));
    armor_wr32((au8*)p + 4, (au32)(v >> 32));
}

static inline void* armor_copy(void* dst, const void* src, size_t n)
{
    volatile au8* d = (volatile au8*)dst;
    const au8* s = (const au8*)src;
    while (n--) *d++ = *s++;
    return dst;
}

static inline void* armor_fill(void* dst, int c, size_t n)
{
    /* volatile 目标指针：防止编译器把该填充循环识别为 memset 并折叠成对
       memset 的调用，从而避免与 stub.cpp 中自定义 memset -> armor_fill 形成
       无限递归（导致栈溢出 0xC00000FD）。 */
    volatile au8* d = (volatile au8*)dst;
    while (n--) *d++ = (au8)c;
    return dst;
}

static inline void* armor_move(void* dst, const void* src, size_t n)
{
    volatile au8* d = (volatile au8*)dst;
    const au8* s = (const au8*)src;
    if (d == s || n == 0) return dst;
    if (d < s || d >= s + n) return armor_copy(dst, src, n);
    while (n--) d[n] = s[n];
    return dst;
}

static inline int armor_cmp(const void* a, const void* b, size_t n)
{
    const au8* x = (const au8*)a;
    const au8* y = (const au8*)b;
    while (n--) {
        if (*x != *y) return (int)*x - (int)*y;
        x++;
        y++;
    }
    return 0;
}

static inline size_t armor_len(const char* s)
{
    size_t n = 0;
    while (s && s[n]) n++;
    return n;
}

/* 大小写无关 ASCII 比较（仅用于外壳内部） */
static inline int armor_cmpi(const char* a, const char* b)
{
    while (*a && *b) {
        int ca = (int)(au8)*a, cb = (int)(au8)*b;
        if (ca >= 'a' && ca <= 'z') ca -= 32;
        if (cb >= 'a' && cb <= 'z') cb -= 32;
        if (ca != cb) return ca - cb;
        a++;
        b++;
    }
    return (int)(au8)*a - (int)(au8)*b;
}

#endif /* ARMOR_BASE_H */
