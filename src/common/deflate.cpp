#include "deflate.h"

#define MIN_MATCH 3
#define MAX_MATCH 258
#define MAX_DIST  32768

#define WBITS   15
#define WSIZE   (1u << WBITS)
#define WMASK   (WSIZE - 1)

#define HASHBITS 15
#define HASHSIZE (1u << HASHBITS)

static const au16 kLenBase[29] = {
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
    35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258
};
static const au8 kLenExtra[29] = {
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
    3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0
};
static const au16 kDistBase[30] = {
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
    257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577
};
static const au8 kDistExtra[30] = {
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
    7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13
};

/* ------------------------------------------------------------------ 位流 */

typedef struct _BW {
    au8* cur;
    au8* end;
    au8* begin;
    au32 bb;
    int  bc;
} BW;

static void bw_init(BW* w, void* dst, size_t cap)
{
    w->begin = (au8*)dst;
    w->cur = w->begin;
    w->end = w->begin + cap;
    w->bb = 0;
    w->bc = 0;
}

static int bw_raw(BW* w, au32 b)
{
    if (w->cur >= w->end) return 0;
    *w->cur++ = (au8)b;
    return 1;
}

/* LSB first，用于头字段与附加位 */
static int bw_bits(BW* w, au32 v, int n)
{
    w->bb |= (v & ((n >= 32) ? 0xFFFFFFFFu : ((1u << n) - 1u))) << w->bc;
    w->bc += n;
    while (w->bc >= 8) {
        if (!bw_raw(w, w->bb & 0xFF)) return 0;
        w->bb >>= 8;
        w->bc -= 8;
    }
    return 1;
}

/* MSB first，用于哈夫曼码 */
static int bw_code(BW* w, au32 code, int len)
{
    int i;
    for (i = len - 1; i >= 0; i--)
        if (!bw_bits(w, (code >> i) & 1, 1)) return 0;
    return 1;
}

static int bw_align(BW* w)
{
    if (w->bc > 0) {
        if (!bw_raw(w, w->bb & 0xFF)) return 0;
        w->bb = 0;
        w->bc = 0;
    }
    return 1;
}

typedef struct _BR {
    const au8* cur;
    const au8* end;
    au32 bb;
    int  bc;
} BR;

static void br_init(BR* r, const void* src, size_t len)
{
    r->cur = (const au8*)src;
    r->end = r->cur + len;
    r->bb = 0;
    r->bc = 0;
}

static int br_bits(BR* r, int n, au32* out)
{
    au32 v = 0;
    int i;
    for (i = 0; i < n; i++) {
        au32 bit;
        if (r->bc == 0) {
            if (r->cur >= r->end) return 0;
            r->bb = *r->cur++;
            r->bc = 8;
        }
        bit = (r->bb >> (8 - r->bc)) & 1u;
        r->bc--;
        v |= bit << i;
    }
    *out = v;
    return 1;
}

static int br_align(BR* r)
{
    r->bb = 0;
    r->bc = 0;
    return 1;
}

/* ------------------------------------------------------------- 哈夫曼表 */

typedef struct _HUFF {
    au16 count[16];
    au16 symbol[288];
} HUFF;

static void huff_build(HUFF* h, const au8* lengths, int n)
{
    au16 offs[16];
    int i;
    for (i = 0; i < 16; i++) h->count[i] = 0;
    for (i = 0; i < n; i++) h->count[lengths[i]]++;
    h->count[0] = 0;
    offs[1] = 0;
    for (i = 1; i < 15; i++) offs[i + 1] = (au16)(offs[i] + h->count[i]);
    for (i = 0; i < n; i++)
        if (lengths[i]) h->symbol[offs[lengths[i]]++] = (au16)i;
}

static int huff_decode(BR* r, const HUFF* h)
{
    int code = 0, first = 0, index = 0, len = 1;
    for (;;) {
        au32 bit;
        int count;
        if (!br_bits(r, 1, &bit)) return -1;
        code |= (int)bit;
        count = h->count[len];
        if (code - count < first) return h->symbol[index + (code - first)];
        index += count;
        first = (first + count) << 1;
        code <<= 1;
        len++;
        if (len >= 16) return -1;
    }
}

/* --------------------------------------------------------------- 编码器 */

#ifndef ARMOR_DECOMPRESS_ONLY

static void fixed_lengths(au8* litLen, au8* distLen)
{
    int i;
    for (i = 0; i < 144; i++) litLen[i] = 8;
    for (; i < 256; i++) litLen[i] = 9;
    for (; i < 280; i++) litLen[i] = 7;
    for (; i < 288; i++) litLen[i] = 8;
    for (i = 0; i < 30; i++) distLen[i] = 5;
}

static au32 hash3(const au8* p)
{
    au32 v = ((au32)p[0] << 16) | ((au32)p[1] << 8) | (au32)p[2];
    return (au32)((v * 2654435761u) >> (32 - HASHBITS));
}

static int find_match(const au8* src, size_t srcLen, size_t pos,
                      au32* head, au32* prev, int maxChain, int niceLen, int* distOut)
{
    size_t limit;
    au32 cand;
    const au8* cur = src + pos;
    int bestLen = 0, bestDist = 0;
    int maxLen, chain;

    if (pos + MIN_MATCH > srcLen) return 0;
    maxLen = (int)ARMOR_MIN((size_t)MAX_MATCH, srcLen - pos);
    limit = (pos > WSIZE) ? (pos - WSIZE) : 0;
    cand = head[hash3(cur)];
    chain = maxChain;

    while (cand > limit && chain-- > 0) {
        const au8* p = src + cand;
        if (p[bestLen] == cur[bestLen] && p[0] == cur[0] && p[1] == cur[1]) {
            int l = 0;
            while (l < maxLen && p[l] == cur[l]) l++;
            if (l > bestLen) {
                bestLen = l;
                bestDist = (int)(pos - cand);
                if (l >= maxLen || l >= niceLen) break;
            }
        }
        cand = prev[cand & WMASK];
    }
    if (bestLen >= MIN_MATCH) {
        *distOut = bestDist;
        return bestLen;
    }
    return 0;
}

static int len_code(int len, int* extraBits, int* extraVal)
{
    int i;
    for (i = 28; i >= 0; i--) {
        if (len >= kLenBase[i]) {
            *extraVal = len - kLenBase[i];
            *extraBits = kLenExtra[i];
            return i;
        }
    }
    return -1;
}

static int dist_code(int dist, int* extraBits, int* extraVal)
{
    int i;
    for (i = 29; i >= 0; i--) {
        if ((au32)dist >= kDistBase[i]) {
            *extraVal = dist - kDistBase[i];
            *extraBits = kDistExtra[i];
            return i;
        }
    }
    return -1;
}

size_t armor_compress_scratch(int level)
{
    (void)level;
    return (size_t)(HASHSIZE + WSIZE) * sizeof(au32);
}

static int compress_fixed_block(BW* w, const au8* src, size_t srcLen, int level,
                                void* scratch, size_t scratchBytes)
{
    au8 litLenA[288], distLenA[30];
    au16 litCode[288], distCode[30];
    au32* head;
    au32* prev;
    size_t pos = 0;
    int maxChain, niceLen;
    static const int kChain[10] = { 0, 4, 8, 16, 32, 64, 128, 256, 512, 1024 };
    static const int kNice[10] = { 0, 16, 24, 32, 48, 64, 96, 128, 192, 258 };

    if (level < 1) level = 1;
    if (level > 9) level = 9;
    maxChain = kChain[level];
    niceLen = kNice[level];

    if (scratchBytes < armor_compress_scratch(level)) return 0;
    head = (au32*)scratch;
    prev = head + HASHSIZE;

    fixed_lengths(litLenA, distLenA);
    {
        /* 由码长生成规范哈夫曼码 */
        au16 offs[16];
        int i;
        for (i = 0; i < 16; i++) { offs[i] = 0; }
        {
            au16 cnt[16];
            for (i = 0; i < 16; i++) cnt[i] = 0;
            for (i = 0; i < 288; i++) cnt[litLenA[i]]++;
            offs[1] = 0;
            for (i = 1; i < 15; i++) offs[i + 1] = (au16)((offs[i] + cnt[i]) << 1);
            for (i = 0; i < 288; i++) litCode[i] = offs[litLenA[i]]++;
            for (i = 0; i < 16; i++) cnt[i] = 0;
            for (i = 0; i < 30; i++) cnt[distLenA[i]]++;
            offs[1] = 0;
            for (i = 1; i < 15; i++) offs[i + 1] = (au16)((offs[i] + cnt[i]) << 1);
            for (i = 0; i < 30; i++) distCode[i] = offs[distLenA[i]]++;
        }
    }

    {
        size_t i;
        for (i = 0; i < HASHSIZE; i++) head[i] = 0;
        for (i = 0; i < WSIZE; i++) prev[i] = 0;
    }

    if (!bw_bits(w, 3, 3)) return 0; /* BFINAL=1, BTYPE=01 */

    while (pos < srcLen) {
        int dist = 0, len = 0;
        if (pos + MIN_MATCH <= srcLen)
            len = find_match(src, srcLen, pos, head, prev, maxChain, niceLen, &dist);

        if (len >= MIN_MATCH) {
            int lc, eb, ev, dc;
            size_t i;

            if (pos + MIN_MATCH <= srcLen) {
                au32 h = hash3(src + pos);
                prev[pos & WMASK] = head[h];
                head[h] = (au32)pos;
            }

            /* 惰性匹配 */
            if (len < niceLen && pos + 1 + MIN_MATCH <= srcLen) {
                int dist2 = 0;
                int len2 = find_match(src, srcLen, pos + 1, head, prev, maxChain, niceLen, &dist2);
                if (len2 > len) {
                    if (!bw_code(w, litCode[src[pos]], litLenA[src[pos]])) return 0;
                    pos++;
                    continue;
                }
            }

            lc = len_code(len, &eb, &ev);
            if (lc < 0) return 0;
            if (!bw_code(w, litCode[257 + lc], litLenA[257 + lc])) return 0;
            if (eb && !bw_bits(w, (au32)ev, eb)) return 0;

            dc = dist_code(dist, &eb, &ev);
            if (dc < 0) return 0;
            if (!bw_code(w, distCode[dc], 5)) return 0;
            if (eb && !bw_bits(w, (au32)ev, eb)) return 0;

            for (i = 1; i < (size_t)len; i++) {
                size_t q = pos + i;
                if (q + MIN_MATCH <= srcLen) {
                    au32 h = hash3(src + q);
                    prev[q & WMASK] = head[h];
                    head[h] = (au32)q;
                }
            }
            pos += (size_t)len;
        } else {
            if (pos + MIN_MATCH <= srcLen) {
                au32 h = hash3(src + pos);
                prev[pos & WMASK] = head[h];
                head[h] = (au32)pos;
            }
            if (!bw_code(w, litCode[src[pos]], litLenA[src[pos]])) return 0;
            pos++;
        }
    }

    if (!bw_code(w, litCode[256], litLenA[256])) return 0;
    if (!bw_align(w)) return 0;
    return 1;
}

size_t armor_compress(const void* src, size_t srcLen, void* dst, size_t dstCap,
                      int level, void* scratch, size_t scratchBytes)
{
    const au8* s = (const au8*)src;
    BW w;
    int ok;
    size_t huffSize;
    size_t storedSize = srcLen + 5;

    bw_init(&w, dst, dstCap);
    ok = (srcLen > 0) ? compress_fixed_block(&w, s, srcLen, level, scratch, scratchBytes) : 0;
    huffSize = ok ? (size_t)(w.cur - w.begin) : 0;

    if (!ok || huffSize >= storedSize) {
        /* 回退到未压缩存储块 */
        size_t n;
        if (storedSize > dstCap) return 0;
        bw_init(&w, dst, dstCap);
        if (!bw_bits(&w, 1, 3)) return 0; /* BFINAL=1, BTYPE=00 */
        if (!bw_align(&w)) return 0;
        if (w.cur + 4 + srcLen > w.end) return 0;
        w.cur[0] = (au8)(srcLen & 0xFF);
        w.cur[1] = (au8)((srcLen >> 8) & 0xFF);
        w.cur[2] = (au8)((~srcLen) & 0xFF);
        w.cur[3] = (au8)(((~srcLen) >> 8) & 0xFF);
        w.cur += 4;
        for (n = 0; n < srcLen; n++) *w.cur++ = s[n];
        return (size_t)(w.cur - w.begin);
    }
    return huffSize;
}

#else /* ARMOR_DECOMPRESS_ONLY */

size_t armor_compress_scratch(int level) { (void)level; return 0; }

size_t armor_compress(const void* src, size_t srcLen, void* dst, size_t dstCap,
                      int level, void* scratch, size_t scratchBytes)
{
    (void)src; (void)srcLen; (void)dst; (void)dstCap; (void)level;
    (void)scratch; (void)scratchBytes;
    return 0;
}

#endif /* ARMOR_DECOMPRESS_ONLY */

/* --------------------------------------------------------------- 解码器 */

size_t armor_decompress(const void* src, size_t srcLen, void* dst, size_t dstCap)
{
    BR r;
    au8* out = (au8*)dst;
    au8* outEnd = out + dstCap;
    size_t total = 0;

    br_init(&r, src, srcLen);

    for (;;) {
        au32 last = 0, type = 0;
        if (!br_bits(&r, 1, &last)) return 0;
        if (!br_bits(&r, 2, &type)) return 0;

        if (type == 0) {
            au32 lo, hi, len, i;
            (void)br_align(&r);
            if (r.cur + 4 > r.end) return 0;
            lo = (au32)r.cur[0] | ((au32)r.cur[1] << 8);
            hi = (au32)r.cur[2] | ((au32)r.cur[3] << 8);
            r.cur += 4;
            if ((lo ^ 0xFFFFu) != hi) return 0;
            len = lo;
            if (r.cur + len > r.end) return 0;
            if (out + len > outEnd) return 0;
            for (i = 0; i < len; i++) out[i] = r.cur[i];
            r.cur += len;
            out += len;
            total += len;
        } else if (type == 1) {
            HUFF hl, hd;
            au8 litLenA[288], distLenA[30];
            int i;
            for (i = 0; i < 144; i++) litLenA[i] = 8;
            for (; i < 256; i++) litLenA[i] = 9;
            for (; i < 280; i++) litLenA[i] = 7;
            for (; i < 288; i++) litLenA[i] = 8;
            for (i = 0; i < 30; i++) distLenA[i] = 5;
            huff_build(&hl, litLenA, 288);
            huff_build(&hd, distLenA, 30);

            for (;;) {
                int sym = huff_decode(&r, &hl);
                au32 len, dist;
                int ds;
                au32 extra;
                size_t k;
                const au8* from;

                if (sym < 0) return 0;
                if (sym == 256) break;
                if (sym < 256) {
                    if (out >= outEnd) return 0;
                    *out++ = (au8)sym;
                    total++;
                    continue;
                }
                sym -= 257;
                if (sym >= 29) return 0;
                len = kLenBase[sym];
                if (kLenExtra[sym]) {
                    if (!br_bits(&r, kLenExtra[sym], &extra)) return 0;
                    len += extra;
                }
                ds = huff_decode(&r, &hd);
                if (ds < 0 || ds >= 30) return 0;
                dist = kDistBase[ds];
                if (kDistExtra[ds]) {
                    if (!br_bits(&r, kDistExtra[ds], &extra)) return 0;
                    dist += extra;
                }
                if (dist > total || dist == 0) return 0;
                if ((size_t)(outEnd - out) < len) return 0;
                from = out - dist;
                for (k = 0; k < len; k++) out[k] = from[k];
                out += len;
                total += len;
            }
        } else {
            return 0;
        }
        if (last) break;
    }
    return total;
}
