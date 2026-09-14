#include "peflat.h"
#include "packfmt.h"

#include <windows.h>

#define ARMOR_PARAM_SECTION ".apar"

namespace {

bool rvaToOffset(const au8* base, size_t fileSize,
                 const IMAGE_SECTION_HEADER* secs, int nsec,
                 au32 rva, au32 len, au32* off)
{
    int i;
    if (rva == 0) return false;
    for (i = 0; i < nsec; i++) {
        au32 va = secs[i].VirtualAddress;
        au32 vs = secs[i].Misc.VirtualSize;
        au32 rs = secs[i].SizeOfRawData;
        au32 span = vs ? vs : rs;
        if (rva >= va && rva < va + span) {
            au32 delta = rva - va;
            if (delta + len > rs) return false;
            au32 o = secs[i].PointerToRawData + delta;
            if ((size_t)o + len > fileSize) return false;
            *off = o;
            return true;
        }
    }
    return false;
}

} /* namespace */

/* 读取 NT 头公共部分并做边界校验。成功后 nt/out 可用。 */
static bool peParseNt(const au8* fileData, size_t fileSize,
                      const IMAGE_NT_HEADERS32** nt32,
                      const IMAGE_NT_HEADERS64** nt64,
                      const IMAGE_SECTION_HEADER** secs,
                      int* nsec, bool* is64, std::string& err)
{
    const IMAGE_DOS_HEADER* dos;
    const au8* nt;
    au32 lfa;
    au16 optSize;

    *nt32 = nullptr;
    *nt64 = nullptr;
    *secs = nullptr;
    *nsec = 0;

    if (fileSize < 0x200) {
        err = "文件太小，不是有效的 PE";
        return false;
    }
    dos = (const IMAGE_DOS_HEADER*)fileData;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        err = "缺少 MZ 签名";
        return false;
    }
    lfa = (au32)dos->e_lfanew;
    if (lfa < 0x40 || (size_t)lfa + 24u > fileSize || (lfa & 3u)) {
        err = "PE 头偏移越界";
        return false;
    }
    nt = fileData + lfa;
    if (armor_rd32(nt) != IMAGE_NT_SIGNATURE) {
        err = "缺少 PE 签名";
        return false;
    }
    optSize = armor_rd16(nt + 20);
    if (optSize < 2 || (size_t)lfa + 24u + (size_t)optSize > fileSize) {
        err = "可选头越界";
        return false;
    }
    {
        au16 magic = armor_rd16(nt + 24);
        if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) *is64 = true;
        else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) *is64 = false;
        else { err = "可选头 Magic 非法（既不是 PE32 也不是 PE32+）"; return false; }
    }
    {
        au16 n = armor_rd16(nt + 6);
        const au8* s = nt + 24u + optSize;
        if (n == 0 || n > 96) { err = "节数量异常"; return false; }
        if ((size_t)(s - fileData) + (size_t)n * sizeof(IMAGE_SECTION_HEADER) > fileSize) {
            err = "节表越界";
            return false;
        }
        *secs = (const IMAGE_SECTION_HEADER*)s;
        *nsec = (int)n;
    }
    if (*is64) *nt64 = (const IMAGE_NT_HEADERS64*)nt;
    else       *nt32 = (const IMAGE_NT_HEADERS32*)nt;
    return true;
}

bool peBuildFlatImage(const au8* fileData, size_t fileSize, FlatImage& out, std::string& err)
{
    const IMAGE_NT_HEADERS32* nt32 = nullptr;
    const IMAGE_NT_HEADERS64* nt64 = nullptr;
    const IMAGE_SECTION_HEADER* secs = nullptr;
    int nsec = 0, i;
    bool is64 = false;
    au32 imageSize;
    au32 machine;

    if (!peParseNt(fileData, fileSize, &nt32, &nt64, &secs, &nsec, &is64, err))
        return false;

    machine = nt64 ? nt64->FileHeader.Machine : nt32->FileHeader.Machine;
    if (machine != IMAGE_FILE_MACHINE_I386 && machine != IMAGE_FILE_MACHINE_AMD64) {
        err = "外壳必须是 x86 或 x64 映像";
        return false;
    }
    if (is64 && machine != IMAGE_FILE_MACHINE_AMD64) {
        err = "外壳架构与 PE 格式不一致（PE32+ 必须是 AMD64）";
        return false;
    }
    if (!is64 && machine != IMAGE_FILE_MACHINE_I386) {
        err = "外壳架构与 PE 格式不一致（PE32 必须是 I386）";
        return false;
    }

    imageSize = nt64 ? nt64->OptionalHeader.SizeOfImage : nt32->OptionalHeader.SizeOfImage;
    if (imageSize < 0x2000 || imageSize > 16u * 1024u * 1024u) {
        err = "外壳映像大小异常";
        return false;
    }

    out.image.assign(imageSize, 0);
    out.imageBase = nt64 ? nt64->OptionalHeader.ImageBase : nt32->OptionalHeader.ImageBase;
    out.entryRva = nt64 ? nt64->OptionalHeader.AddressOfEntryPoint
                        : nt32->OptionalHeader.AddressOfEntryPoint;
    out.sizeOfImage = imageSize;
    out.machine = machine;
    out.is64 = is64;
    out.relocs.clear();
    out.paramRva = 0;
    out.paramSize = 0;

    /* 头部区域保持为 0：避免扁平映像中出现 MZ/PE 特征 */
    for (i = 0; i < nsec; i++) {
        au32 va = secs[i].VirtualAddress;
        au32 rs = secs[i].SizeOfRawData;
        au32 vs = secs[i].Misc.VirtualSize;
        au32 span = vs ? vs : rs;
        au32 copy = rs < span ? rs : span;
        if (va >= imageSize) continue;
        if ((size_t)va + copy > imageSize) copy = imageSize - va;
        if ((size_t)secs[i].PointerToRawData + copy > fileSize)
            copy = (au32)(fileSize - secs[i].PointerToRawData);
        if (copy) memcpy(&out.image[va], fileData + secs[i].PointerToRawData, copy);

        if (strncmp((const char*)secs[i].Name, ARMOR_PARAM_SECTION, 8) == 0) {
            out.paramRva = va;
            out.paramSize = rs ? rs : vs;
            out.stubSection = ARMOR_PARAM_SECTION;

            /* 精确定位 g_armorParams：.apar 节内不一定从偏移 0 开始就是该符号，
               故扫描节内 4 个 magic dword (ARMOR_STUB_MAGIC0..3) 来定位。 */
            au32 scanSpan = vs ? vs : rs;
            if (va + scanSpan > imageSize) scanSpan = imageSize - va;
            for (au32 o = 0; o + 16 <= scanSpan; o += 4) {
                const au32* p = (const au32*)&out.image[va + o];
                if (p[0] == ARMOR_STUB_MAGIC0 && p[1] == ARMOR_STUB_MAGIC1 &&
                    p[2] == ARMOR_STUB_MAGIC2 && p[3] == ARMOR_STUB_MAGIC3) {
                    out.paramRva = va + o;
                    break;
                }
            }
        }
    }

    /* 收集重定位项（PE32 用 HIGHLOW，PE32+ 用 DIR64；两者都可能同时出现填充项） */
    {
        const IMAGE_DATA_DIRECTORY* dd = nt64
            ? &nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
            : &nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (dd->VirtualAddress && dd->Size) {
            const au8* p = &out.image[dd->VirtualAddress];
            au32 left = dd->Size;
            if ((size_t)dd->VirtualAddress + left <= imageSize) {
                while (left >= 8) {
                    au32 pageRva = armor_rd32(p);
                    au32 blkSize = armor_rd32(p + 4);
                    au32 n;
                    if (blkSize < 8 || blkSize > left) break;
                    n = (blkSize - 8) / 2;
                    for (au32 k = 0; k < n; k++) {
                        au16 item = armor_rd16(p + 8 + k * 2);
                        au32 type = item >> 12;
                        au32 off = item & 0xFFF;
                        au32 full = pageRva + off;
                        if (type == ARMOR_RELOC_HIGHLOW || type == ARMOR_RELOC_DIR64) {
                            if (full < 0x10000000u)
                                out.relocs.push_back(ARMOR_RELOC_PACK(full, type));
                        }
                    }
                    p += blkSize;
                    left -= blkSize;
                    if (blkSize == 0) break;
                }
            }
        }
    }

    if (out.paramRva == 0) {
        err = "未找到 " ARMOR_PARAM_SECTION " 参数节";
        return false;
    }
    if (out.entryRva == 0 || out.entryRva >= imageSize) {
        err = "入口点无效";
        return false;
    }
    return true;
}
