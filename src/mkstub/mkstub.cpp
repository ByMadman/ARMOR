/* ArmorMakeStub：把 ArmorStub.exe 转换成可内嵌到打包器里的 C 头文件。
 *
 * 用法：ArmorMakeStub.exe <Stub.exe> <stub_blob.h> [符号后缀]
 *
 *   符号后缀可选（默认按输入映像位宽自动选择：PE32+ -> "64"，PE32 -> 空）。
 *   打包器内嵌两份外壳映像：
 *     stub_blob.h   : 后缀为空 -> g_stubImage   / ARMOR_STUB_*      （x86）
 *     stub_blob64.h : 后缀 64  -> g_stubImage64 / ARMOR_STUB64_*    （x64）
 *
 * 做法：把 PE 按"被加载后的内存布局"扁平化（头部清零），提取：
 *   - 入口 RVA
 *   - .apar 参数节 RVA
 *   - 需要重定位的项（HIGHLOW / DIR64，打包为 rva|type<<28）
 */

#include "../common/armor_base.h"
#include "../common/peflat.h"

#include <windows.h>

#include <stdio.h>
#include <string>
#include <vector>

static bool readAll(const wchar_t* path, std::vector<au8>& out)
{
    FILE* f = nullptr;
    long size;
    if (_wfopen_s(&f, path, L"rb") != 0 || !f) return false;
    fseek(f, 0, SEEK_END);
    size = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (size <= 0) { fclose(f); return false; }
    out.assign((size_t)size, 0);
    if (fread(&out[0], 1, (size_t)size, f) != (size_t)size) { fclose(f); return false; }
    fclose(f);
    return true;
}

static std::string wideToUtf8(const wchar_t* s)
{
    std::string out;
    if (!s || !*s) return out;
    int n = WideCharToMultiByte(CP_UTF8, 0, s, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 0) return out;
    out.assign((size_t)(n - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, s, -1, &out[0], n, nullptr, nullptr);
    return out;
}

static bool hasImportDirectory(const std::vector<au8>& file)
{
    if (file.size() < 0x200) return false;
    const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)&file[0];
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    if ((size_t)dos->e_lfanew + 24u + 2u > file.size()) return false;
    const au8* nt = &file[0] + dos->e_lfanew;
    if (armor_rd32(nt) != IMAGE_NT_SIGNATURE) return false;
    au16 optSize = armor_rd16(nt + 20);
    au16 magic = armor_rd16(nt + 24);
    au32 ddOff = (au32)optSize + 24u;
    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        if ((size_t)dos->e_lfanew + ddOff + 8u * IMAGE_DIRECTORY_ENTRY_IMPORT + 8u > file.size()) return false;
        return armor_rd32(nt + ddOff + 8u * IMAGE_DIRECTORY_ENTRY_IMPORT) != 0;
    }
    if ((size_t)dos->e_lfanew + ddOff + 8u * IMAGE_DIRECTORY_ENTRY_IMPORT + 8u > file.size()) return false;
    return armor_rd32(nt + ddOff + 8u * IMAGE_DIRECTORY_ENTRY_IMPORT) != 0;
}

int wmain(int argc, wchar_t* argv[])
{
    std::vector<au8> file;
    FlatImage fi;
    std::string err;

    if (argc < 3) {
        wprintf(L"用法: ArmorMakeStub.exe <Stub.exe> <stub_blob.h> [符号后缀]\n");
        return 1;
    }
    if (!readAll(argv[1], file)) {
        wprintf(L"错误: 无法读取 %s\n", argv[1]);
        return 2;
    }
    if (!peBuildFlatImage(file.data(), file.size(), fi, err)) {
        wprintf(L"错误: %S\n", err.c_str());
        return 3;
    }
    if (hasImportDirectory(file)) {
        wprintf(L"警告: 外壳存在静态导入表，打包后的文件将携带这些导入\n");
    }

    std::string suffix = (argc >= 4) ? wideToUtf8(argv[3]) : std::string();
    if (argc < 4) suffix = fi.is64 ? "64" : "";

    FILE* out = nullptr;
    if (_wfopen_s(&out, argv[2], L"wb") != 0 || !out) {
        wprintf(L"错误: 无法写出 %s\n", argv[2]);
        return 4;
    }

    const std::string& S = suffix;
    std::string pfx = "ARMOR_STUB" + S + "_";

    /* 路径需先转 UTF-8 再以 %s 输出：%ls 在默认 "C" 区域设置下无法转换非 ASCII
       宽字符，一旦失败 fprintf 会提前中止，导致注释缺少结束标记。 */
    std::string srcUtf8 = wideToUtf8(argv[1]);
    fprintf(out, "/* 本文件由 ArmorMakeStub 自动生成，请勿手工修改。\n");
    fprintf(out, "   生成自: %s (machine=0x%04X, %s, imageBase=0x%016llX, entry=0x%08X, size=0x%08X, relocs=%u) */\n",
            srcUtf8.c_str(), fi.machine, fi.is64 ? "PE32+" : "PE32",
            (unsigned long long)fi.imageBase, fi.entryRva, fi.sizeOfImage,
            (unsigned)fi.relocs.size());
    fprintf(out, "#pragma once\n\n");
    fprintf(out, "#define %sIMAGE_BASE 0x%016llXull\n", pfx.c_str(), (unsigned long long)fi.imageBase);
    fprintf(out, "#define %sENTRY_RVA  0x%08Xu\n", pfx.c_str(), fi.entryRva);
    fprintf(out, "#define %sPARAM_RVA  0x%08Xu\n", pfx.c_str(), fi.paramRva);
    fprintf(out, "#define %sSIZE       %u\n", pfx.c_str(), (unsigned)fi.image.size());
    fprintf(out, "#define %sMACHINE    0x%04Xu\n", pfx.c_str(), fi.machine);
    fprintf(out, "#define %sIS64       %u\n", pfx.c_str(), fi.is64 ? 1u : 0u);
    fprintf(out, "\nstatic const unsigned char g_stubImage%s[%sSIZE] = {\n",
            S.c_str(), pfx.c_str());

    for (size_t i = 0; i < fi.image.size(); i++) {
        if ((i % 16) == 0) fprintf(out, "   ");
        fprintf(out, " 0x%02X,", fi.image[i]);
        if ((i % 16) == 15 || i + 1 == fi.image.size()) fprintf(out, "\n");
    }
    fprintf(out, "};\n\n");

    fprintf(out, "#define %sRELOC_COUNT %u\n", pfx.c_str(), (unsigned)fi.relocs.size());
    fprintf(out, "static const unsigned int g_stubRelocs%s[%s] = {\n",
            S.c_str(), fi.relocs.empty() ? "1" : (pfx + "RELOC_COUNT").c_str());
    if (fi.relocs.empty()) {
        fprintf(out, "   0\n");
    } else {
        for (size_t i = 0; i < fi.relocs.size(); i++) {
            if ((i % 8) == 0) fprintf(out, "   ");
            fprintf(out, " 0x%08Xu,", fi.relocs[i]);
            if ((i % 8) == 7 || i + 1 == fi.relocs.size()) fprintf(out, "\n");
        }
    }
    fprintf(out, "};\n");
    fclose(out);

    wprintf(L"已生成 %s (映像 %u 字节，%s，入口 0x%08X，参数节 0x%08X，重定位 %u 项)\n",
            argv[2], (unsigned)fi.image.size(), fi.is64 ? L"x64" : L"x86",
            fi.entryRva, fi.paramRva, (unsigned)fi.relocs.size());
    return 0;
}
