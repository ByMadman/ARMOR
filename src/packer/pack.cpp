#include "pack.h"

#include "pefile.h"
#include "utf8util.h"

#include "../common/crc32.h"
#include "../common/deflate.h"
#include "../common/packfmt.h"
#include "../common/peflat.h"
#include "../common/rc4.h"

/* 内嵌两份运行时外壳映像，按目标架构二选一：
     stub_blob.h   -> x86（PE32）
     stub_blob64.h -> x64（PE32+）
   两者都由 ArmorStub 工程构建后经 ArmorMakeStub 自动生成，请勿手改。 */
#include "stub_blob.h"
#include "stub_blob64.h"

#include <windows.h>

#include <algorithm>
#include <cstring>
#include <stdio.h>
#include <time.h>

/* ------------------------------------------------------------------ 工具 */

namespace {

au32 g_rng = 0;

au32 rndNext(void)
{
    g_rng ^= g_rng << 13;
    g_rng ^= g_rng >> 17;
    g_rng ^= g_rng << 5;
    return g_rng;
}

void rngInit(const PackOptions& opt)
{
    g_rng = (au32)time(nullptr) ^ (au32)GetCurrentProcessId() ^ (au32)(au64)(size_t)&g_rng ^ (opt.seed * 2654435761u);
    if (g_rng == 0) g_rng = 0x12345678u;
    for (int i = 0; i < 8; i++) rndNext();
}

struct StubBlob {
    std::vector<au8> image;
    au64 imageBase = 0;
    au32 entryRva = 0;
    au32 paramRva = 0;
    au32 machine = 0;
    bool is64 = false;
    std::vector<au32> relocs; /* ARMOR_RELOC_PACK(rva, type) */
};

void setStubBlobFromEmbedded(StubBlob& out, bool want64)
{
    if (want64) {
        out.image.assign(g_stubImage64, g_stubImage64 + ARMOR_STUB64_SIZE);
        out.imageBase = ARMOR_STUB64_IMAGE_BASE;
        out.entryRva = ARMOR_STUB64_ENTRY_RVA;
        out.paramRva = ARMOR_STUB64_PARAM_RVA;
        out.machine = ARMOR_STUB64_MACHINE;
        out.is64 = true;
        out.relocs.assign(g_stubRelocs64, g_stubRelocs64 + ARMOR_STUB64_RELOC_COUNT);
    } else {
        out.image.assign(g_stubImage, g_stubImage + ARMOR_STUB_SIZE);
        out.imageBase = ARMOR_STUB_IMAGE_BASE;
        out.entryRva = ARMOR_STUB_ENTRY_RVA;
        out.paramRva = ARMOR_STUB_PARAM_RVA;
        out.machine = ARMOR_STUB_MACHINE;
        out.is64 = false;
        out.relocs.assign(g_stubRelocs, g_stubRelocs + ARMOR_STUB_RELOC_COUNT);
    }
}

bool loadStubBlob(const std::string& path, StubBlob& out, std::string& err, bool want64)
{
    if (path.empty()) {
        setStubBlobFromEmbedded(out, want64);
        return true;
    }
    std::wstring wp = utf8ToWide(path);
    std::string raw;
    if (!readFileToString(wp, raw)) {
        err = "无法读取外壳文件: " + path;
        return false;
    }
    FlatImage fi;
    if (!peBuildFlatImage((const au8*)raw.data(), raw.size(), fi, err)) {
        err = "外壳文件无效: " + err;
        return false;
    }
    if (fi.is64 != want64) {
        err = std::string("外部外壳架构与目标不一致：目标是 ") + (want64 ? "x64（PE32+）" : "x86（PE32）") +
              "，而 --stub 指定的是 " + (fi.is64 ? "x64" : "x86") + " 映像";
        return false;
    }
    out.image = fi.image;
    out.imageBase = fi.imageBase;
    out.entryRva = fi.entryRva;
    out.paramRva = fi.paramRva;
    out.machine = fi.machine;
    out.is64 = fi.is64;
    out.relocs = fi.relocs;
    return true;
}

bool loadSignatureText(const std::string& explicitPath, std::string& text, std::string& note)
{
    if (!explicitPath.empty()) {
        std::wstring wp = utf8ToWide(explicitPath);
        if (readFileToString(wp, text)) return true;
        note = "指定的特征文件不存在，已改用内置特征: " + explicitPath;
        text = sigDefaultText();
        return true;
    }
    /* 同目录查找 signatures.txt */
    wchar_t modPath[MAX_PATH];
    DWORD n = GetModuleFileNameW(nullptr, modPath, MAX_PATH);
    if (n > 0 && n < MAX_PATH) {
        std::wstring p(modPath);
        size_t pos = p.find_last_of(L"\\/");
        if (pos != std::string::npos) {
            std::wstring cand = p.substr(0, pos + 1) + L"signatures.txt";
            if (readFileToString(cand, text)) return true;
        }
    }
    text = sigDefaultText();
    return true;
}

struct OutSection {
    char name[8];
    au32 va;
    au32 vs;
    au32 rawSize;
    au32 rawPtr;
    au32 chars;
    au32 srcRawOff;  /* 保留节：原文件 raw 偏移（供复制原始数据） */
    au32 srcRawSize; /* 保留节：原文件 raw 大小 */
};

void setSectionName(OutSection& s, const std::string& n)
{
    memset(s.name, 0, 8);
    /* PE 节名是 8 字节定长数组，允许无 null 终止；strncpy_s(_TRUNCATE)
       会在 8 字节时强制补 null 丢最后一字节，故用 memcpy */
    memcpy(s.name, n.c_str(), n.size() > 8 ? 8 : n.size());
}

/* 生成产物节名：.{prefix}0 / .{prefix}r / .{prefix}1（PE 节名最长 8 字节） */
static std::string makeSectionName(const std::string& prefix, char suffix)
{
    std::string n = ".";
    n += prefix;
    n += suffix;
    if (n.size() > 8) n.resize(8);
    return n;
}

/* 生成仅包含 RT_MANIFEST 的最小资源树 */
std::vector<au8> buildManifestResource(const au8* data, au32 size, au32 baseRva, au16 resId, au16 langId)
{
    const size_t dirSize = sizeof(IMAGE_RESOURCE_DIRECTORY) + sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);
    size_t offType = 0;
    size_t offName = dirSize;
    size_t offLang = dirSize * 2;
    size_t offData = dirSize * 3;
    size_t offRaw = offData + sizeof(IMAGE_RESOURCE_DATA_ENTRY);

    std::vector<au8> buf(offRaw + size + 4, 0);

    IMAGE_RESOURCE_DIRECTORY* d1 = (IMAGE_RESOURCE_DIRECTORY*)&buf[offType];
    d1->NumberOfIdEntries = 1;
    IMAGE_RESOURCE_DIRECTORY_ENTRY* e1 = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)&buf[offType + sizeof(IMAGE_RESOURCE_DIRECTORY)];
    /* RT_MANIFEST 是 MAKEINTRESOURCE(24)，x64 下为指针宽度，需屏蔽高位再取低 16 位 */
    e1->Id = (au32)((size_t)RT_MANIFEST & 0xFFFFu);
    e1->DataIsDirectory = 1;
    e1->OffsetToDirectory = (au32)offName;

    IMAGE_RESOURCE_DIRECTORY* d2 = (IMAGE_RESOURCE_DIRECTORY*)&buf[offName];
    d2->NumberOfIdEntries = 1;
    IMAGE_RESOURCE_DIRECTORY_ENTRY* e2 = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)&buf[offName + sizeof(IMAGE_RESOURCE_DIRECTORY)];
    e2->Id = resId ? resId : 1;
    e2->DataIsDirectory = 1;
    e2->OffsetToDirectory = (au32)offLang;

    IMAGE_RESOURCE_DIRECTORY* d3 = (IMAGE_RESOURCE_DIRECTORY*)&buf[offLang];
    d3->NumberOfIdEntries = 1;
    IMAGE_RESOURCE_DIRECTORY_ENTRY* e3 = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)&buf[offLang + sizeof(IMAGE_RESOURCE_DIRECTORY)];
    e3->Id = langId;
    e3->DataIsDirectory = 0;
    e3->OffsetToData = (au32)offData;

    IMAGE_RESOURCE_DATA_ENTRY* de = (IMAGE_RESOURCE_DATA_ENTRY*)&buf[offData];
    de->OffsetToData = baseRva + (au32)offRaw;
    de->Size = size;
    de->CodePage = 0;
    de->Reserved = 0;

    if (size) memcpy(&buf[offRaw], data, size);
    buf.resize(offRaw + size);
    return buf;
}

/* 重定位表（标准 IMAGE_BASE_RELOCATION 块）。
   items 为 ARMOR_RELOC_PACK(rva,type) 打包值，按页分组写出。 */
std::vector<au8> buildRelocTable(const std::vector<au32>& packed)
{
    std::vector<au32> sorted = packed;
    std::sort(sorted.begin(), sorted.end());
    sorted.erase(std::unique(sorted.begin(), sorted.end()), sorted.end());

    std::vector<au8> buf;
    size_t i = 0;
    while (i < sorted.size()) {
        au32 page = ARMOR_RELOC_RVA(sorted[i]) & 0xFFFFF000u;
        std::vector<au16> items;
        while (i < sorted.size() && (ARMOR_RELOC_RVA(sorted[i]) & 0xFFFFF000u) == page) {
            au32 rva = ARMOR_RELOC_RVA(sorted[i]);
            au32 type = ARMOR_RELOC_TYPE(sorted[i]);
            items.push_back((au16)((type << 12) | (rva & 0xFFFu)));
            i++;
        }
        size_t blk = 8 + items.size() * 2;
        while (blk % 4) { items.push_back(0); blk += 2; }
        size_t off = buf.size();
        buf.resize(off + blk, 0);
        armor_wr32(&buf[off], page);
        armor_wr32(&buf[off + 4], (au32)blk);
        for (size_t k = 0; k < items.size(); k++) armor_wr16(&buf[off + 8 + k * 2], items[k]);
    }
    return buf;
}

/* 合成 TLS 目录里需要随映像重定位的 VA 字段（相对目录起始的偏移） */
void tlsDirRelocOffsets(bool is64, au32 offs[3])
{
    if (is64) { offs[0] = 0x00u; offs[1] = 0x08u; offs[2] = 0x10u; } /* 三个 8 字节 VA */
    else      { offs[0] = 0x00u; offs[1] = 0x04u; offs[2] = 0x08u; } /* 三个 4 字节 VA */
}

const char* kAutoHideNames[] = {
    "程序入口", "易语言入口", "静态编译识别", "核心支持库",
    "第三方支持库", "FF25_1", "FF25_2", "模盾模块Jmp"
};

const char* kEplIndicators[] = {
    "程序入口", "易语言入口", "静态编译识别", "核心支持库", "第三方支持库",
    "按钮事件1", "按钮事件2", "信息框", "信息框2", "取文本长度",
    "到文本1", "载入窗口1", "调用子程序1", "取随机数", "窗口消息处理"
};

bool nameInList(const std::string& name, const char* const* list, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (name == list[i]) return true;
    return false;
}

bool hideListHas(const std::vector<std::string>& v, const std::string& s)
{
    for (size_t i = 0; i < v.size(); i++)
        if (v[i] == s) return true;
    return false;
}

std::vector<std::string> splitNames(const std::string& s)
{
    std::vector<std::string> out;
    size_t pos = 0;
    while (pos <= s.size()) {
        size_t sep = s.find_first_of(";,", pos);
        if (sep == std::string::npos) {
            std::string t = s.substr(pos);
            if (!t.empty()) out.push_back(t);
            break;
        }
        std::string t = s.substr(pos, sep - pos);
        if (!t.empty()) out.push_back(t);
        pos = sep + 1;
    }
    return out;
}

void analyzeEpl(PackStats& st)
{
    int hits = 0;
    bool hasStatic = false, hasCore = false;
    for (size_t i = 0; i < st.sigs.size(); i++) {
        const SigResult& r = st.sigs[i];
        if (r.hitCount == 0) continue;
        if (nameInList(r.name, kEplIndicators, sizeof(kEplIndicators) / sizeof(kEplIndicators[0]))) hits++;
        if (r.name == "静态编译识别") hasStatic = true;
        if (r.name == "核心支持库" || r.name == "第三方支持库") hasCore = true;
    }
    st.isEpl = hits >= 2;
    if (st.isEpl) {
        if (hasStatic) st.eplKind = "静态编译";
        else if (hasCore) st.eplKind = "非静态编译（依赖支持库）";
        else st.eplKind = "易语言特征";
    }
}

void countImports(const PEFile& pe, int* dlls, int* funcs)
{
    *dlls = 0;
    *funcs = 0;
    const IMAGE_DATA_DIRECTORY& dd = pe.dir(IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (!dd.VirtualAddress || !dd.Size) return;
    bool ok = false;
    au32 off = pe.rvaToOffset(dd.VirtualAddress, sizeof(IMAGE_IMPORT_DESCRIPTOR), &ok);
    if (!ok) return;
    const au32 step = pe.is64 ? 8u : 4u; /* IMAGE_THUNK_DATA 宽度 */
    for (;;) {
        const IMAGE_IMPORT_DESCRIPTOR* d = (const IMAGE_IMPORT_DESCRIPTOR*)&pe.data[off];
        if (off + sizeof(IMAGE_IMPORT_DESCRIPTOR) > pe.data.size()) break;
        if (d->OriginalFirstThunk == 0 && d->FirstThunk == 0 && d->Name == 0) break;
        (*dlls)++;
        au32 thunkRva = d->OriginalFirstThunk ? d->OriginalFirstThunk : d->FirstThunk;
        bool ok2 = false;
        au32 toff = pe.rvaToOffset(thunkRva, step, &ok2);
        if (ok2) {
            for (;;) {
                au64 v;
                if (toff + step > pe.data.size()) break;
                v = pe.is64 ? armor_rd64(&pe.data[toff]) : (au64)armor_rd32(&pe.data[toff]);
                if (v == 0) break;
                (*funcs)++;
                toff += step;
            }
        }
        off += sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }
}

/* 写出打包后的 PE 头（按目标架构输出 PE32 或 PE32+） */
void writePeHeaders(std::vector<au8>& out, const PEFile& pe,
                    const std::vector<OutSection>& secs, au32 entryRva,
                    au32 sizeOfImage, au32 sizeOfHeaders,
                    const IMAGE_DATA_DIRECTORY dirs[16])
{
    memset(&out[0], 0, 0x80);
    out[0] = 'M';
    out[1] = 'Z';
    armor_wr32(&out[0x3C], 0x80);

    /* 传统 DOS 存根，仅作兼容，不会被执行 */
    const au8 dosStub[] = {
        0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21,
        'T', 'h', 'i', 's', ' ', 'p', 'r', 'o', 'g', 'r', 'a', 'm', ' ', 'c', 'a', 'n',
        'n', 'o', 't', ' ', 'b', 'e', ' ', 'r', 'u', 'n', ' ', 'i', 'n', ' ', 'D', 'O',
        'S', ' ', 'm', 'o', 'd', 'e', '.', 0x0D, 0x0D, 0x0A, 0x24, 0x00
    };
    memcpy(&out[0x40], dosStub, sizeof(dosStub));

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)&out[0];
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = 0x80;

    au8* ntp = &out[0x80];
    au8* ohp = ntp + 24;
    IMAGE_FILE_HEADER* fh = (IMAGE_FILE_HEADER*)(ntp + 4);

    armor_wr32(ntp, IMAGE_NT_SIGNATURE);
    *fh = pe.is64 ? pe.nt64()->FileHeader : pe.nt32()->FileHeader;
    fh->NumberOfSections = (au16)secs.size();
    fh->SizeOfOptionalHeader = pe.optHeaderSize();
    fh->PointerToSymbolTable = 0;
    fh->NumberOfSymbols = 0;
    fh->Characteristics &= ~IMAGE_FILE_RELOCS_STRIPPED;
    fh->Characteristics |= IMAGE_FILE_EXECUTABLE_IMAGE;

    au32 sizeOfCode = 0, sizeOfInit = 0;
    for (size_t i = 0; i < secs.size(); i++) {
        if (secs[i].chars & IMAGE_SCN_CNT_CODE) sizeOfCode += secs[i].vs;
        else sizeOfInit += secs[i].vs;
    }

    if (pe.is64) {
        IMAGE_OPTIONAL_HEADER64 oh = pe.nt64()->OptionalHeader;
        /* 栈/堆保留字段在某些目标里较小，统一补齐下限，避免加壳后初始栈过小导致外壳崩溃 */
        if (oh.SizeOfStackReserve < 0x100000ull) oh.SizeOfStackReserve = 0x100000ull;
        if (oh.SizeOfStackCommit == 0) oh.SizeOfStackCommit = 0x4000ull;
        if (oh.SizeOfHeapReserve < 0x100000ull) oh.SizeOfHeapReserve = 0x100000ull;
        if (oh.SizeOfHeapCommit == 0) oh.SizeOfHeapCommit = 0x2000ull;
        oh.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        oh.SizeOfCode = sizeOfCode;
        oh.SizeOfInitializedData = sizeOfInit;
        oh.SizeOfUninitializedData = 0;
        oh.AddressOfEntryPoint = entryRva;
        oh.BaseOfCode = secs.empty() ? 0 : secs[0].va;
        oh.SizeOfImage = sizeOfImage;
        oh.SizeOfHeaders = sizeOfHeaders;
        oh.CheckSum = 0;
        oh.LoaderFlags = 0;
        oh.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        oh.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY;
        memcpy(ohp, &oh, sizeof(oh));
    } else {
        IMAGE_OPTIONAL_HEADER32 oh = pe.nt32()->OptionalHeader;
        if (oh.SizeOfStackReserve < 0x40000u) oh.SizeOfStackReserve = 0x100000u;
        if (oh.SizeOfStackCommit == 0) oh.SizeOfStackCommit = 0x2000u;
        if (oh.SizeOfHeapReserve < 0x100000u) oh.SizeOfHeapReserve = 0x100000u;
        if (oh.SizeOfHeapCommit == 0) oh.SizeOfHeapCommit = 0x1000u;
        oh.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
        oh.SizeOfCode = sizeOfCode;
        oh.SizeOfInitializedData = sizeOfInit;
        oh.SizeOfUninitializedData = 0;
        oh.AddressOfEntryPoint = entryRva;
        oh.BaseOfCode = secs.empty() ? 0 : secs[0].va;
        oh.BaseOfData = oh.BaseOfCode;
        oh.SizeOfImage = sizeOfImage;
        oh.SizeOfHeaders = sizeOfHeaders;
        oh.CheckSum = 0;
        oh.LoaderFlags = 0;
        oh.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        oh.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY;
        memcpy(ohp, &oh, sizeof(oh));
    }

    IMAGE_DATA_DIRECTORY* ddOut = (IMAGE_DATA_DIRECTORY*)(ohp + (pe.is64 ? 0x70u : 0x60u));
    for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
        ddOut[i].VirtualAddress = 0;
        ddOut[i].Size = 0;
    }
    for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
        if (dirs[i].VirtualAddress) ddOut[i] = dirs[i];
    }

    IMAGE_SECTION_HEADER* sh = (IMAGE_SECTION_HEADER*)(ohp + pe.optHeaderSize());
    memset(sh, 0, sizeof(IMAGE_SECTION_HEADER) * secs.size());
    for (size_t i = 0; i < secs.size(); i++) {
        memcpy(sh[i].Name, secs[i].name, 8);
        sh[i].Misc.VirtualSize = secs[i].vs;
        sh[i].VirtualAddress = secs[i].va;
        sh[i].SizeOfRawData = secs[i].rawSize;
        sh[i].PointerToRawData = secs[i].rawPtr;
        sh[i].Characteristics = secs[i].chars;
    }
}

} /* namespace */

/* --------------------------------------------------------------- 主流程 */

bool packFile(const std::wstring& inPath, const std::wstring& outPath,
              const PackOptions& opt, PackStats& st)
{
    DWORD t0 = GetTickCount();
    std::string err;
    PEFile pe;

    rngInit(opt);

    st.inputUtf8 = wideToUtf8(inPath);
    st.outputUtf8 = wideToUtf8(outPath);

    /* 解压还原模式：输入是已加壳产物，输出为还原后的原始文件 */
    if (opt.unpack) return unpackFile(inPath, outPath, opt, st);

    if (!pe.load(inPath.c_str(), err)) { st.error = err; return false; }
    st.inSize = (au64)pe.data.size();

    /* ---- 按 PE 格式判定目标形态（不看扩展名） ---- */
    st.is64 = pe.is64;
    st.machine = pe.machine();
    st.isDll = pe.isDll();
    st.targetKind = st.isDll ? "dll" : "exe";
    st.stubArch = pe.is64 ? "x64" : "x86";

    if (pe.isDriver()) {
        st.error = "不支持内核态映像（.sys / Native 子系统）：加壳需要能在内核态运行的外壳，"
                   "且会破坏驱动签名导致 DSE 拒绝加载";
        return false;
    }
    if (pe.isEfi()) {
        st.error = "不支持 EFI 固件映像（非 Windows 用户态程序）";
        return false;
    }
    if (pe.isDotNet()) {
        st.error = "不支持 .NET 程序（含 CLR 头）";
        return false;
    }
    if (st.isDll && !opt.allowDll) {
        st.error = "目标是 DLL，如需加壳请加 --allow-dll";
        return false;
    }
    if (pe.isPackedByArmor(opt.sectionPrefix.c_str()) && !opt.force) {
        st.error = "目标已经是 ARMOR 处理过的文件（如需重复处理请加 --force）";
        return false;
    }

    au32 sectAlign = pe.sectionAlign();
    au32 fileAlign = pe.fileAlign();
    if (sectAlign < 0x1000 || fileAlign == 0 || fileAlign > sectAlign || (sectAlign & (sectAlign - 1))) {
        st.error = "节对齐参数异常，无法处理";
        return false;
    }

    /* ---- 外壳：按目标架构选取 ---- */
    StubBlob stub;
    if (!loadStubBlob(opt.stubPath, stub, err, pe.is64)) { st.error = err; return false; }
    if (stub.is64 != pe.is64) { st.error = "外壳架构与目标不一致"; return false; }
    st.stubSize = (au32)stub.image.size();

    /* 特征库 */
    std::string sigText;
    std::string note;
    loadSignatureText(opt.sigFile, sigText, note);
    if (!note.empty()) st.warnings.push_back(note);
    std::vector<SigPattern> pats;
    std::string sigErr;
    sigParseText(sigText, pats, sigErr);
    if (!sigErr.empty()) st.warnings.push_back(sigErr);

    /* 扁平映像 */
    const IMAGE_SECTION_HEADER* rsrcSec = nullptr;
    bool keepRsrc = opt.keepRsrc;
    bool isDll = st.isDll;
    if (keepRsrc) {
        rsrcSec = pe.findSection(".rsrc");
        if (!rsrcSec) { keepRsrc = false; st.warnings.push_back("未找到 .rsrc 节，忽略 --keep-rsrc"); }
    }
    /* 需原样保留在外层的节（RVA 升序）。
       DLL 模式下 .rdata（导入/导出表）与 .reloc（重定位表）必须保留，
       因为加载器在调用 DllMain 之前就要解析它们，外壳来不及还原。 */
    std::vector<const IMAGE_SECTION_HEADER*> keepSecs;
    if (isDll) {
        const IMAGE_SECTION_HEADER* rdataSec = pe.findSection(".rdata");
        const IMAGE_SECTION_HEADER* relocSec = pe.findSection(".reloc");
        if (rdataSec) keepSecs.push_back(rdataSec);
        if (relocSec) keepSecs.push_back(relocSec);
    }
    if (keepRsrc && rsrcSec) keepSecs.push_back(rsrcSec);
    std::sort(keepSecs.begin(), keepSecs.end(),
              [](const IMAGE_SECTION_HEADER* a, const IMAGE_SECTION_HEADER* b) {
                  return a->VirtualAddress < b->VirtualAddress;
              });
    std::vector<au32> skipRvas;
    for (size_t i = 0; i < keepSecs.size(); i++) skipRvas.push_back(keepSecs[i]->VirtualAddress);
    std::vector<au8> flat = pe.buildFlatImage(skipRvas);
    if (flat.empty()) { st.error = "构建扁平映像失败"; return false; }
    st.unpackedSize = (au32)flat.size();
    st.keepRsrc = keepRsrc;

    /* 扫描 */
    std::vector<SigResult> results;
    sigScanImage(flat.data(), flat.size(), pats, results, 32);
    st.sigs = results;
    analyzeEpl(st);

    /* 特征隐藏 */
    std::vector<ARMOR_HIDE_ENT> hides;
    {
        std::vector<std::string> wanted;
        std::string mode = opt.hideFeatures;
        if (mode.empty()) mode = "auto";
        if (mode == "auto") {
            for (size_t i = 0; i < sizeof(kAutoHideNames) / sizeof(kAutoHideNames[0]); i++)
                wanted.push_back(kAutoHideNames[i]);
        } else if (mode != "none" && mode != "off" && mode != "0") {
            if (mode == "all") {
                for (size_t i = 0; i < pats.size(); i++) wanted.push_back(pats[i].name);
            } else {
                wanted = splitNames(mode);
            }
        }
        size_t totalBytes = 0;
        for (size_t i = 0; i < results.size() && hides.size() < 768; i++) {
            const SigResult& r = results[i];
            if (r.hitCount == 0) continue;
            if (!hideListHas(wanted, r.name)) continue;
            size_t patLen = pats[r.patternIndex].bytes.size();
            for (size_t h = 0; h < r.hits.size() && hides.size() < 768; h++) {
                au32 rva = r.hits[h];
                if (rva < 0x40) continue;
                if ((size_t)rva + patLen > flat.size()) continue;
                if (totalBytes + patLen > 262144u) break;
                hides.push_back(ARMOR_HIDE_ENT{ rva, (au32)patLen });
                totalBytes += patLen;
            }
        }
        /* 先写入的先加密，外壳按相反顺序解密 */
    }

    /* 载荷密钥 */
    au8 key[16];
    for (int i = 0; i < 16; i++) key[i] = (au8)(rndNext() & 0xFF);

    /* 应用特征加密 */
    for (size_t i = 0; i < hides.size(); i++) {
        au8 hk[16];
        ARMOR_RC4 rc4;
        armor_hide_key(hk, key, hides[i].rva, hides[i].len);
        armor_rc4_init(&rc4, hk, 16);
        armor_rc4_apply(&rc4, &flat[hides[i].rva], hides[i].len);
    }
    st.hiddenRegions = (au32)hides.size();
    for (size_t i = 0; i < hides.size(); i++) st.hiddenBytes += hides[i].len;

    /* 压缩 */
    size_t compCap = flat.size() + flat.size() / 8 + 512;
    std::vector<au8> comp;
    comp.assign(compCap, 0);
    std::vector<au8> scratch;
    scratch.assign(armor_compress_scratch(opt.level) + 16, 0);
    size_t compSize = armor_compress(flat.data(), flat.size(), comp.data(), compCap,
                                     opt.level, scratch.data(), scratch.size());
    if (compSize == 0 || compSize > compCap) { st.error = "压缩失败"; return false; }
    comp.resize(compSize);

    if (opt.encrypt) {
        ARMOR_RC4 rc4;
        armor_rc4_init(&rc4, key, 16);
        armor_rc4_apply(&rc4, comp.data(), comp.size());
    }
    st.payloadSize = (au32)comp.size();

    /* 统计原导入表 */
    countImports(pe, &st.importDllCount, &st.importFuncCount);

    const IMAGE_DATA_DIRECTORY& ddTls = pe.dir(IMAGE_DIRECTORY_ENTRY_TLS);
    const IMAGE_DATA_DIRECTORY& ddRel = pe.dir(IMAGE_DIRECTORY_ENTRY_BASERELOC);
    const IMAGE_DATA_DIRECTORY& ddRes = pe.dir(IMAGE_DIRECTORY_ENTRY_RESOURCE);
    st.hasTls = ddTls.VirtualAddress != 0 || ddTls.Size != 0;
    st.hasReloc = ddRel.VirtualAddress != 0 || ddRel.Size != 0;
    st.hasRsrc = ddRes.VirtualAddress != 0 || ddRes.Size != 0;

    /* TLS 原始数据 */
    std::vector<au8> tlsRaw;
    au32 tlsOrigIndexRva = 0;
    au32 tlsCallbackRva = 0;
    au32 tlsZeroFill = 0;
    au32 tlsCharacteristics = 0;
    bool hasTls = false;
    if (st.hasTls) {
        size_t dirSize = pe.is64 ? sizeof(IMAGE_TLS_DIRECTORY64) : sizeof(IMAGE_TLS_DIRECTORY32);
        bool ok = false;
        au32 off = pe.rvaToOffset(ddTls.VirtualAddress, (au32)dirSize, &ok);
        if (ok) {
            au64 imageBase = pe.imageBase();
            au64 rawStart = 0, rawEnd = 0, addrIndex = 0, addrCb = 0;
            if (pe.is64) {
                const IMAGE_TLS_DIRECTORY64* td = (const IMAGE_TLS_DIRECTORY64*)&pe.data[off];
                rawStart = td->StartAddressOfRawData;
                rawEnd = td->EndAddressOfRawData;
                addrIndex = td->AddressOfIndex;
                addrCb = td->AddressOfCallBacks;
                tlsZeroFill = td->SizeOfZeroFill;
                tlsCharacteristics = td->Characteristics;
            } else {
                const IMAGE_TLS_DIRECTORY32* td = (const IMAGE_TLS_DIRECTORY32*)&pe.data[off];
                rawStart = td->StartAddressOfRawData;
                rawEnd = td->EndAddressOfRawData;
                addrIndex = td->AddressOfIndex;
                addrCb = td->AddressOfCallBacks;
                tlsZeroFill = td->SizeOfZeroFill;
                tlsCharacteristics = td->Characteristics;
            }
            {
                au64 start = 0, end = 0;
                if (rawStart > imageBase) start = rawStart - imageBase;
                if (rawEnd > imageBase) end = rawEnd - imageBase;
                if (end > start && start < flat.size()) {
                    if (end > flat.size()) end = (au32)flat.size();
                    tlsRaw.assign(&flat[(size_t)start], &flat[(size_t)end]);
                }
            }
            if (addrIndex > imageBase) tlsOrigIndexRva = (au32)(addrIndex - imageBase);
            if (addrCb > imageBase) tlsCallbackRva = (au32)(addrCb - imageBase);
            hasTls = true;
        } else {
            st.warnings.push_back("TLS 目录无法解析，已忽略");
        }
    }

    /* 清单资源 */
    std::vector<au8> manifestBlob;
    if (opt.keepManifest && !keepRsrc) {
        au32 mrva = 0, msize = 0;
        au16 mid = 0, mlang = 0;
        if (pe.findManifest(&mrva, &msize, &mid, &mlang)) {
            bool ok = false;
            au32 moff = pe.rvaToOffset(mrva, msize, &ok);
            if (ok && msize && msize < 1u << 20) {
                /* baseRva 稍后确定，先占位 */
                manifestBlob.assign(msize, 0);
                memcpy(&manifestBlob[0], &pe.data[moff], msize);
                manifestBlob = buildManifestResource(&manifestBlob[0], msize, 0, mid, mlang);
            }
        }
    }

    /* ---------------------------------------------------------- 布局计算 */
    au32 origHdr = pe.sizeOfHeaders();
    au32 hdrBytes = 0x80 + 4 + 20 + pe.optHeaderSize() + 16 * 40;
    au32 packedHdr = armor_align_up(ARMOR_MAX(hdrBytes, 0x200u), fileAlign);
    au32 hdrRVA = armor_align_up(ARMOR_MAX(packedHdr, ARMOR_MAX(origHdr, 0x200u)), sectAlign);
    au32 span = armor_align_up(pe.imageSpan(), sectAlign);
    if (span < hdrRVA + 0x1000) span = hdrRVA + 0x1000;
    if (span > 512u * 1024 * 1024) { st.error = "目标映像过大"; return false; }
    au32 arm1RVA = armor_align_up(span, sectAlign);

    /* 需要还原的节区 */
    std::vector<ARMOR_SECTION> secEnts;
    for (int i = 0; i < pe.nsec; i++) {
        const IMAGE_SECTION_HEADER& s = pe.secs[i];
        au32 va = s.VirtualAddress;
        au32 vs = ARMOR_MAX(s.Misc.VirtualSize, s.SizeOfRawData);
        if (vs == 0 || va == 0) continue;
        if (va < hdrRVA) {
            st.warnings.push_back("节区 RVA 低于 PE 头区域，已跳过还原");
            continue;
        }
        if ((size_t)va + vs > flat.size()) vs = (au32)flat.size() - va;
        if (vs == 0) continue;
        au32 chars = s.Characteristics;
        for (size_t k = 0; k < keepSecs.size(); k++)
            if (keepSecs[k]->VirtualAddress == va) { chars = 0; break; } /* 保留节已就位，外壳无需还原 */
        secEnts.push_back(ARMOR_SECTION{ va, vs, chars });
    }
    st.sectionCount = (int)secEnts.size();

    /* arm1 内部布局 */
    size_t off = stub.image.size();
    off = (off + 15) & ~(size_t)15;
    size_t hdrOff = off;
    off += sizeof(ARMOR_HEADER);
    size_t secOff = off;
    off += secEnts.size() * sizeof(ARMOR_SECTION);
    size_t hideOff = off;
    off += hides.size() * sizeof(ARMOR_HIDE_ENT);
    off = (off + 15) & ~(size_t)15;
    size_t payloadOff = off;
    off += comp.size();
    off = (off + 3) & ~(size_t)3;
    /* 重定位表紧随载荷之后；原 DLL 重定位数据随后 */
    size_t tlsDirOff = 0;
    size_t tlsRawOff = 0;
    size_t tlsIndexOff = 0;
    {
        off = (off + 15) & ~(size_t)15;
        tlsDirOff = off;
        if (hasTls) off += pe.is64 ? sizeof(IMAGE_TLS_DIRECTORY64) : sizeof(IMAGE_TLS_DIRECTORY32);
        off = (off + 15) & ~(size_t)15;
        tlsRawOff = off;
        off += tlsRaw.size();
        off = (off + 3) & ~(size_t)3;
        tlsIndexOff = off;
        if (hasTls) off += 4;
        off = (off + 15) & ~(size_t)15;
    }
    size_t manifestOff = off;
    off += manifestBlob.size();
    size_t arm1ContentSize = off;

    /* 重定位表（stub 重定位 + 合成 TLS 目录的 VA 字段） */
    std::vector<au32> relocRvas;
    for (size_t i = 0; i < stub.relocs.size(); i++) relocRvas.push_back(stub.relocs[i]);
    if (hasTls) {
        /* 合成的 TLS 目录含绝对 VA，映像被重定位时加载器必须一并修正，
           否则 TLS 初始化会读到错误的地址。 */
        au32 type = pe.is64 ? ARMOR_RELOC_DIR64 : ARMOR_RELOC_HIGHLOW;
        au32 fieldOffs[3];
        tlsDirRelocOffsets(pe.is64, fieldOffs);
        for (int k = 0; k < 3; k++)
            relocRvas.push_back(ARMOR_RELOC_PACK(arm1RVA + (au32)tlsDirOff + fieldOffs[k], type));
    }
    std::vector<au8> relocTable = buildRelocTable(relocRvas);

    /* DLL：原重定位表数据也放进 .arm1，与 stub 重定位合并为一张表供加载器使用 */
    std::vector<au8> origReloc;
    if (isDll && ddRel.VirtualAddress && ddRel.Size && ddRel.Size < (1u << 20)) {
        bool rok = false;
        au32 ro = pe.rvaToOffset(ddRel.VirtualAddress, ddRel.Size, &rok);
        if (rok) {
            origReloc.assign(ddRel.Size, 0);
            memcpy(&origReloc[0], &pe.data[ro], ddRel.Size);
        }
    }
    au32 origRelocSize = (au32)origReloc.size();

    au32 relocSize = (au32)relocTable.size();
    size_t relocOffFinal = arm1ContentSize;
    size_t origRelocOff = relocOffFinal + relocTable.size();
    /* 重定位目录指向：优先 stub 表，没有则指向原 DLL 重定位数据 */
    au32 relocDirRva = 0;
    au32 relocDirSize = relocSize + origRelocSize;
    if (relocDirSize) {
        relocDirRva = arm1RVA + (au32)(relocSize ? relocOffFinal : origRelocOff);
    }

    au32 arm1Size = (au32)((arm1ContentSize + relocTable.size() + origRelocSize + 3) & ~(size_t)3);

    /* 输出节区：压缩区生成 .{prefix}0 段（虚拟映射，rawSize=0），
       保留节单独成节并写出原始数据（.rdata->.{prefix}d / .rsrc->.{prefix}r / .reloc->.{prefix}l） */
    std::vector<OutSection> outs;
    {
        au32 cursor = hdrRVA;
        for (size_t k = 0; k < keepSecs.size(); k++) {
            const IMAGE_SECTION_HEADER* kk = keepSecs[k];
            au32 krva = kk->VirtualAddress;
            au32 kvs = ARMOR_MAX(kk->Misc.VirtualSize, kk->SizeOfRawData);
            au32 kend = armor_align_up(krva + kvs, sectAlign);
            if (krva > cursor && krva < span) {
                OutSection s;
                memset(&s, 0, sizeof(s));
                setSectionName(s, makeSectionName(opt.sectionPrefix, '0'));
                s.va = cursor; s.vs = krva - cursor; s.rawSize = 0; s.rawPtr = 0;
                s.chars = 0xE0000060u;
                outs.push_back(s);
            }
            OutSection s;
            memset(&s, 0, sizeof(s));
            char ksuf = 'l'; /* .reloc 及其它 */
            if (strncmp((const char*)kk->Name, ".rdata", 6) == 0) ksuf = 'd';
            else if (strncmp((const char*)kk->Name, ".rsrc", 5) == 0) ksuf = 'r';
            setSectionName(s, makeSectionName(opt.sectionPrefix, ksuf));
            s.va = krva; s.vs = kvs; s.chars = kk->Characteristics;
            au32 copy = kk->SizeOfRawData;
            if (copy > kvs) copy = kvs;
            if ((size_t)kk->PointerToRawData + copy > pe.data.size())
                copy = (au32)pe.data.size() - kk->PointerToRawData;
            s.rawSize = armor_align_up(copy, fileAlign);
            s.rawPtr = 0; /* 稍后填 */
            s.srcRawOff = kk->PointerToRawData;
            s.srcRawSize = copy;
            outs.push_back(s);
            cursor = kend;
        }
        if (cursor < span) {
            OutSection s;
            memset(&s, 0, sizeof(s));
            setSectionName(s, makeSectionName(opt.sectionPrefix, '0'));
            s.va = cursor; s.vs = span - cursor; s.rawSize = 0; s.rawPtr = 0;
            s.chars = 0xE0000060u;
            outs.push_back(s);
        }
        OutSection s;
        memset(&s, 0, sizeof(s));
        setSectionName(s, makeSectionName(opt.sectionPrefix, '1'));
        s.va = arm1RVA; s.vs = arm1Size;
        s.rawSize = armor_align_up(arm1Size, fileAlign);
        s.rawPtr = hdrRVA;
        s.chars = 0x60000020u | (hasTls ? IMAGE_SCN_MEM_WRITE : 0u);
        outs.push_back(s);
    }

    au32 sizeOfImage = armor_align_up(arm1RVA + arm1Size, sectAlign);
    au32 fileHdrSize = hdrRVA;
    au32 arm1Raw = armor_align_up(arm1Size, fileAlign);
    au32 overlayOff = fileHdrSize + arm1Raw;
    for (size_t i = 0; i < outs.size(); i++) {
        if (outs[i].rawSize && outs[i].rawPtr == 0) {
            outs[i].rawPtr = overlayOff;
            overlayOff += outs[i].rawSize;
        }
    }

    std::vector<au8> out;
    out.assign((size_t)overlayOff + pe.overlaySize(), 0);

    /* arm1 内容 */
    {
        std::vector<au8> arm1;
        arm1.assign(arm1Size, 0);
        memcpy(&arm1[0], stub.image.data(), stub.image.size());

        /* 头部 */
        ARMOR_HEADER hdr;
        memset(&hdr, 0, sizeof(hdr));
        hdr.magic = ARMOR_MAGIC;
        hdr.version = ARMOR_VERSION;
        hdr.flags = 0;
        if (opt.encrypt) hdr.flags |= ARMOR_F_ENCRYPT;
        if (opt.antiDump) hdr.flags |= ARMOR_F_ANTIDUMP;
        if (opt.checkCrc) hdr.flags |= ARMOR_F_CHECK_CRC;
        if (!hides.empty()) hdr.flags |= ARMOR_F_HIDE_FEAT;
        if (keepRsrc) hdr.flags |= ARMOR_F_KEEP_RSRC;
        if (opt.antiDebug == 1) hdr.flags |= ARMOR_F_ANTIDBG_EXIT;
        if (opt.antiDebug == 2) hdr.flags |= ARMOR_F_ANTIDBG_FAKE;
        if (opt.antiDebugLevel >= 2) hdr.flags |= ARMOR_F_ANTIDBG_L2;
        if (isDll) hdr.flags |= ARMOR_F_IS_DLL;
        hdr.headerSize = (au32)sizeof(ARMOR_HEADER);
        hdr.imageBase = pe.imageBase();
        hdr.oepRva = pe.entryRva();
        hdr.headersSize = ARMOR_MIN(origHdr, hdrRVA);
        hdr.machine = pe.machine();
        hdr.is64 = pe.is64 ? 1u : 0u;
        hdr.sectionCount = (au32)secEnts.size();
        hdr.sectionsRva = arm1RVA + (au32)secOff;
        hdr.payloadRva = arm1RVA + (au32)payloadOff;
        hdr.payloadSize = (au32)comp.size();
        hdr.unpackedSize = (au32)flat.size();
        hdr.hideCount = (au32)hides.size();
        hdr.hideRva = hides.empty() ? 0 : (arm1RVA + (au32)hideOff);
        hdr.tlsIndexRva = hasTls ? (arm1RVA + (au32)tlsIndexOff) : 0;
        hdr.tlsOrigIndexRva = tlsOrigIndexRva;
        hdr.tlsCallbackRva = tlsCallbackRva;
        hdr.tlsRawRva = (hasTls && !tlsRaw.empty()) ? (arm1RVA + (au32)tlsRawOff) : 0;
        hdr.tlsRawSize = (au32)tlsRaw.size();
        hdr.tlsZeroFill = tlsZeroFill;
        hdr.payloadCrc = armor_crc32(comp.data(), comp.size());
        hdr.headerCrc = 0;
        memcpy(hdr.key, key, 16);
        hdr.headerCrc = armor_crc32(&hdr, sizeof(hdr));
        memcpy(&arm1[hdrOff], &hdr, sizeof(hdr));

        if (!secEnts.empty()) memcpy(&arm1[secOff], &secEnts[0], secEnts.size() * sizeof(ARMOR_SECTION));
        if (!hides.empty()) memcpy(&arm1[hideOff], &hides[0], hides.size() * sizeof(ARMOR_HIDE_ENT));
        memcpy(&arm1[payloadOff], comp.data(), comp.size());
        if (relocSize) memcpy(&arm1[relocOffFinal], relocTable.data(), relocTable.size());
        if (origRelocSize) memcpy(&arm1[origRelocOff], origReloc.data(), origReloc.size());

        if (hasTls) {
            au64 imageBase = pe.imageBase();
            if (pe.is64) {
                IMAGE_TLS_DIRECTORY64 td;
                memset(&td, 0, sizeof(td));
                td.StartAddressOfRawData = imageBase + arm1RVA + (au32)tlsRawOff;
                td.EndAddressOfRawData = td.StartAddressOfRawData + (au32)tlsRaw.size();
                td.AddressOfIndex = imageBase + arm1RVA + (au32)tlsIndexOff;
                td.AddressOfCallBacks = 0;
                td.SizeOfZeroFill = tlsZeroFill;
                td.Characteristics = tlsCharacteristics;
                memcpy(&arm1[tlsDirOff], &td, sizeof(td));
            } else {
                IMAGE_TLS_DIRECTORY32 td;
                memset(&td, 0, sizeof(td));
                td.StartAddressOfRawData = (au32)(imageBase + arm1RVA + (au32)tlsRawOff);
                td.EndAddressOfRawData = td.StartAddressOfRawData + (au32)tlsRaw.size();
                td.AddressOfIndex = (au32)(imageBase + arm1RVA + (au32)tlsIndexOff);
                td.AddressOfCallBacks = 0;
                td.SizeOfZeroFill = tlsZeroFill;
                td.Characteristics = tlsCharacteristics;
                memcpy(&arm1[tlsDirOff], &td, sizeof(td));
            }
            if (!tlsRaw.empty()) memcpy(&arm1[tlsRawOff], tlsRaw.data(), tlsRaw.size());
        }
        if (!manifestBlob.empty()) {
            /* 修正资源数据项的 OffsetToData，使其指向最终 RVA */
            au32 baseRva = arm1RVA + (au32)manifestOff;
            size_t offData = (sizeof(IMAGE_RESOURCE_DIRECTORY) + sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY)) * 3;
            IMAGE_RESOURCE_DATA_ENTRY* de = (IMAGE_RESOURCE_DATA_ENTRY*)&manifestBlob[offData];
            de->OffsetToData = baseRva + de->OffsetToData;
            memcpy(&arm1[manifestOff], manifestBlob.data(), manifestBlob.size());
        }

        memcpy(&out[fileHdrSize], arm1.data(), arm1.size());
    }

    /* 保留节原始数据（.rdata/.rsrc/.reloc 等） */
    for (size_t i = 0; i < outs.size(); i++) {
        if (outs[i].rawSize && outs[i].rawPtr && outs[i].srcRawSize && outs[i].srcRawOff) {
            au32 copy = outs[i].srcRawSize;
            if ((size_t)outs[i].srcRawOff + copy > pe.data.size())
                copy = (au32)pe.data.size() - outs[i].srcRawOff;
            if (copy) memcpy(&out[outs[i].rawPtr], &pe.data[outs[i].srcRawOff], copy);
        }
    }

    /* 附加数据（overlay） */
    if (pe.overlaySize()) {
        memcpy(&out[overlayOff], &pe.data[pe.overlayOffset()], pe.overlaySize());
    }

    /* 写入外壳参数 */
    {
        ARMOR_STUB_PARAMS* pp = (ARMOR_STUB_PARAMS*)&out[fileHdrSize + stub.paramRva];
        if (pp->magic[0] != ARMOR_STUB_MAGIC0 || pp->magic[1] != ARMOR_STUB_MAGIC1 ||
            pp->magic[2] != ARMOR_STUB_MAGIC2 || pp->magic[3] != ARMOR_STUB_MAGIC3) {
            st.error = "外壳参数节特征不匹配，请重新生成 stub_blob.h / stub_blob64.h";
            return false;
        }
        pp->headerRva = arm1RVA + (au32)hdrOff;
        pp->stubRva = arm1RVA;
    }

    /* 预修正外壳中的绝对地址，并把重定位项挂到打包后映像 */
    {
        au64 delta0 = (pe.imageBase() + arm1RVA) - stub.imageBase;
        for (size_t i = 0; i < stub.relocs.size(); i++) {
            au32 rva = ARMOR_RELOC_RVA(stub.relocs[i]);
            au32 type = ARMOR_RELOC_TYPE(stub.relocs[i]);
            size_t fo = (size_t)fileHdrSize + rva;
            if (fo + (type == ARMOR_RELOC_DIR64 ? 8u : 4u) > out.size()) continue;
            armor_reloc_apply(&out[fo], type, delta0);
        }
        /* 重定位表里的 RVA 需要加上 arm1RVA */
        if (relocSize) {
            size_t ro = (size_t)fileHdrSize + relocOffFinal;
            size_t left = relocSize;
            au8* p = &out[ro];
            while (left >= 8) {
                au32 page = armor_rd32(p);
                au32 blk = armor_rd32(p + 4);
                if (blk < 8 || blk > left) break;
                armor_wr32(p, page + arm1RVA);
                p += blk;
                left -= blk;
            }
        }
    }

    /* PE 头 */
    {
        IMAGE_DATA_DIRECTORY dirs[16];
        memset(dirs, 0, sizeof(dirs));
        if (isDll) {
            /* DLL：保留原导出/导入等目录（.rdata/.reloc 已保留在外层，RVA 有效），
               供加载器在调用 DllMain 之前解析；重定位/资源/TLS 另行处理 */
            for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
                if (i == IMAGE_DIRECTORY_ENTRY_BASERELOC) continue;
                if (i == IMAGE_DIRECTORY_ENTRY_RESOURCE) continue;
                if (i == IMAGE_DIRECTORY_ENTRY_TLS) continue;
                dirs[i] = pe.dir(i);
            }
        }
        if (relocDirSize) {
            /* 合并重定位表：stub 重定位 + 原 DLL 重定位（DLL 时） */
            dirs[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = relocDirRva;
            dirs[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = relocDirSize;
        }
        if (!manifestBlob.empty()) {
            dirs[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress = arm1RVA + (au32)manifestOff;
            dirs[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size = (au32)manifestBlob.size();
        } else if (keepRsrc && rsrcSec) {
            dirs[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress = rsrcSec->VirtualAddress;
            dirs[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size = rsrcSec->Misc.VirtualSize;
        }
        if (hasTls) {
            dirs[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = arm1RVA + (au32)tlsDirOff;
            dirs[IMAGE_DIRECTORY_ENTRY_TLS].Size =
                pe.is64 ? (au32)sizeof(IMAGE_TLS_DIRECTORY64) : (au32)sizeof(IMAGE_TLS_DIRECTORY32);
        }
        writePeHeaders(out, pe, outs, arm1RVA + stub.entryRva, sizeOfImage, fileHdrSize, dirs);
    }

    /* 写出文件 */
    {
        FILE* f = nullptr;
        if (_wfopen_s(&f, outPath.c_str(), L"wb") != 0 || !f) {
            st.error = "无法创建输出文件";
            return false;
        }
        if (!out.empty() && fwrite(out.data(), 1, out.size(), f) != out.size()) {
            fclose(f);
            st.error = "写文件失败";
            return false;
        }
        fclose(f);
    }

    st.outSize = (au64)out.size();
    st.imageBase = pe.imageBase();
    st.oepRva = pe.entryRva();
    st.ok = true;
    st.elapsedMs = (double)(GetTickCount() - t0);
    return true;
}

bool scanFile(const std::wstring& inPath, const PackOptions& opt, PackStats& st)
{
    std::string err;
    PEFile pe;
    st.inputUtf8 = wideToUtf8(inPath);
    if (!pe.load(inPath.c_str(), err)) { st.error = err; return false; }
    st.inSize = (au64)pe.data.size();

    st.is64 = pe.is64;
    st.machine = pe.machine();
    st.isDll = pe.isDll();
    if (pe.isDriver())     st.targetKind = "driver";
    else if (pe.isEfi())   st.targetKind = "efi";
    else                   st.targetKind = st.isDll ? "dll" : "exe";
    st.stubArch = pe.is64 ? "x64" : "x86";

    if (pe.isDotNet()) { st.error = "不支持 .NET 程序"; return false; }

    std::string sigText, note;
    loadSignatureText(opt.sigFile, sigText, note);
    if (!note.empty()) st.warnings.push_back(note);
    std::vector<SigPattern> pats;
    std::string sigErr;
    sigParseText(sigText, pats, sigErr);
    if (!sigErr.empty()) st.warnings.push_back(sigErr);

    std::vector<au32> noSkip;
    std::vector<au8> flat = pe.buildFlatImage(noSkip);
    std::vector<SigResult> results;
    sigScanImage(flat.data(), flat.size(), pats, results, 32);
    st.sigs = results;
    analyzeEpl(st);

    countImports(pe, &st.importDllCount, &st.importFuncCount);
    st.sectionCount = pe.nsec;
    st.imageBase = pe.imageBase();
    st.oepRva = pe.entryRva();
    st.unpackedSize = (au32)flat.size();
    st.hasTls = pe.dir(IMAGE_DIRECTORY_ENTRY_TLS).VirtualAddress != 0;
    st.hasReloc = pe.dir(IMAGE_DIRECTORY_ENTRY_BASERELOC).VirtualAddress != 0;
    st.hasRsrc = pe.dir(IMAGE_DIRECTORY_ENTRY_RESOURCE).VirtualAddress != 0;
    st.ok = true;
    return true;
}

/* --------------------------------------------------------- 一键解压还原 */

/* 扫描外壳节寻找 ARMOR_HEADER：用 magic/version/headerCrc/RVA 合理性排除假魔数 */
static bool findArmorHeader(const PEFile& pe, au32 arm1Rva, au32 arm1Raw, au32 arm1Size,
                            ARMOR_HEADER* outHdr)
{
    au32 maxOff = arm1Size;
    if (maxOff > sizeof(ARMOR_HEADER)) maxOff -= sizeof(ARMOR_HEADER);
    for (au32 off = 0; off <= maxOff; off += 4) {
        const ARMOR_HEADER* cand = (const ARMOR_HEADER*)&pe.data[arm1Raw + off];
        if (cand->magic != ARMOR_MAGIC) continue;
        if (cand->version != ARMOR_VERSION) continue;
        if (cand->headerSize < sizeof(ARMOR_HEADER)) continue;
        /* 载荷与节表 RVA 应落在外壳节内 */
        if (cand->payloadRva < arm1Rva) continue;
        if ((au64)cand->payloadRva - arm1Rva + cand->payloadSize > arm1Size) continue;
        if (cand->sectionsRva < arm1Rva) continue;
        if ((au64)cand->sectionsRva - arm1Rva + (au64)cand->sectionCount * sizeof(ARMOR_SECTION) > arm1Size) continue;
        if (cand->unpackedSize == 0 || cand->unpackedSize > 0x4000000u) continue;
        /* headerCrc 校验（headerCrc 字段本身置 0 后计算） */
        ARMOR_HEADER tmp = *cand;
        tmp.headerCrc = 0;
        if (armor_crc32(&tmp, sizeof(tmp)) != cand->headerCrc) continue;
        *outHdr = *cand;
        return true;
    }
    return false;
}

/* 节名是否匹配（strncmp 遇 '\0' 停止，安全处理 8 字节节名数组） */
static bool armorSecNameMatch(const char name[8], const char* want)
{
    return strncmp(name, want, 8) == 0;
}

bool unpackFile(const std::wstring& inPath, const std::wstring& outPath,
                const PackOptions& opt, PackStats& st)
{
    std::string err;
    PEFile pe;

    if (!pe.load(inPath.c_str(), err)) { st.error = err; return false; }
    st.inSize = (au64)pe.data.size();
    st.is64 = pe.is64;
    st.machine = pe.machine();
    st.isDll = pe.isDll();
    st.targetKind = st.isDll ? "dll" : "exe";
    st.stubArch = pe.is64 ? "x64" : "x86";

    if (!pe.isPackedByArmor(opt.sectionPrefix.c_str())) {
        /* 可能是自定义前缀加壳：自动探测任一含有效 ARMOR 头的节 */
        bool autoFound = false;
        for (int i = 0; i < pe.nsec && !autoFound; i++) {
            if (!pe.secs[i].SizeOfRawData) continue;
            au32 rva = pe.secs[i].VirtualAddress;
            au32 raw = pe.secs[i].PointerToRawData;
            au32 sz = pe.secs[i].SizeOfRawData;
            if ((au64)raw + sz > pe.data.size()) sz = (au32)(pe.data.size() - raw);
            ARMOR_HEADER th;
            if (findArmorHeader(pe, rva, raw, sz, &th)) autoFound = true;
        }
        if (!autoFound) {
            st.error = "输入不是 ARMOR 加壳产物（未识别到特征节）";
            return false;
        }
    }

    /* 定位外壳节：优先匹配当前/默认前缀；否则自动探测（扫描能通过 ARMOR 头校验的节） */
    std::string name1 = makeSectionName(opt.sectionPrefix, '1');
    std::string name1def = makeSectionName("arm", '1');
    const IMAGE_SECTION_HEADER* sec1 = nullptr;
    for (int i = 0; i < pe.nsec; i++) {
        if (armorSecNameMatch((const char*)pe.secs[i].Name, name1.c_str()) ||
            armorSecNameMatch((const char*)pe.secs[i].Name, name1def.c_str())) {
            sec1 = &pe.secs[i];
            break;
        }
    }
    if (!sec1 || !sec1->SizeOfRawData) {
        for (int i = 0; i < pe.nsec; i++) {
            if (!pe.secs[i].SizeOfRawData) continue;
            au32 rva = pe.secs[i].VirtualAddress;
            au32 raw = pe.secs[i].PointerToRawData;
            au32 sz = pe.secs[i].SizeOfRawData;
            if ((au64)raw + sz > pe.data.size()) sz = (au32)(pe.data.size() - raw);
            ARMOR_HEADER th;
            if (findArmorHeader(pe, rva, raw, sz, &th)) { sec1 = &pe.secs[i]; break; }
        }
    }
    if (!sec1 || !sec1->SizeOfRawData) { st.error = "未找到外壳节"; return false; }
    au32 arm1Rva = sec1->VirtualAddress;
    au32 arm1Raw = sec1->PointerToRawData;
    au32 arm1Size = sec1->SizeOfRawData;
    if ((au64)arm1Raw + arm1Size > pe.data.size())
        arm1Size = (au32)(pe.data.size() - arm1Raw);

    ARMOR_HEADER hdr;
    if (!findArmorHeader(pe, arm1Rva, arm1Raw, arm1Size, &hdr)) {
        st.error = "未找到有效的 ARMOR 头（产物损坏或非 ARMOR 加壳）";
        return false;
    }

    /* 载荷：CRC 校验 + RC4 解密 */
    au32 payloadOff = arm1Raw + (hdr.payloadRva - arm1Rva);
    std::vector<au8> payload(&pe.data[payloadOff], &pe.data[payloadOff] + hdr.payloadSize);
    if (hdr.flags & ARMOR_F_CHECK_CRC) {
        if (armor_crc32(payload.data(), payload.size()) != hdr.payloadCrc) {
            st.error = "载荷 CRC 校验失败（产物损坏）";
            return false;
        }
    }
    if (hdr.flags & ARMOR_F_ENCRYPT) {
        ARMOR_RC4 rc4;
        armor_rc4_init(&rc4, hdr.key, 16);
        armor_rc4_apply(&rc4, payload.data(), payload.size());
    }

    /* 解压为扁平映像（与原加载后内存布局一致） */
    std::vector<au8> flat(hdr.unpackedSize, 0);
    if (armor_decompress(payload.data(), payload.size(), flat.data(), flat.size()) != flat.size()) {
        st.error = "载荷解压失败（产物损坏）";
        return false;
    }

    /* 还原易语言特征区域（与外壳解包相反的顺序） */
    if ((hdr.flags & ARMOR_F_HIDE_FEAT) && hdr.hideCount && hdr.hideRva >= arm1Rva) {
        au32 hideOff = arm1Raw + (hdr.hideRva - arm1Rva);
        if ((au64)hideOff + (au64)hdr.hideCount * sizeof(ARMOR_HIDE_ENT) <= pe.data.size()) {
            const ARMOR_HIDE_ENT* ents = (const ARMOR_HIDE_ENT*)&pe.data[hideOff];
            for (au32 i = hdr.hideCount; i > 0; i--) {
                const ARMOR_HIDE_ENT* e = &ents[i - 1];
                if ((size_t)e->rva + (size_t)e->len <= flat.size()) {
                    au8 hk[16];
                    ARMOR_RC4 rc4;
                    armor_hide_key(hk, hdr.key, e->rva, e->len);
                    armor_rc4_init(&rc4, hk, 16);
                    armor_rc4_apply(&rc4, &flat[e->rva], e->len);
                }
            }
        }
    }

    /* 把保留节（chars==0：.rdata/.rsrc/.reloc 等）数据填回 flat 对应 RVA */
    if (hdr.sectionsRva >= arm1Rva && hdr.sectionCount) {
        au32 secOff = arm1Raw + (hdr.sectionsRva - arm1Rva);
        if ((au64)secOff + (au64)hdr.sectionCount * sizeof(ARMOR_SECTION) <= pe.data.size()) {
            const ARMOR_SECTION* secs = (const ARMOR_SECTION*)&pe.data[secOff];
            for (au32 i = 0; i < hdr.sectionCount; i++) {
                if (secs[i].chars != 0) continue; /* 仅保留节 */
                for (int j = 0; j < pe.nsec; j++) {
                    if (pe.secs[j].VirtualAddress != secs[i].rva) continue;
                    au32 copy = pe.secs[j].SizeOfRawData;
                    if (copy > secs[i].vsize) copy = secs[i].vsize;
                    if (copy && (size_t)secs[i].rva + copy <= flat.size()) {
                        au32 src = pe.secs[j].PointerToRawData;
                        if ((size_t)src + copy <= pe.data.size())
                            memcpy(&flat[secs[i].rva], &pe.data[src], copy);
                    }
                    break;
                }
            }
        }
    }

    /* 校验还原映像的 PE 有效性（同时判定它是 PE32 还是 PE32+） */
    if (flat.size() < sizeof(IMAGE_DOS_HEADER) + 4) { st.error = "还原映像无效"; return false; }
    const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)flat.data();
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { st.error = "还原映像无效（DOS 头）"; return false; }
    if ((size_t)dos->e_lfanew + 24u + 2u > flat.size()) {
        st.error = "还原映像无效（NT 头越界）";
        return false;
    }
    const au8* ntp = flat.data() + dos->e_lfanew;
    if (armor_rd32(ntp) != IMAGE_NT_SIGNATURE) { st.error = "还原映像无效（NT 头）"; return false; }
    {
        au16 optSize = armor_rd16(ntp + 20);
        bool is64 = (armor_rd16(ntp + 24) == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
        au32 ddOff = 24u + optSize;
        au32 needOpt = is64 ? 0x70u : 0x60u;
        if (optSize < needOpt || (size_t)dos->e_lfanew + ddOff > flat.size()) {
            st.error = "还原映像无效（可选头过小）";
            return false;
        }

        /* 重建文件：头部 + 各节（数据来自 flat 内存布局） */
        au32 nsec2 = armor_rd16(ntp + 6);
        const IMAGE_SECTION_HEADER* secTbl = (const IMAGE_SECTION_HEADER*)(ntp + ddOff);
        au32 hdrSize = armor_rd32(ntp + 24 + 0x3C); /* SizeOfHeaders（PE32/PE32+ 偏移相同） */
        if (hdrSize > flat.size()) hdrSize = (au32)flat.size();
        if (nsec2 == 0 || nsec2 > 96 ||
            (size_t)((const au8*)secTbl - flat.data()) + (size_t)nsec2 * sizeof(IMAGE_SECTION_HEADER) > hdrSize) {
            st.error = "还原映像无效（节表越界）";
            return false;
        }
        au64 imageBase = is64 ? armor_rd64(ntp + 24 + 0x18)
                              : (au64)armor_rd32(ntp + 24 + 0x1C);
        au32 oep = armor_rd32(ntp + 24 + 0x10);
        /* 数据目录项：ddOff + 8 * index（越界时按缺失处理） */
        bool ddOk = ((size_t)dos->e_lfanew + ddOff + 8u * IMAGE_NUMBEROF_DIRECTORY_ENTRIES) <= flat.size();

        au32 outSize = hdrSize;
        for (au32 i = 0; i < nsec2; i++) {
            au64 end = (au64)secTbl[i].PointerToRawData + secTbl[i].SizeOfRawData;
            if (end > outSize) outSize = (au32)end;
        }
        std::vector<au8> out(outSize, 0);
        memcpy(&out[0], flat.data(), hdrSize);
        for (au32 i = 0; i < nsec2; i++) {
            const IMAGE_SECTION_HEADER& s = secTbl[i];
            au32 vs = ARMOR_MAX(s.Misc.VirtualSize, s.SizeOfRawData);
            au32 copy = s.SizeOfRawData;
            if (copy > vs) copy = vs;
            if (copy == 0) continue;
            if (s.VirtualAddress >= flat.size()) continue;
            if ((size_t)s.VirtualAddress + copy > flat.size())
                copy = (au32)(flat.size() - s.VirtualAddress);
            if ((size_t)s.PointerToRawData + copy > out.size())
                copy = (au32)(out.size() - s.PointerToRawData);
            if (copy) memcpy(&out[s.PointerToRawData], &flat[s.VirtualAddress], copy);
        }

        /* 写出文件 */
        {
            FILE* f = nullptr;
            if (_wfopen_s(&f, outPath.c_str(), L"wb") != 0 || !f) {
                st.error = "无法创建输出文件";
                return false;
            }
            if (fwrite(out.data(), 1, out.size(), f) != out.size()) {
                fclose(f);
                st.error = "写文件失败";
                return false;
            }
            fclose(f);
        }

        st.outSize = (au64)out.size();
        st.unpackedSize = (au32)flat.size();
        st.payloadSize = hdr.payloadSize;
        st.imageBase = imageBase;
        st.oepRva = oep;
        st.sectionCount = (int)nsec2;
        st.is64 = is64;
        st.machine = armor_rd16(ntp + 4);
        st.hasTls = ddOk && armor_rd32(ntp + ddOff + 8u * IMAGE_DIRECTORY_ENTRY_TLS) != 0;
        st.hasReloc = ddOk && armor_rd32(ntp + ddOff + 8u * IMAGE_DIRECTORY_ENTRY_BASERELOC) != 0;
        st.hasRsrc = ddOk && armor_rd32(ntp + ddOff + 8u * IMAGE_DIRECTORY_ENTRY_RESOURCE) != 0;
        st.hiddenRegions = hdr.hideCount;
        st.isDll = (armor_rd16(ntp + 22) & IMAGE_FILE_DLL) != 0;
        st.targetKind = st.isDll ? "dll" : "exe";
        st.ok = true;
        return true;
    }
}
