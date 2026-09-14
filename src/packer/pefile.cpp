#include "pefile.h"

#include <stdio.h>

/* ------------------------------------------------------------ 形态判定 */

PeKind peKindOf(const au8* data, size_t size, au16* machine)
{
    au32 lfa;

    if (machine) *machine = 0;
    if (!data) return PeKind::Unknown;
    if (size < 2 || data[0] != 'M' || data[1] != 'Z') return PeKind::NotPe;
    if (size < 0x40) return PeKind::DosMz;

    lfa = armor_rd32(data + 0x3C);
    if (lfa >= 0x40 && (size_t)lfa + 24u <= size) {
        const au8* nt = data + lfa;
        if (armor_rd32(nt) == IMAGE_NT_SIGNATURE) {
            au16 mach = armor_rd16(nt + 4);
            au16 optSize = armor_rd16(nt + 20);
            au32 needOpt;
            if (machine) *machine = mach;
            if ((size_t)lfa + 26u > size) return PeKind::PeOtherArch;
            au16 magic = armor_rd16(nt + 24);
            needOpt = (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) ? 0x70u : 0x60u;
            if ((size_t)lfa + 24u + (size_t)optSize > size || optSize < needOpt)
                return PeKind::PeOtherArch;
            if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
                return (mach == IMAGE_FILE_MACHINE_I386) ? PeKind::Pe32 : PeKind::PeOtherArch;
            if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                return (mach == IMAGE_FILE_MACHINE_AMD64) ? PeKind::Pe32Plus : PeKind::PeOtherArch;
            return PeKind::PeOtherArch;
        }
        if (nt[0] == 'N' && nt[1] == 'E') return PeKind::Ne;
        if (nt[0] == 'L' && nt[1] == 'E') return PeKind::Ne; /* OS/2 / VxD 线性可执行 */
    }
    return PeKind::DosMz;
}

const char* peKindName(PeKind k)
{
    switch (k) {
    case PeKind::NotPe:       return "非 PE 映像";
    case PeKind::DosMz:       return "16 位 DOS MZ 映像（无 PE 头）";
    case PeKind::Ne:          return "16 位 Windows NE 映像";
    case PeKind::Pe32:        return "PE32（x86, 32 位）";
    case PeKind::Pe32Plus:    return "PE32+（x64, 64 位）";
    case PeKind::PeOtherArch: return "其它机器类型的 PE";
    default:                  return "未知格式";
    }
}

/* ---------------------------------------------------------------- 载入 */

bool PEFile::load(const wchar_t* path, std::string& err)
{
    FILE* f = nullptr;
    long size = 0;

    if (_wfopen_s(&f, path, L"rb") != 0 || !f) {
        err = "无法打开输入文件";
        return false;
    }
    fseek(f, 0, SEEK_END);
    size = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (size < 0 || size > 1024L * 1024 * 1024) {
        fclose(f);
        err = "输入文件大小异常";
        return false;
    }
    data.assign((size_t)size, 0);
    if (size > 0 && fread(&data[0], 1, (size_t)size, f) != (size_t)size) {
        fclose(f);
        err = "读取输入文件失败";
        return false;
    }
    fclose(f);
    return parse(err);
}

bool PEFile::parse(std::string& err)
{
    au16 mach = 0;
    au32 lfa, optSize, secOff, needOpt;

    dos = nullptr;
    nt = nullptr;
    secs = nullptr;
    nsec = 0;
    is64 = false;

    if (data.empty()) {
        err = "输入文件为空";
        return false;
    }

    switch (peKindOf(&data[0], data.size(), &mach)) {
    case PeKind::Pe32:     is64 = false; break;
    case PeKind::Pe32Plus: is64 = true;  break;
    case PeKind::PeOtherArch: {
        char buf[128];
        sprintf_s(buf, "不支持的 PE 机器类型 0x%04X（本项目支持 x86=0x014C / x64=0x8664）",
                  (unsigned)mach);
        err = buf;
        return false;
    }
    case PeKind::Ne:
        err = "不支持 16 位 Windows NE 映像（Win3.x），无法加壳";
        return false;
    case PeKind::DosMz:
        err = "16 位 DOS MZ 映像（无 PE 头），无法加壳";
        return false;
    case PeKind::NotPe:
        err = "不是有效的 PE 映像（16 位 DOS COM / ELF / 脚本 / 数据文件均无法加壳）";
        return false;
    default:
        err = "无法识别的文件格式";
        return false;
    }

    dos = (IMAGE_DOS_HEADER*)&data[0];
    lfa = (au32)dos->e_lfanew;
    nt = (void*)(&data[0] + lfa);

    optSize = armor_rd16((const au8*)nt + 20);
    needOpt = is64 ? 0x70u : 0x60u; /* 至少覆盖到 DataDirectory 起点 */
    if (optSize < needOpt) {
        err = "可选头过小，缺少完整数据目录";
        return false;
    }
    nsec = (int)armor_rd16((const au8*)nt + 6);
    secOff = lfa + 24u + (au32)optSize;
    if (nsec <= 0 || nsec > 96) {
        err = "节数量异常";
        return false;
    }
    if ((size_t)secOff + (size_t)nsec * sizeof(IMAGE_SECTION_HEADER) > data.size()) {
        err = "节表越界";
        return false;
    }
    secs = (IMAGE_SECTION_HEADER*)(&data[0] + secOff);
    return true;
}

/* ------------------------------------------------------- 字段统一访问 */

au16 PEFile::machine() const           { return armor_rd16((const au8*)nt + 4); }
au16 PEFile::characteristics() const   { return nt64() ? nt64()->FileHeader.Characteristics
                                                       : nt32()->FileHeader.Characteristics; }

const IMAGE_DATA_DIRECTORY& PEFile::dir(int index) const
{
    static const IMAGE_DATA_DIRECTORY zero = { 0, 0 };
    const au8* opt;
    const IMAGE_DATA_DIRECTORY* dd;

    if (!nt || index < 0 || index >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) return zero;
    opt = (const au8*)nt + 24;
    dd = (const IMAGE_DATA_DIRECTORY*)(opt + (is64 ? 0x70u : 0x60u));
    return dd[index];
}

au16 PEFile::subsystem() const
{
    return nt64() ? nt64()->OptionalHeader.Subsystem : nt32()->OptionalHeader.Subsystem;
}

au16 PEFile::dllCharacteristics() const
{
    return nt64() ? nt64()->OptionalHeader.DllCharacteristics
                  : nt32()->OptionalHeader.DllCharacteristics;
}

au64 PEFile::imageBase() const
{
    return nt64() ? nt64()->OptionalHeader.ImageBase : (au64)nt32()->OptionalHeader.ImageBase;
}

au32 PEFile::entryRva() const
{
    return nt64() ? nt64()->OptionalHeader.AddressOfEntryPoint
                  : nt32()->OptionalHeader.AddressOfEntryPoint;
}

au32 PEFile::sizeOfHeaders() const
{
    return nt64() ? nt64()->OptionalHeader.SizeOfHeaders : nt32()->OptionalHeader.SizeOfHeaders;
}

au32 PEFile::sizeOfImage() const
{
    return nt64() ? nt64()->OptionalHeader.SizeOfImage : nt32()->OptionalHeader.SizeOfImage;
}

au32 PEFile::sectionAlign() const
{
    return nt64() ? nt64()->OptionalHeader.SectionAlignment : nt32()->OptionalHeader.SectionAlignment;
}

au32 PEFile::fileAlign() const
{
    return nt64() ? nt64()->OptionalHeader.FileAlignment : nt32()->OptionalHeader.FileAlignment;
}

au32 PEFile::optHeaderSize() const
{
    return is64 ? (au32)sizeof(IMAGE_OPTIONAL_HEADER64) : (au32)sizeof(IMAGE_OPTIONAL_HEADER32);
}

/* --------------------------------------------------------------- 分类 */

PeKind PEFile::kind() const
{
    if (!nt) return PeKind::Unknown;
    return is64 ? PeKind::Pe32Plus : PeKind::Pe32;
}

/* Native 子系统：内核驱动（.sys）与原生程序（如 autochk.exe），
   均不使用 Win32 子系统，用户态外壳无法在其中运行。 */
bool PEFile::isDriver() const
{
    return nt && subsystem() == IMAGE_SUBSYSTEM_NATIVE;
}

bool PEFile::isEfi() const
{
    if (!nt) return false;
    switch (subsystem()) {
    case IMAGE_SUBSYSTEM_EFI_APPLICATION:
    case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
    case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
    case IMAGE_SUBSYSTEM_EFI_ROM:
        return true;
    default:
        return false;
    }
}

PeTarget PEFile::target() const
{
    if (!nt) return PeTarget::None;
    if (isDriver()) return PeTarget::Driver;
    if (isEfi())    return PeTarget::Efi;
    return isDll() ? PeTarget::Dll : PeTarget::Exe;
}

bool PEFile::isDotNet() const
{
    const IMAGE_DATA_DIRECTORY& dd = dir(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR);
    return dd.VirtualAddress != 0 || dd.Size != 0;
}

bool PEFile::isPackedByArmor(const char* prefix) const
{
    /* 同时检测当前前缀与默认前缀 arm，避免换前缀后漏判重复加壳 */
    const char* prefixes[2] = { prefix, "arm" };
    for (int p = 0; p < 2; p++) {
        char n0[9], n1[9];
        snprintf(n0, sizeof(n0), ".%s0", prefixes[p]);
        snprintf(n1, sizeof(n1), ".%s1", prefixes[p]);
        for (int i = 0; i < nsec; i++) {
            if (strncmp((const char*)secs[i].Name, n0, 8) == 0) return true;
            if (strncmp((const char*)secs[i].Name, n1, 8) == 0) return true;
        }
    }
    return false;
}

/* --------------------------------------------------------------- 节区 */

const IMAGE_SECTION_HEADER* PEFile::findSection(const char* name) const
{
    for (int i = 0; i < nsec; i++)
        if (strncmp((const char*)secs[i].Name, name, 8) == 0) return &secs[i];
    return nullptr;
}

au32 PEFile::rvaToOffset(au32 rva, au32 len, bool* ok) const
{
    if (ok) *ok = false;
    if (rva == 0) return 0;
    for (int i = 0; i < nsec; i++) {
        au32 va = secs[i].VirtualAddress;
        au32 vs = secs[i].Misc.VirtualSize;
        au32 rs = secs[i].SizeOfRawData;
        au32 span = vs ? vs : rs;
        if (rva >= va && rva < va + span) {
            au32 delta = rva - va;
            if (delta + len > rs) return 0;
            if ((size_t)secs[i].PointerToRawData + delta + len > data.size()) return 0;
            if (ok) *ok = true;
            return secs[i].PointerToRawData + delta;
        }
    }
    return 0;
}

au32 PEFile::imageSpan() const
{
    au32 span = sizeOfHeaders();
    for (int i = 0; i < nsec; i++) {
        au32 va = secs[i].VirtualAddress;
        au32 vs = secs[i].Misc.VirtualSize;
        au32 rs = secs[i].SizeOfRawData;
        au32 end = va + ARMOR_MAX(vs, rs);
        if (end > span) span = end;
    }
    return span;
}

au32 PEFile::rawEnd() const
{
    au32 end = sizeOfHeaders();
    for (int i = 0; i < nsec; i++) {
        if (secs[i].SizeOfRawData == 0) continue;
        au32 e = secs[i].PointerToRawData + secs[i].SizeOfRawData;
        if (e > end) end = e;
    }
    return end;
}

au32 PEFile::overlayOffset() const
{
    au32 e = rawEnd();
    if (e > data.size()) e = (au32)data.size();
    return e;
}

au32 PEFile::overlaySize() const
{
    au32 off = overlayOffset();
    return (au32)data.size() - off;
}

std::vector<au8> PEFile::buildFlatImage(const std::vector<au32>& skipRvas) const
{
    au32 span = imageSpan();
    std::vector<au8> img;
    img.assign(span, 0);

    au32 hdrSize = sizeOfHeaders();
    if (hdrSize > span) hdrSize = span;
    if (hdrSize) memcpy(&img[0], &data[0], hdrSize);

    for (int i = 0; i < nsec; i++) {
        const IMAGE_SECTION_HEADER& s = secs[i];
        bool skip = false;
        for (size_t k = 0; k < skipRvas.size(); k++)
            if (skipRvas[k] == s.VirtualAddress) { skip = true; break; }
        if (skip) continue;
        au32 va = s.VirtualAddress;
        au32 rs = s.SizeOfRawData;
        au32 vs = s.Misc.VirtualSize;
        au32 span2 = ARMOR_MAX(vs, rs);
        au32 copy = rs;
        if (copy > span2) copy = span2;
        if (va >= span) continue;
        if ((size_t)va + copy > span) copy = span - va;
        if ((size_t)s.PointerToRawData + copy > data.size())
            copy = (au32)(data.size() - s.PointerToRawData);
        if (copy) memcpy(&img[va], &data[s.PointerToRawData], copy);
    }
    return img;
}

/* ----------------------------------------------------------- 资源解析 */

namespace {

struct ResWalk {
    const std::vector<au8>* file;
    int nsec;
    const IMAGE_SECTION_HEADER* secs;

    const au8* at(au32 rva, au32 need) const
    {
        for (int i = 0; i < nsec; i++) {
            au32 va = secs[i].VirtualAddress;
            au32 span = ARMOR_MAX(secs[i].Misc.VirtualSize, secs[i].SizeOfRawData);
            if (rva >= va && rva < va + span) {
                au32 delta = rva - va;
                if (delta + need > secs[i].SizeOfRawData) return nullptr;
                if ((size_t)secs[i].PointerToRawData + delta + need > file->size()) return nullptr;
                return &(*file)[secs[i].PointerToRawData + delta];
            }
        }
        return nullptr;
    }
};

const IMAGE_RESOURCE_DIRECTORY_ENTRY* resFindEntry(const ResWalk& w,
                                                   const IMAGE_RESOURCE_DIRECTORY* dir,
                                                   au32 id)
{
    au32 n = dir->NumberOfNamedEntries + dir->NumberOfIdEntries;
    const IMAGE_RESOURCE_DIRECTORY_ENTRY* ents =
        (const IMAGE_RESOURCE_DIRECTORY_ENTRY*)((const au8*)dir + sizeof(IMAGE_RESOURCE_DIRECTORY));
    for (au32 i = 0; i < n; i++) {
        if (!ents[i].NameIsString && ents[i].Id == id) return &ents[i];
    }
    return nullptr;
}

} /* namespace */

bool PEFile::findManifest(au32* outRva, au32* outSize, au16* outResId, au16* outLangId) const
{
    const IMAGE_DATA_DIRECTORY& dd = dir(IMAGE_DIRECTORY_ENTRY_RESOURCE);
    *outRva = 0;
    *outSize = 0;
    if (outResId) *outResId = 0;
    if (outLangId) *outLangId = 0;
    if (!dd.VirtualAddress || !dd.Size) return false;

    ResWalk w;
    w.file = &data;
    w.nsec = nsec;
    w.secs = secs;

    const IMAGE_RESOURCE_DIRECTORY* typeDir =
        (const IMAGE_RESOURCE_DIRECTORY*)w.at(dd.VirtualAddress, sizeof(IMAGE_RESOURCE_DIRECTORY));
    if (!typeDir) return false;

    /* RT_MANIFEST 是 MAKEINTRESOURCE(24)，x64 下为指针宽度，需屏蔽高位再取低 16 位 */
    const IMAGE_RESOURCE_DIRECTORY_ENTRY* typeEnt =
        resFindEntry(w, typeDir, (au32)((size_t)RT_MANIFEST & 0xFFFFu));
    if (!typeEnt || !typeEnt->DataIsDirectory) return false;

    const IMAGE_RESOURCE_DIRECTORY* nameDir =
        (const IMAGE_RESOURCE_DIRECTORY*)w.at(dd.VirtualAddress + typeEnt->OffsetToDirectory,
                                              sizeof(IMAGE_RESOURCE_DIRECTORY));
    if (!nameDir) return false;
    if (nameDir->NumberOfIdEntries == 0) return false;

    /* 取第一个 ID 条目 */
    {
        const IMAGE_RESOURCE_DIRECTORY_ENTRY* ents =
            (const IMAGE_RESOURCE_DIRECTORY_ENTRY*)((const au8*)nameDir + sizeof(IMAGE_RESOURCE_DIRECTORY));
        const IMAGE_RESOURCE_DIRECTORY_ENTRY* nameEnt = nullptr;
        au32 total = nameDir->NumberOfNamedEntries + nameDir->NumberOfIdEntries;
        for (au32 i = 0; i < total; i++) {
            if (!ents[i].NameIsString) { nameEnt = &ents[i]; break; }
        }
        if (!nameEnt || !nameEnt->DataIsDirectory) return false;
        if (outResId) *outResId = (au16)nameEnt->Id;

        const IMAGE_RESOURCE_DIRECTORY* langDir =
            (const IMAGE_RESOURCE_DIRECTORY*)w.at(dd.VirtualAddress + nameEnt->OffsetToDirectory,
                                                  sizeof(IMAGE_RESOURCE_DIRECTORY));
        if (!langDir) return false;
        {
            const IMAGE_RESOURCE_DIRECTORY_ENTRY* lents =
                (const IMAGE_RESOURCE_DIRECTORY_ENTRY*)((const au8*)langDir + sizeof(IMAGE_RESOURCE_DIRECTORY));
            au32 ltotal = langDir->NumberOfNamedEntries + langDir->NumberOfIdEntries;
            if (ltotal == 0) return false;
            for (au32 i = 0; i < ltotal; i++) {
                if (!lents[i].DataIsDirectory) {
                    const IMAGE_RESOURCE_DATA_ENTRY* dat =
                        (const IMAGE_RESOURCE_DATA_ENTRY*)w.at(dd.VirtualAddress + lents[i].OffsetToData,
                                                               sizeof(IMAGE_RESOURCE_DATA_ENTRY));
                    if (!dat || dat->Size == 0) continue;
                    *outRva = dat->OffsetToData;
                    *outSize = dat->Size;
                    if (outLangId) *outLangId = (au16)lents[i].Id;
                    return true;
                }
            }
        }
    }
    return false;
}
