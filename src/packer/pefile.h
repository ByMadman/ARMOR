#ifndef ARMOR_PEFILE_H
#define ARMOR_PEFILE_H

/* PE 文件读取与基本分析（仅打包器使用）。
   同时支持 PE32（x86）与 PE32+（x64）：解析按映像自带的 OptionalHeader.Magic
   分派，与打包器自身编译为 Win32 还是 x64 无关。
   文件类型一律按格式判定，不看扩展名。 */

#include "../common/armor_base.h"

#include <windows.h>

#include <string>
#include <vector>

/* 输入文件的形态（用于给出精确的错误提示） */
enum class PeKind {
    Unknown,    /* 数据不足，无法判定 */
    NotPe,      /* 连 MZ 都没有：16 位 DOS COM、ELF、脚本、数据文件等 */
    DosMz,      /* 有 MZ 但无有效 PE 签名：16 位 DOS EXE / 纯 DOS 存根 */
    Ne,         /* 16 位 Windows NE（Win3.x） */
    Pe32,       /* 32 位 PE（x86） */
    Pe32Plus,   /* 64 位 PE（x64） */
    PeOtherArch /* 其它机器类型的 PE（ARM / ARM64 / IA64 等） */
};

/* 仅凭文件头判定形态，不做完整解析（用于失败时给出可读诊断） */
PeKind peKindOf(const au8* data, size_t size, au16* machine = nullptr);

const char* peKindName(PeKind k);

/* 目标类别（决定产物按 EXE 还是 DLL 语义处理） */
enum class PeTarget {
    None,
    Exe,
    Dll,
    Driver, /* 内核态映像（.sys / Native subsystem） */
    Efi     /* 固件映像 */
};

struct PEFile {
    std::vector<au8> data;

    IMAGE_DOS_HEADER* dos = nullptr;
    void* nt = nullptr; /* IMAGE_NT_HEADERS32* 或 IMAGE_NT_HEADERS64*，按 is64 解释 */
    IMAGE_SECTION_HEADER* secs = nullptr;
    int nsec = 0;
    bool is64 = false;

    bool load(const wchar_t* path, std::string& err);
    bool parse(std::string& err); /* 在已有 data 上做解析 */

    IMAGE_NT_HEADERS32* nt32() const { return is64 ? nullptr : (IMAGE_NT_HEADERS32*)nt; }
    IMAGE_NT_HEADERS64* nt64() const { return is64 ? (IMAGE_NT_HEADERS64*)nt : nullptr; }

    /* ---- 统一字段访问（屏蔽 PE32 / PE32+ 差异） ---- */
    au16 machine() const;
    au16 characteristics() const;
    au16 subsystem() const;
    au16 dllCharacteristics() const;
    au64 imageBase() const;
    au32 entryRva() const;
    au32 sizeOfHeaders() const;
    au32 sizeOfImage() const;
    au32 sectionAlign() const;
    au32 fileAlign() const;
    au32 optHeaderSize() const;
    const IMAGE_DATA_DIRECTORY& dir(int index) const;

    /* ---- 分类 ---- */
    PeKind   kind() const;
    PeTarget target() const;
    bool     isDll() const    { return (characteristics() & IMAGE_FILE_DLL) != 0; }
    bool     isDriver() const; /* Native 子系统（内核驱动 .sys） */
    bool     isEfi() const;    /* EFI 固件映像 */
    bool     isDotNet() const;
    bool     isPackedByArmor(const char* prefix) const;

    /* ---- 节区 ---- */
    const IMAGE_SECTION_HEADER* findSection(const char* name) const;

    au32 rvaToOffset(au32 rva, au32 len, bool* ok = nullptr) const;
    au32 imageSpan() const;  /* 实际需要的映像跨度（按节区计算，按 SectionAlignment 对齐） */
    au32 rawEnd() const;     /* 文件中最后一个节区原始数据的结束位置 */
    au32 overlayOffset() const;
    au32 overlaySize() const;

    /* 构建扁平映像（等价于加载后的内存布局）。
       skipRvas 非空时，这些 RVA 对应的节内容不写入（资源/导入导出/重定位等需要保留在外层的节）。 */
    std::vector<au8> buildFlatImage(const std::vector<au32>& skipRvas) const;

    /* 查找 RT_MANIFEST 资源数据，返回 RVA/大小以及资源 ID 与语言 ID */
    bool findManifest(au32* rva, au32* size, au16* resId, au16* langId) const;
};

#endif /* ARMOR_PEFILE_H */
