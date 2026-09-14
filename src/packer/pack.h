#ifndef ARMOR_PACK_H
#define ARMOR_PACK_H

#include "../common/armor_base.h"
#include "../common/sig.h"

#include <string>
#include <vector>

/* 打包选项 */
struct PackOptions {
    int  level = 6;          /* 压缩级别 1..9 */
    bool encrypt = true;     /* 载荷加密 */
    int  antiDebug = 1;      /* 0=关闭 1=检测到退出 2=检测到后行为异常 */
    int  antiDebugLevel = 1; /* 1=基础 2=增强（窗口/进程名/计时） */
    bool antiDump = true;    /* 还原后混淆 PE 头 */
    bool keepManifest = true;/* 保留清单资源，保证激活上下文/权限/视觉样式正常 */
    bool keepRsrc = true;    /* 资源节不压缩（保留图标/版本版权等，但体积更大）；可用 --keep-rsrc=0 关闭 */
    bool checkCrc = true;    /* 解包前校验载荷 CRC */
    bool force = false;      /* 忽略"已加壳"等告警 */
    bool allowDll = false;   /* 允许处理 DLL（导入/导出/重定位表原样保留） */
    std::string hideFeatures = "auto"; /* auto | none | all | 名称;名称 */
    std::string sigFile;               /* 外部特征文件，空=自动查找 */
    std::string stubPath;              /* 外部 Stub 映像，空=使用内嵌版本；其架构必须与目标一致 */
    au32 seed = 0;                     /* 随机种子，0=自动 */
    std::string sectionPrefix = "arm"; /* 产物 PE 节名前缀（.arm0/.armr/.arm1 中的 arm），1..6 个字母数字 */
    bool unpack = false;               /* 解压还原模式：对已加壳产物做一键解压还原（--unpack / 配置 unpack=1） */
};

/* 打包结果（供命令行输出 / JSON） */
struct PackStats {
    bool ok = false;
    std::string error;

    std::string inputUtf8;
    std::string outputUtf8;

    au64 inSize = 0;
    au64 outSize = 0;
    au32 unpackedSize = 0;
    au32 payloadSize = 0;
    au64 imageBase = 0;
    au32 oepRva = 0;
    au32 stubSize = 0;

    /* 目标形态（按 PE 格式判定，与扩展名无关） */
    bool is64 = false;      /* PE32+（x64） */
    au32 machine = 0;       /* IMAGE_FILE_MACHINE_* */
    bool isDll = false;     /* Characteristics 含 IMAGE_FILE_DLL */
    std::string targetKind; /* "exe" / "dll"，供展示 */
    std::string stubArch;   /* 实际选用的外壳："x86" / "x64" */

    int  sectionCount = 0;
    int  importDllCount = 0;
    int  importFuncCount = 0;

    bool hasTls = false;
    bool hasReloc = false;
    bool hasRsrc = false;
    bool keepRsrc = false;

    bool isEpl = false;
    std::string eplKind;

    std::vector<SigResult> sigs;
    au32 hiddenRegions = 0;
    au32 hiddenBytes = 0;

    std::vector<std::string> warnings;
    double elapsedMs = 0;
};

/* 执行打包：自动按目标架构（x86/x64）与类型（EXE/DLL）选择外壳与产物格式。
   输入/输出路径使用宽字符（支持中文路径）。 */
bool packFile(const std::wstring& inPath, const std::wstring& outPath,
              const PackOptions& opt, PackStats& st);

/* 一键解压还原：输入为 ARMOR 加壳产物（x86/x64 EXE/DLL），还原出原始文件。
   与 packFile 同一入口（opt.unpack=true 时 packFile 转调本函数）。 */
bool unpackFile(const std::wstring& inPath, const std::wstring& outPath,
                const PackOptions& opt, PackStats& st);

/* 仅做扫描分析，不写文件 */
bool scanFile(const std::wstring& inPath, const PackOptions& opt, PackStats& st);

#endif /* ARMOR_PACK_H */
