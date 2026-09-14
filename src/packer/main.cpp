/* ARMOR 保护壳 命令行工具
 *
 * 用法:
 *   ArmorCLI pack <输入> <输出> [选项]
 *   ArmorCLI scan <输入> [选项]
 *   ArmorCLI version
 *   ArmorCLI help
 */

#include "pack.h"
#include "utf8util.h"

#include "../common/armor_version.h"

#include <windows.h>

#include <stdarg.h>
#include <stdio.h>
#include <string>
#include <vector>

namespace {

void printUsage(void)
{
    printf(
        "ARMOR 软件保护壳 v%s   作者: %s QQ群: %s\n"
        "\n"
        "支持: x86 (PE32) 与 x64 (PE32+) 的 EXE / DLL；按 PE 格式自动识别，不看扩展名\n"
        "\n"
        "用法:\n"
        "  ArmorCLI pack <输入文件> <输出文件> [选项]\n"
        "  ArmorCLI unpack <加壳文件> <还原文件> [选项]\n"
        "  ArmorCLI scan <输入文件> [选项]\n"
        "  ArmorCLI version\n"
        "  ArmorCLI help\n"
        "\n"
        "拖放加壳（无需敲命令）:\n"
        "  把 EXE / DLL 直接拖到 ArmorCLI.exe 图标上即可按默认参数加壳，\n"
        "  输出为「原文件名_packed.扩展名」，与原文件同目录；可一次拖入多个文件。\n"
        "  默认参数: 压缩=级别 6  特征隐藏=auto  载荷加密=开  反调试=exit\n"
        "            反转储=开  载荷 CRC=开  保留资源节=开（图标/版本版权不丢）\n"
        "\n"
        "通用选项:\n"
        "  --json                      以 JSON 输出，便于 GUI 解析\n"
        "  -q, --quiet                 只输出错误\n"
        "  --sigfile=<路径>            指定易语言特征文件\n"
        "\n"
        "pack 选项:\n"
        "  --level=N                   压缩级别 1..9，默认 6\n"
        "  --encrypt=0|1               载荷加密，默认 1\n"
        "  --anti-debug=none|exit|fake 反调试动作，默认 exit\n"
        "  --anti-debug-level=1|2      反调试强度，2 增加窗口/进程名/计时检测，默认 1\n"
        "  --anti-dump=0|1             还原后混淆 PE 头，默认 1\n"
        "  --hide-features=模式        易语言特征隐藏: auto|none|all|名称;名称\n"
        "  --keep-manifest=0|1         保留清单资源，默认 1\n"
        "  --keep-rsrc=0|1             资源节不压缩（保留图标/版本版权），默认 1\n"
        "  --crc=0|1                   解包前校验载荷，默认 1\n"
        "  --force                     忽略重复加壳等告警\n"
        "  --allow-dll                 允许处理 DLL（导入/导出/重定位表原样保留）\n"
        "  --stub=<Stub 映像>          使用外部外壳映像（架构须与目标一致）\n"
        "  --seed=N                    随机种子\n"
        "  --section-prefix=<前缀>    自定义产物 PE 节名前缀（默认 arm -> .arm0/.armr/.arm1）\n"
        "  --unpack                    一键解压还原：把已加壳产物还原为原始 EXE/DLL\n"
        "                              等价于独立子命令 unpack；配置项 unpack=1 同样生效\n"
        "  --config=<path>            load pack options from a config file (CLI wins)\n"
        "\n"
        "不支持的目标:\n"
        "  - 内核态映像 (.sys / Native 子系统): 需要内核态外壳且会破坏驱动签名 (DSE)\n"
        "  - .NET 程序 (含 CLR 头)\n"
        "  - 非 PE 文件: 16 位 DOS COM / DOS MZ / Win3.x NE / ELF / EFI 固件\n"
        "  - 其它机器类型的 PE (ARM / ARM64 / IA64)\n"
        "\n"
        "退出码: 0 成功, 1 参数错误, 2 输入输出错误, 3 不支持的目标, 4 处理失败\n",
        ARMOR_APP_VERSION, ARMOR_APP_AUTHOR, ARMOR_APP_QQGroup);
}

std::string hexStr64(au64 v)
{
    char buf[32];
    sprintf_s(buf, "\"0x%016llX\"", (unsigned long long)v);
    return std::string(buf);
}

std::string jsonEscape(const std::string& s)
{
    std::string out;
    for (size_t i = 0; i < s.size(); i++) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
        case '\\': out += "\\\\"; break;
        case '"': out += "\\\""; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (c < 0x20) {
                char buf[8];
                sprintf_s(buf, "\\u%04X", c);
                out += buf;
            } else {
                out += (char)c;
            }
        }
    }
    return out;
}

std::string jsonStr(const std::string& s) { return "\"" + jsonEscape(s) + "\""; }

std::string hexStr(au32 v)
{
    char buf[16];
    sprintf_s(buf, "\"0x%08X\"", v);
    return std::string(buf);
}

void printSignaturesText(const PackStats& st)
{
    int shown = 0;
    for (size_t i = 0; i < st.sigs.size(); i++) {
        const SigResult& r = st.sigs[i];
        if (r.hitCount == 0) continue;
        printf("  [命中] %-20s 次数=%u", r.name.c_str(), r.hitCount);
        if (!r.hits.empty()) {
            printf("  位置=");
            for (size_t k = 0; k < r.hits.size() && k < 8; k++)
                printf("%s0x%08X", k ? "," : "", r.hits[k]);
            if (r.hitCount > r.hits.size()) printf(",...");
        }
        printf("\n");
        shown++;
    }
    if (!shown) printf("  (未命中任何特征)\n");
}

void printStatsText(const PackStats& st, bool packed)
{
    printf("输入    : %s\n", st.inputUtf8.c_str());
    if (packed) printf("输出    : %s\n", st.outputUtf8.c_str());
    printf("体积    : %llu -> %llu 字节", (unsigned long long)st.inSize,
           (unsigned long long)st.outSize);
    if (st.inSize && packed) {
        double r = (double)st.outSize / (double)st.inSize * 100.0;
        printf("  (%.1f%%)", r);
    }
    printf("\n");
    printf("架构    : %s (%s)  类型: %s  外壳: %s\n",
           st.is64 ? "x64" : "x86",
           st.is64 ? "PE32+" : "PE32",
           st.targetKind.empty() ? "-" : st.targetKind.c_str(),
           st.stubArch.empty() ? "-" : st.stubArch.c_str());
    printf("映像    : 基址 0x%016llX  入口 0x%08X  节区 %d\n",
           (unsigned long long)st.imageBase, st.oepRva, st.sectionCount);
    printf("导入    : %d 个模块 / %d 个函数   重定位:%s 资源:%s TLS:%s\n",
           st.importDllCount, st.importFuncCount,
           st.hasReloc ? "有" : "无", st.hasRsrc ? "有" : "无", st.hasTls ? "有" : "无");
    printf("易语言  : %s%s\n", st.isEpl ? "是" : "否",
           st.eplKind.empty() ? "" : (" (" + st.eplKind + ")").c_str());
    if (packed) {
        printf("载荷    : 原始 %u 字节 -> 压缩后 %u 字节（外壳 %u 字节）\n",
               st.unpackedSize, st.payloadSize, st.stubSize);
        printf("特征隐藏: %u 处 / %u 字节\n", st.hiddenRegions, st.hiddenBytes);
        printf("耗时    : %.0f ms\n", st.elapsedMs);
    }
    printf("特征扫描:\n");
    printSignaturesText(st);
    for (size_t i = 0; i < st.warnings.size(); i++)
        printf("  [警告] %s\n", st.warnings[i].c_str());
}

void printStatsJson(const PackStats& st, const char* command)
{
    printf("{\n");
    printf("  \"ok\": %s,\n", st.ok ? "true" : "false");
    printf("  \"command\": %s,\n", jsonStr(command).c_str());
    printf("  \"error\": %s,\n", jsonStr(st.error).c_str());
    printf("  \"input\": %s,\n", jsonStr(st.inputUtf8).c_str());
    printf("  \"output\": %s,\n", jsonStr(st.outputUtf8).c_str());
    printf("  \"inputSize\": %llu,\n", (unsigned long long)st.inSize);
    printf("  \"outputSize\": %llu,\n", (unsigned long long)st.outSize);
    printf("  \"unpackedSize\": %u,\n", st.unpackedSize);
    printf("  \"payloadSize\": %u,\n", st.payloadSize);
    printf("  \"stubSize\": %u,\n", st.stubSize);
    printf("  \"arch\": %s, \"is64\": %s, \"machine\": %s, \"target\": %s, \"stubArch\": %s,\n",
           jsonStr(st.is64 ? "x64" : "x86").c_str(),
           st.is64 ? "true" : "false",
           hexStr(st.machine).c_str(),
           jsonStr(st.targetKind).c_str(),
           jsonStr(st.stubArch).c_str());
    printf("  \"imageBase\": %s,\n", hexStr64(st.imageBase).c_str());
    printf("  \"oep\": %s,\n", hexStr(st.oepRva).c_str());
    printf("  \"sections\": %d,\n", st.sectionCount);
    printf("  \"imports\": {\"dlls\": %d, \"functions\": %d},\n",
           st.importDllCount, st.importFuncCount);
    printf("  \"tls\": %s, \"reloc\": %s, \"rsrc\": %s, \"keepRsrc\": %s,\n",
           st.hasTls ? "true" : "false", st.hasReloc ? "true" : "false",
           st.hasRsrc ? "true" : "false", st.keepRsrc ? "true" : "false");
    printf("  \"epl\": {\"detected\": %s, \"kind\": %s},\n",
           st.isEpl ? "true" : "false", jsonStr(st.eplKind).c_str());
    printf("  \"hidden\": {\"regions\": %u, \"bytes\": %u},\n", st.hiddenRegions, st.hiddenBytes);
    printf("  \"elapsedMs\": %.1f,\n", st.elapsedMs);
    printf("  \"signatures\": [\n");
    for (size_t i = 0; i < st.sigs.size(); i++) {
        const SigResult& r = st.sigs[i];
        if (r.hitCount == 0) continue;
        printf("    {\"name\": %s, \"hits\": %u, \"rvas\": [", jsonStr(r.name).c_str(), r.hitCount);
        for (size_t k = 0; k < r.hits.size(); k++)
            printf("%s%s", k ? "," : "", hexStr(r.hits[k]).c_str());
        printf("]}%s\n", (i + 1 < st.sigs.size()) ? "," : "");
    }
    printf("  ],\n");
    printf("  \"warnings\": [\n");
    for (size_t i = 0; i < st.warnings.size(); i++)
        printf("    %s%s\n", jsonStr(st.warnings[i]).c_str(),
               (i + 1 < st.warnings.size()) ? "," : "");
    printf("  ]\n");
    printf("}\n");
}

int stoiDef(const std::string& s, int def)
{
    if (s.empty()) return def;
    return atoi(s.c_str());
}

bool applyPackOption(const std::string& key, const std::string& val,
                     PackOptions& opt, int& antiDebugLevel, std::string& err)
{
    if (key == "level") opt.level = stoiDef(val, 6);
    else if (key == "encrypt") opt.encrypt = (stoiDef(val, 1) != 0);
    else if (key == "anti-debug") {
        if (val == "none" || val == "0") opt.antiDebug = 0;
        else if (val == "fake" || val == "2") opt.antiDebug = 2;
        else opt.antiDebug = 1;
    } else if (key == "anti-debug-level") antiDebugLevel = stoiDef(val, 1);
    else if (key == "anti-dump") opt.antiDump = (stoiDef(val, 1) != 0);
    else if (key == "hide-features") opt.hideFeatures = val;
    else if (key == "keep-manifest") opt.keepManifest = (stoiDef(val, 1) != 0);
    else if (key == "keep-rsrc") opt.keepRsrc = (stoiDef(val, 1) != 0);
    else if (key == "crc") opt.checkCrc = (stoiDef(val, 1) != 0);
    else if (key == "force") opt.force = (val.empty() || stoiDef(val, 0) != 0);
    else if (key == "allow-dll") opt.allowDll = (val.empty() || stoiDef(val, 0) != 0);
    else if (key == "stub") opt.stubPath = val;
    else if (key == "sigfile") opt.sigFile = val;
    else if (key == "seed") opt.seed = (au32)stoiDef(val, 0);
    else if (key == "section-prefix") {
        if (val.empty() || val.size() > 6) { err = "section-prefix must be 1..6 chars"; return false; }
        for (size_t i = 0; i < val.size(); i++) {
            char c = val[i];
            if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))) {
                err = "section-prefix must be alphanumeric (A-Z a-z 0-9)"; return false;
            }
        }
        opt.sectionPrefix = val;
    }
    else if (key == "unpack") opt.unpack = (val.empty() || stoiDef(val, 0) != 0);
    else if (key == "json" || key == "quiet") { /* 仅命令行全局项，配置忽略 */ }
    else { err = "unknown option: " + key; return false; }
    return true;
}

/* Load packing options from a config file (one "key=value" per line,
   lines starting with ';' or '#' are comments, blank lines are skipped).
   Command-line arguments take precedence and override same-named entries. */
bool loadConfigFile(const std::wstring& path, PackOptions& opt, int& antiDebugLevel, std::string& err)
{
    std::string content;
    if (!readFileToString(path, content)) { err = "cannot open config file"; return false; }
    /* strip UTF-8 BOM if present */
    if (content.size() >= 3 && (unsigned char)content[0] == 0xEF &&
        (unsigned char)content[1] == 0xBB && (unsigned char)content[2] == 0xBF)
        content.erase(0, 3);
    std::string line;
    size_t pos = 0;
    while (pos <= content.size()) {
        size_t nl = content.find('\n', pos);
        if (nl == std::string::npos) nl = content.size();
        line = content.substr(pos, nl - pos);
        pos = nl + 1;
        if (!line.empty() && line[line.size() - 1] == '\r') line.resize(line.size() - 1);
        size_t b = line.find_first_not_of(" \t");
        if (b == std::string::npos) continue; /* blank */
        if (line[b] == ';' || line[b] == '#') continue; /* comment */
        size_t eq = line.find('=', b);
        if (eq == std::string::npos) { err = "config line missing '=': " + line.substr(b); return false; }
        std::string key = line.substr(b, eq - b);
        size_t ke = key.find_last_not_of(" \t");
        if (ke != std::string::npos) key.resize(ke + 1);
        std::string val = line.substr(eq + 1);
        size_t vb = val.find_first_not_of(" \t");
        if (vb == std::string::npos) val.clear(); else val = val.substr(vb);
        size_t ve = val.find_last_not_of(" \t");
        if (ve != std::string::npos) val.resize(ve + 1);
        if (key.compare(0, 2, "--") == 0) key = key.substr(2); /* tolerate --level=9 */
        if (!applyPackOption(key, val, opt, antiDebugLevel, err)) return false;
    }
    return true;
}

/* ---------------------------------------------------- 拖放（drag & drop）模式
 *
 * 把 EXE / DLL 拖到 ArmorCLI.exe 图标上时，Windows 会用被拖放文件的完整路径作为
 * 命令行参数启动本程序：argv[1] 是文件路径，且不会带 pack / unpack 等子命令。
 * 此时按默认参数直接加壳，输出为「原文件名_packed.扩展名」，与原文件同目录。
 *
 * 默认参数沿用 PackOptions 的内置默认值，其中包含用户要求保留的两项：
 *   压缩     : level = 6（开）
 *   特征隐藏 : hide-features = auto（开）
 * 另外默认开启：载荷 RC4 加密、反调试(exit)、反转储、CRC 校验、保留资源节。
 */

static bool isKnownCommand(const std::string& c)
{
    return c == "pack" || c == "unpack" || c == "scan" ||
           c == "version" || c == "--version" ||
           c == "help" || c == "-h" || c == "--help" || c == "/?";
}

static bool pathExists(const std::wstring& p)
{
    return GetFileAttributesW(p.c_str()) != INVALID_FILE_ATTRIBUTES;
}

static bool pathIsExistingFile(const std::wstring& p)
{
    DWORD a = GetFileAttributesW(p.c_str());
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

/* foo.exe -> foo_packed.exe（保留原扩展名，输出放在同一目录） */
static std::wstring makeDroppedOutputPath(const std::wstring& in)
{
    size_t slash = in.find_last_of(L"\\/");
    size_t dot = in.find_last_of(L'.');
    std::wstring base = in;
    std::wstring ext;
    if (dot != std::wstring::npos && (slash == std::wstring::npos || dot > slash + 1)) {
        base = in.substr(0, dot);
        ext = in.substr(dot);
    }
    return base + L"_packed" + ext;
}

/* ------------------------------------------------------------------ 日志
 *
 * 拖放启动时窗口由资源管理器创建，加壳结束即关闭，用户在屏幕上什么也看不到，
 * 因此结果一律写入日志文件（追加模式，UTF-8）。日志放在与第一个待处理文件
 * 相同的目录，加壳后就近即可查看。
 */

#define ARMOR_DROP_LOG_NAME L"ArmorCLI.log"

static std::wstring makeLogPath(const std::wstring& nearFile)
{
    size_t slash = nearFile.find_last_of(L"\\/");
    if (slash == std::wstring::npos) return std::wstring(ARMOR_DROP_LOG_NAME);
    return nearFile.substr(0, slash + 1) + ARMOR_DROP_LOG_NAME;
}

/* 二进制追加：避免 CRT 按当前代码页做转换，日志统一以 UTF-8 写入 */
static FILE* openLog(const std::wstring& path)
{
    FILE* f = nullptr;
    if (path.empty()) return nullptr;
    if (_wfopen_s(&f, path.c_str(), L"ab") != 0 || !f) return nullptr;
    return f;
}

static void logWrite(FILE* f, const std::string& s)
{
    if (f && !s.empty()) fwrite(s.data(), 1, s.size(), f);
}

static void logPrintf(FILE* f, const char* fmt, ...)
{
    char buf[2048];
    va_list ap;
    int n;
    if (!f) return;
    va_start(ap, fmt);
    n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > 0) logWrite(f, std::string(buf, (size_t)n < sizeof(buf) ? (size_t)n : sizeof(buf) - 1));
}

static std::string nowStamp(void)
{
    SYSTEMTIME st;
    char buf[32];
    GetLocalTime(&st);
    sprintf_s(buf, "%04d-%02d-%02d %02d:%02d:%02d",
              st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return std::string(buf);
}

/* 把一次加壳结果写进日志 */
static void logPackResult(FILE* f, int index, bool ok, const std::wstring& in,
                          const std::wstring& out, const PackStats& st)
{
    logPrintf(f, "[%d] %s\n", index, ok ? "成功" : "失败");
    logPrintf(f, "    输入    : %s\n", wideToUtf8(in).c_str());
    if (ok) {
        logPrintf(f, "    输出    : %s\n", wideToUtf8(out).c_str());
        logPrintf(f, "    体积    : %llu -> %llu 字节",
                  (unsigned long long)st.inSize, (unsigned long long)st.outSize);
        if (st.inSize)
            logPrintf(f, "  (%.1f%%)", (double)st.outSize / (double)st.inSize * 100.0);
        logPrintf(f, "\n");
        logPrintf(f, "    架构    : %s (%s)  类型: %s  外壳: %s\n",
                  st.is64 ? "x64" : "x86",
                  st.is64 ? "PE32+" : "PE32",
                  st.targetKind.empty() ? "-" : st.targetKind.c_str(),
                  st.stubArch.empty() ? "-" : st.stubArch.c_str());
        logPrintf(f, "    载荷    : 原始 %u 字节 -> 压缩后 %u 字节（外壳 %u 字节）\n",
                  st.unpackedSize, st.payloadSize, st.stubSize);
        logPrintf(f, "    特征隐藏: %u 处 / %u 字节\n", st.hiddenRegions, st.hiddenBytes);
        logPrintf(f, "    耗时    : %.0f ms\n", st.elapsedMs);
    } else {
        logPrintf(f, "    原因    : %s\n", st.error.c_str());
    }
    for (size_t i = 0; i < st.warnings.size(); i++)
        logPrintf(f, "    警告    : %s\n", st.warnings[i].c_str());
    logPrintf(f, "\n");
}

static int runDropMode(int argc, wchar_t* argv[])
{
    int handled = 0;
    int failures = 0;
    std::wstring logPath;
    FILE* log = nullptr;

    /* 日志放在与第一个待处理文件相同的目录，方便加壳后就近查看 */
    for (int i = 1; i < argc; i++) {
        std::wstring p = argv[i];
        if (p.empty() || p.compare(0, 2, L"--") == 0) continue;
        if (!pathExists(p)) continue;
        logPath = makeLogPath(p);
        break;
    }
    log = openLog(logPath);

    logPrintf(log, "\n");
    logPrintf(log, "============================================================\n");
    logPrintf(log, "ARMOR %s  %s  (作者: %s)  QQ群:%s \n",
              ARMOR_APP_VERSION, nowStamp().c_str(), ARMOR_APP_AUTHOR, ARMOR_APP_QQGroup);
    logPrintf(log, "默认参数: 压缩=级别 6  特征隐藏=auto  载荷加密=开  反调试=exit\n");
    logPrintf(log, "          反转储=开  载荷 CRC=开  保留资源节=开（图标/版本版权不丢）\n");
    logPrintf(log, "------------------------------------------------------------\n");

    /* 控制台输出保持精简：拖放启动时窗口会立即关闭，屏幕上看不到，
       真正的结果在日志文件里；从终端运行时这些行仍然有用。 */
    printf("ARMOR %s  拖放加壳（默认参数）  作者: %s\n",
           ARMOR_APP_VERSION, ARMOR_APP_AUTHOR);
    if (!logPath.empty())
        printf("日志: %s\n", wideToUtf8(logPath).c_str());
    printf("\n");

    for (int i = 1; i < argc; i++) {
        std::wstring in = argv[i];
        std::wstring out;
        PackOptions opt;
        PackStats st;

        if (in.empty()) continue;
        if (in.compare(0, 2, L"--") == 0) continue; /* 拖放不带选项，保险起见跳过 */

        if (!pathIsExistingFile(in)) {
            printf("  [跳过] 不是文件: %s\n", wideToUtf8(in).c_str());
            logPrintf(log, "[跳过] 不是文件: %s\n\n", wideToUtf8(in).c_str());
            continue;
        }

        out = makeDroppedOutputPath(in);

        /* 全部使用内置默认值：保留压缩（level 6）与特征隐藏（auto）。
           allowDll 置真以便拖入 DLL 时可直接处理；对 EXE 目标无任何副作用
           （打包器只在目标确实带 IMAGE_FILE_DLL 标志时才走 DLL 流程）。 */
        opt.allowDll = true;
        opt.unpack = false;
        opt.antiDebugLevel = 1;

        handled++;

        if (!packFile(in, out, opt, st)) {
            failures++;
            logPackResult(log, handled, false, in, out, st);
            fflush(stdout);
            fprintf(stderr, "  [失败] %s\n", wideToUtf8(in).c_str());
            fprintf(stderr, "         %s\n", st.error.c_str());
            continue;
        }
        logPackResult(log, handled, true, in, out, st);
        printf("  [成功] %s -> %s\n", wideToUtf8(in).c_str(), wideToUtf8(out).c_str());
    }

    logPrintf(log, "------------------------------------------------------------\n");
    logPrintf(log, "合计: 处理 %d 个，成功 %d 个，失败 %d 个\n",
              handled, handled - failures, failures);
    if (log) { fclose(log); log = nullptr; }

    if (handled == 0) {
        fflush(stdout);
        fprintf(stderr, "没有可处理的文件。\n");
        if (!logPath.empty())
            fprintf(stderr, "日志: %s\n", wideToUtf8(logPath).c_str());
        return 1;
    }

    printf("共处理 %d 个，成功 %d 个，失败 %d 个；结果见日志\n",
           handled, handled - failures, failures);
    /* 不暂停：加壳结束窗口直接关闭，结果一律以日志文件留档 */
    return failures ? 4 : 0;
}

} /* namespace */

int wmain(int argc, wchar_t* argv[])
{
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    if (argc < 2) {
        printUsage();
        return 1;
    }

    std::string cmd = wideToUtf8(argv[1]);
    if (cmd == "help" || cmd == "-h" || cmd == "--help" || cmd == "/?") {
        printUsage();
        return 0;
    }
    if (cmd == "version" || cmd == "--version") {
        printf("ARMOR %s\n", ARMOR_APP_VERSION);
        printf("作者    : %s\n", ARMOR_APP_AUTHOR);
        printf("%s\n", ARMOR_APP_COPYRIGHT);
        printf("支持    : x86 (PE32) / x64 (PE32+) 的 EXE 与 DLL\n");
        return 0;
    }
    if (!isKnownCommand(cmd)) {
        /* 不是子命令：若首个参数是真实存在的路径（文件或目录），则视为
           "拖放到 ArmorCLI.exe 上"，按默认参数直接加壳（保留压缩与特征隐藏）。
           目录也会进入拖放流程，这样能给出「不是文件」的明确提示，
           而不是莫名其妙的「未知命令」。 */
        if (pathExists(argv[1])) return runDropMode(argc, argv);
        fprintf(stderr, "未知命令: %s\n\n", cmd.c_str());
        printUsage();
        return 1;
    }

    PackOptions opt;
    std::vector<std::wstring> positional;
    bool jsonOut = false;
    bool quiet = false;
    int antiDebugLevel = 1;

    /* pass 1: load config file(s) first so command line can override */
    for (int i = 2; i < argc; i++) {
        std::string a0 = wideToUtf8(argv[i]);
        if (a0.compare(0, 9, "--config=") == 0) {
            std::wstring cwp = utf8ToWide(a0.substr(9));
            std::string cerr;
            if (!loadConfigFile(cwp, opt, antiDebugLevel, cerr)) {
                fprintf(stderr, "config error: %s\n", cerr.c_str());
                return 1;
            }
        }
    }

    for (int i = 2; i < argc; i++) {
        std::string a = wideToUtf8(argv[i]);
        if (a.compare(0, 2, "--") == 0 && a != "--") {
            std::string key = a, val;
            size_t eq = a.find('=');
            if (eq != std::string::npos) {
                key = a.substr(0, eq);
                val = a.substr(eq + 1);
            }
            if (key == "--json") jsonOut = true;
            else if (key == "--quiet") quiet = true;
            else if (key == "--config") { /* already loaded in pass 1 */ }
            else {
                std::string oerr;
                if (!applyPackOption(key.substr(2), val, opt, antiDebugLevel, oerr)) {
                    fprintf(stderr, "unknown option: %s\n", a.c_str());
                    return 1;
                }
            }
        } else if (a == "-q") {
            quiet = true;
        } else {
            positional.push_back(argv[i]);
        }
    }

    if (opt.level < 1) opt.level = 1;
    if (opt.level > 9) opt.level = 9;

    if (positional.size() < 1) {
        fprintf(stderr, "缺少输入文件\n");
        return 1;
    }
    if (cmd == "pack" && positional.size() < 2) {
        fprintf(stderr, "缺少输出文件\n");
        return 1;
    }
    if (cmd == "unpack" && positional.size() < 2) {
        fprintf(stderr, "缺少还原输出文件（用法: ArmorCLI unpack <加壳文件> <还原文件>）\n");
        return 1;
    }

    PackStats st;

    if (cmd == "scan") {
        bool ok = scanFile(positional[0], opt, st);
        if (!ok) {
            fprintf(stderr, "错误: %s\n", st.error.c_str());
            if (jsonOut) printStatsJson(st, "scan");
            return 3;
        }
        if (jsonOut) printStatsJson(st, "scan");
        else if (!quiet) printStatsText(st, false);
        return 0;
    }

    /* pack / unpack */
    {
        opt.antiDebugLevel = antiDebugLevel;
        if (cmd == "unpack") opt.unpack = true; /* 独立子命令等价于 --unpack */
        bool ok = packFile(positional[0], positional[1], opt, st);
        if (!ok) {
            fprintf(stderr, "错误: %s\n", st.error.c_str());
            if (jsonOut) printStatsJson(st, opt.unpack ? "unpack" : "pack");
            return 4;
        }
        if (jsonOut) printStatsJson(st, opt.unpack ? "unpack" : "pack");
        else if (!quiet) printStatsText(st, true);
        return 0;
    }
}
