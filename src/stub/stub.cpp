/* ARMOR 运行时外壳。
 *
 * 编译约束（见 ArmorStub.vcxproj）：
 *   /NODEFAULTLIB /ENTRY:StubEntry /GS- /Gs8192
 * 因此本文件：
 *   - 不使用任何 CRT 函数（自行实现 memcpy/memset 等可能被编译器生成的符号）；
 *   - 不使用静态导入表，kernel32 / ntdll 通过 PEB 遍历 + 导出表解析获得；
 *   - 不使用可写全局量（打包后的 .arm1 节不可写），全部状态保存在栈上的上下文中。
 *
 * 同一份源码同时构建为 x86 与 x64 两份外壳映像，打包器按目标程序架构二选一：
 *   - PEB / LDR 链表偏移、导出表数据目录偏移、导入 thunk 与 TLS 目录宽度、
 *     基址重定位类型（HIGHLOW / DIR64）均由 ARMOR_IS64 决定；
 *   - 结构统一走 ARMOR_NT / ARMOR_TLS_DIR / ARMOR_THUNK 别名。
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>

#pragma function(memcpy, memset, memmove, memcmp, strlen)

#include "../common/armor_base.h"
#include "../common/crc32.h"
#include "../common/deflate.h"
#include "../common/packfmt.h"
#include "../common/rc4.h"

/* ------------------------------------------------- 架构相关的类型与偏移 */

#ifdef _WIN64
#  define ARMOR_IS64       1
#  define ARMOR_PTR_BYTES  8
typedef IMAGE_NT_HEADERS64      ARMOR_NT;
typedef IMAGE_OPTIONAL_HEADER64 ARMOR_OPT;
typedef IMAGE_TLS_DIRECTORY64   ARMOR_TLS_DIR;
typedef IMAGE_THUNK_DATA64      ARMOR_THUNK;

#  define ARMOR_PEB_SELF            __readgsqword(0x60)                 /* GS:[0x60] -> PEB */
#  define ARMOR_PEB_LDR_OFF         0x18  /* PEB->Ldr */
#  define ARMOR_PEB_NTGLOBALFLAG    0xBC  /* PEB->NtGlobalFlag */
#  define ARMOR_LDR_LIST_OFF        0x10  /* PEB_LDR_DATA->InLoadOrderModuleList */
#  define ARMOR_LDR_DLLBASE_OFF     0x30  /* LDR_DATA_TABLE_ENTRY->DllBase */
#  define ARMOR_LDR_NAMELEN_OFF     0x58  /* ...->BaseDllName.Length */
#  define ARMOR_LDR_NAMEBUF_OFF     0x60  /* ...->BaseDllName.Buffer */
#  define ARMOR_DD0_OFF             0x88  /* NT + 0x18(FileHeader) + 0x70(PE32+ DataDirectory) */
#  define ARMOR_ORDINAL_BIT(v)      (((v) >> 63) & 1u)
#else
#  define ARMOR_IS64       0
#  define ARMOR_PTR_BYTES  4
typedef IMAGE_NT_HEADERS32      ARMOR_NT;
typedef IMAGE_OPTIONAL_HEADER32 ARMOR_OPT;
typedef IMAGE_TLS_DIRECTORY32   ARMOR_TLS_DIR;
typedef IMAGE_THUNK_DATA32      ARMOR_THUNK;

#  define ARMOR_PEB_SELF            __readfsdword(0x30)                 /* FS:[0x30] -> PEB */
#  define ARMOR_PEB_LDR_OFF         0x0C  /* PEB->Ldr */
#  define ARMOR_PEB_NTGLOBALFLAG    0x68  /* PEB->NtGlobalFlag */
#  define ARMOR_LDR_LIST_OFF        0x0C  /* PEB_LDR_DATA->InLoadOrderModuleList */
#  define ARMOR_LDR_DLLBASE_OFF     0x18  /* LDR_DATA_TABLE_ENTRY->DllBase */
#  define ARMOR_LDR_NAMELEN_OFF     0x2C  /* ...->BaseDllName.Length */
#  define ARMOR_LDR_NAMEBUF_OFF     0x30  /* ...->BaseDllName.Buffer */
#  define ARMOR_DD0_OFF             0x78  /* NT + 0x18(FileHeader) + 0x60(PE32 DataDirectory) */
#  define ARMOR_ORDINAL_BIT(v)      (((v) >> 31) & 1u)
#endif

/* ------------------------------------------------------- CRT 符号兜底 */

extern "C" {

void* __cdecl memcpy(void* d, const void* s, size_t n) { return armor_copy(d, s, n); }
void* __cdecl memset(void* d, int c, size_t n) { return armor_fill(d, (au8)c, n); }

void* __cdecl memmove(void* d, const void* s, size_t n)
{
    return armor_move(d, s, n);
}

int __cdecl memcmp(const void* a, const void* b, size_t n)
{
    return armor_cmp(a, b, n);
}

size_t __cdecl strlen(const char* s)
{
    return armor_len(s);
}

} /* extern "C" */

/* ---------------------------------------------------------- 参数块 */

#pragma section(".apar", read)
__declspec(allocate(".apar")) const volatile ARMOR_STUB_PARAMS g_armorParams = {
    { ARMOR_STUB_MAGIC0, ARMOR_STUB_MAGIC1, ARMOR_STUB_MAGIC2, ARMOR_STUB_MAGIC3 },
    0, 0, { 0, 0 }
};

/* 自带的 ANSI 版 PROCESSENTRY32（等价于 tlhelp32.h 中的 tagPROCESSENTRY32） */
typedef struct _ARMOR_PROCENT {
    au32 dwSize;
    au32 cntUsage;
    au32 th32ProcessID;
    au32 th32DefaultHeapID;
    au32 th32ModuleID;
    au32 cntThreads;
    au32 th32ParentProcessID;
    ai32 pcPriClassBase;
    au32 dwFlags;
    char szExeFile[260];
} ARMOR_PROCENT;

/* --------------------------------------------------------- API 上下文 */

typedef struct _ARMOR_CTX {
    au8* base;
    const ARMOR_HEADER* hdr;
    au64 delta;   /* 实际基址 - 首选基址（x64 下为 64 位增量） */
    au32 rndState;

    void* kernel32;
    void* ntdll;

    HMODULE(WINAPI* pLoadLibraryA)(LPCSTR);
    FARPROC(WINAPI* pGetProcAddress)(HMODULE, LPCSTR);
    LPVOID(WINAPI* pVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
    BOOL(WINAPI* pVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
    BOOL(WINAPI* pVirtualFree)(LPVOID, SIZE_T, DWORD);
    SIZE_T(WINAPI* pVirtualQuery)(LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
    void(WINAPI* pExitProcess)(UINT);
    void(WINAPI* pExitThread)(DWORD);
    BOOL(WINAPI* pFlushInstructionCache)(HANDLE, LPCVOID, SIZE_T);
    HANDLE(WINAPI* pGetCurrentProcess)(void);
    HANDLE(WINAPI* pGetCurrentThread)(void);
    DWORD(WINAPI* pGetTickCount)(void);
    BOOL(WINAPI* pIsDebuggerPresent)(void);
    BOOL(WINAPI* pCheckRemoteDebuggerPresent)(HANDLE, PBOOL);
    BOOL(WINAPI* pQueryPerformanceCounter)(LARGE_INTEGER*);
    HANDLE(WINAPI* pCreateToolhelp32Snapshot)(DWORD, DWORD);
    BOOL(WINAPI* pProcess32FirstA)(HANDLE, ARMOR_PROCENT*);
    BOOL(WINAPI* pProcess32NextA)(HANDLE, ARMOR_PROCENT*);
    BOOL(WINAPI* pCloseHandle)(HANDLE);
    void(WINAPI* pSleep)(DWORD);

    /* 文件追踪（供 dbgMark 使用，由 initApi 解析，避免自行 PEB 遍历的不确定性） */
    HANDLE(WINAPI* pCreateFileA)(LPCSTR, DWORD, BOOL, void*, DWORD, DWORD, HANDLE);
    BOOL(WINAPI* pWriteFile)(HANDLE, LPCVOID, SIZE_T, LPDWORD, void*);
    DWORD(WINAPI* pSetFilePointer)(HANDLE, LONG, PLONG, DWORD);

    /* ntdll */
    LONG(WINAPI* pNtQueryInformationProcess)(HANDLE, au32, void*, au32, au32*);
    LONG(WINAPI* pNtSetInformationThread)(HANDLE, au32, void*, au32);
} ARMOR_CTX;

/* ------------------------------------------------------- PEB / 导出表 */

static au8* pebPtr(void)
{
    return (au8*)(size_t)ARMOR_PEB_SELF;
}

static au32 hashAsciiI(const char* s)
{
    au32 h = 2166136261u;
    while (*s) {
        char c = *s++;
        if (c >= 'a' && c <= 'z') c = (char)(c - 32);
        h = (h ^ (au8)c) * 16777619u;
    }
    return h;
}

static au32 hashUnicodeI(const wchar_t* s, int n)
{
    /* 必须与 hashAsciiI 对“ASCII 形式”的哈希结果一致：
       模块名均为 ASCII，每个宽字符只取低字节做一次 FNV 步进，
       否则宽字符的高字节会多引入一次乘，导致与 hashAsciiI 结果永远不等。 */
    au32 h = 2166136261u;
    int i;
    for (i = 0; i < n; i++) {
        au32 c = (au32)s[i];
        if (c >= 'a' && c <= 'z') c -= 32;
        h = (h ^ (au8)(c & 0xFF)) * 16777619u;
    }
    return h;
}

/* 取 PEB_LDR_DATA->InLoadOrderModuleList 链表头 */
static int pebLdrHead(LIST_ENTRY** out)
{
    au8* peb = pebPtr();
    au8* ldr;

    if (!peb) return 0;
#if ARMOR_IS64
    ldr = (au8*)(size_t)armor_rd64(peb + ARMOR_PEB_LDR_OFF);
#else
    ldr = (au8*)(size_t)armor_rd32(peb + ARMOR_PEB_LDR_OFF);
#endif
    if (!ldr) return 0;
    *out = (LIST_ENTRY*)(ldr + ARMOR_LDR_LIST_OFF);
    return 1;
}

static void* pebFindModule(au32 nameHash)
{
    LIST_ENTRY* head;
    LIST_ENTRY* e;
    int guard;

    if (!pebLdrHead(&head)) return nullptr;
    e = head->Flink;
    for (guard = 0; guard < 256 && e && e != head; guard++) {
        au8* entry = (au8*)e;
        void* dllBase;
        wchar_t* nameBuf;
        au16 nameLen;
#if ARMOR_IS64
        dllBase = (void*)(size_t)armor_rd64(entry + ARMOR_LDR_DLLBASE_OFF);
        nameLen = armor_rd16(entry + ARMOR_LDR_NAMELEN_OFF);
        nameBuf = (wchar_t*)(size_t)armor_rd64(entry + ARMOR_LDR_NAMEBUF_OFF);
#else
        dllBase = (void*)(size_t)armor_rd32(entry + ARMOR_LDR_DLLBASE_OFF);
        nameLen = armor_rd16(entry + ARMOR_LDR_NAMELEN_OFF);
        nameBuf = (wchar_t*)(size_t)armor_rd32(entry + ARMOR_LDR_NAMEBUF_OFF);
#endif
        if (dllBase && nameBuf && nameLen >= 4) {
            if (hashUnicodeI(nameBuf, (int)(nameLen / 2)) == nameHash) return dllBase;
        }
        e = e->Flink;
    }
    return nullptr;
}

static void* pebExeBase(void)
{
    LIST_ENTRY* head;
    LIST_ENTRY* e;
    if (!pebLdrHead(&head)) return nullptr;
    e = head->Flink;
    if (e && e != head) {
        au8* entry = (au8*)e;
#if ARMOR_IS64
        return (void*)(size_t)armor_rd64(entry + ARMOR_LDR_DLLBASE_OFF);
#else
        return (void*)(size_t)armor_rd32(entry + ARMOR_LDR_DLLBASE_OFF);
#endif
    }
    return nullptr;
}

/* 通过调用方的返回地址向下回溯 PE 头，定位所在模块基址（不依赖 PEB 遍历）。
   在 StubEntry 入口调用时返回地址位于 kernel32 内，可据此拿到 kernel32 基址。
   注意：kernel32 基址一律通过 pebFindModule() 现取，不再缓存到可写全局量——
   打包后的 .arm1 节为 R+X（不可写），可写全局量会触发 0xC0000005 访问违规。 */
static void* findModuleByAddr(void* addr)
{
    size_t p = (size_t)addr & ~(size_t)0xFFFu;
    for (; p > 0x10000u; p -= 0x1000u) {
        au8* m = (au8*)p;
        if (m[0] == 'M' && m[1] == 'Z') {
            au32 e = armor_rd32(m + 0x3C);
            if (e < 0x1000u && m[e] == 'P' && m[e + 1] == 'E' && m[e + 2] == 0 && m[e + 3] == 0)
                return m;
        }
    }
    return nullptr;
}

static au32 armor_fnv(const char* s)
{
    au32 h = 2166136261u;
    while (*s) { au32 c = (au32)(au8)*s++; h = (h ^ c) * 16777619u; }
    return h;
}

static void* getExportByName(void* dll, au32 nameHash)
{
    au8* b = (au8*)dll;
    au32 peOff;
    au8* nt;
    au32 expRva;
    au8* exp;
    au32 nFuncs, nNames, addrFn, addrNm, addrOrd;
    const au32* names;
    const au16* ords;
    const au32* funcs;
    au32 i;

    if (!b) return nullptr;
    peOff = armor_rd32(b + 0x3C);
    if (peOff > 0x100000u) return nullptr;
    nt = b + peOff;
    if (armor_rd32(nt) != 0x00004550u) return nullptr;
    /* OptionalHeader.DataDirectory[0]（导出表）：PE32 与 PE32+ 偏移不同 */
    expRva = armor_rd32(nt + ARMOR_DD0_OFF);
    if (!expRva) return nullptr;
    exp = b + expRva;
    nFuncs = armor_rd32(exp + 0x14);
    nNames = armor_rd32(exp + 0x18);
    addrFn = armor_rd32(exp + 0x1C);
    addrNm = armor_rd32(exp + 0x20);
    addrOrd = armor_rd32(exp + 0x24);
    if (!nNames || !addrNm || !addrOrd || !addrFn) return nullptr;
    names = (const au32*)(b + addrNm);
    ords = (const au16*)(b + addrOrd);
    funcs = (const au32*)(b + addrFn);

    for (i = 0; i < nNames; i++) {
        const char* nm = (const char*)(b + names[i]);
        if (armor_fnv(nm) == nameHash) {
            au16 ord = ords[i];
            if (ord >= nFuncs) return nullptr;
            return b + funcs[ord];
        }
    }
    return nullptr;
}

static void earlyMark(const char* tag);

static void dbgDword(ARMOR_CTX* c, au32 v)
{
#if 0 /* debug marks disabled */
    if (!c || !c->pCreateFileA || !c->pWriteFile || !c->pCloseHandle) return;
    char path[64];
    const char* p = "c:\\Users\\Administrator\\Desktop\\shell\\armor_dbg.txt";
    int i;
    for (i = 0; p[i] && i < 63; i++) path[i] = p[i];
    path[i] = 0;
    HANDLE h = c->pCreateFileA(path, GENERIC_WRITE, 0, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    if (h == INVALID_HANDLE_VALUE) return;
    if (c->pSetFilePointer) c->pSetFilePointer(h, 0, 0, 2);
    DWORD w = 0;
    c->pWriteFile(h, &v, 4, &w, 0);
    c->pCloseHandle(h);
#endif
}

static int initApi(ARMOR_CTX* c)
{
    earlyMark("i1");
    c->kernel32 = (void*)pebFindModule(0x29CDD463u);
    if (!c->kernel32) return 0;

    c->pLoadLibraryA = (HMODULE(WINAPI*)(LPCSTR))getExportByName(c->kernel32, 0x53B2070Fu);
    c->pGetProcAddress = (FARPROC(WINAPI*)(HMODULE, LPCSTR))getExportByName(c->kernel32, 0xF8F45725u);
    c->pVirtualAlloc = (LPVOID(WINAPI*)(LPVOID, SIZE_T, DWORD, DWORD))getExportByName(c->kernel32, 0x03285501u);
    c->pVirtualProtect = (BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD))getExportByName(c->kernel32, 0x820621F3u);
    c->pVirtualFree = (BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD))getExportByName(c->kernel32, 0x3A9ACC72u);
    c->pVirtualQuery = (SIZE_T(WINAPI*)(LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T))getExportByName(c->kernel32, 0xBE4D5EF8u);
    c->pExitProcess = (void(WINAPI*)(UINT))getExportByName(c->kernel32, 0x0E80FD3Au);
    earlyMark("i2");
    c->pFlushInstructionCache = (BOOL(WINAPI*)(HANDLE, LPCVOID, SIZE_T))getExportByName(c->kernel32, 0x0490286Bu);
    c->pGetCurrentProcess = (HANDLE(WINAPI*)(void))getExportByName(c->kernel32, 0x6DD8A845u);
    c->pGetCurrentThread = (HANDLE(WINAPI*)(void))getExportByName(c->kernel32, 0x9BC5A608u);
    c->pGetTickCount = (DWORD(WINAPI*)(void))getExportByName(c->kernel32, 0x0F4D8B55u);
    c->pIsDebuggerPresent = (BOOL(WINAPI*)(void))getExportByName(c->kernel32, 0x694A8C81u);
    c->pCheckRemoteDebuggerPresent = (BOOL(WINAPI*)(HANDLE, PBOOL))getExportByName(c->kernel32, 0x4CFE97C1u);
    c->pQueryPerformanceCounter = (BOOL(WINAPI*)(LARGE_INTEGER*))getExportByName(c->kernel32, 0x27C5F681u);
    c->pCreateToolhelp32Snapshot = (HANDLE(WINAPI*)(DWORD, DWORD))getExportByName(c->kernel32, 0x185776B5u);
    c->pProcess32FirstA = (BOOL(WINAPI*)(HANDLE, ARMOR_PROCENT*))getExportByName(c->kernel32, 0x0481A84Au);
    c->pProcess32NextA = (BOOL(WINAPI*)(HANDLE, ARMOR_PROCENT*))getExportByName(c->kernel32, 0xB9E52849u);
    c->pCloseHandle = (BOOL(WINAPI*)(HANDLE))getExportByName(c->kernel32, 0xFABA0065u);
    c->pSleep = (void(WINAPI*)(DWORD))getExportByName(c->kernel32, 0x2FA62CA8u);
    c->pCreateFileA = (HANDLE(WINAPI*)(LPCSTR, DWORD, BOOL, void*, DWORD, DWORD, HANDLE))getExportByName(c->kernel32, 0xBDCAC9CEu);
    c->pWriteFile = (BOOL(WINAPI*)(HANDLE, LPCVOID, SIZE_T, LPDWORD, void*))getExportByName(c->kernel32, 0x7F07C44Au);
    c->pSetFilePointer = (DWORD(WINAPI*)(HANDLE, LONG, PLONG, DWORD))getExportByName(c->kernel32, 0xB7F5E1C2u);
    earlyMark("i3");

    if (!c->pLoadLibraryA || !c->pGetProcAddress || !c->pVirtualAlloc ||
        !c->pVirtualProtect || !c->pExitProcess)
        return 0;

    c->ntdll = pebFindModule(0x145370BBu);
    if (!c->ntdll && c->pLoadLibraryA) c->ntdll = (void*)c->pLoadLibraryA("ntdll.dll");
    if (c->ntdll) {
        c->pNtQueryInformationProcess =
            (LONG(WINAPI*)(HANDLE, au32, void*, au32, au32*))getExportByName(c->ntdll, 0xEA2DDA8Au);
        c->pNtSetInformationThread =
            (LONG(WINAPI*)(HANDLE, au32, void*, au32))getExportByName(c->ntdll, 0xF19E1321u);
        earlyMark("i4");
    }
    return 1;
}

/* --------------------------------------------------------- 反调试 */

static int adPebMarkers(void)
{
    au8* peb = pebPtr();
    if (peb[2]) return 1;                              /* BeingDebugged */
    if ((armor_rd32(peb + ARMOR_PEB_NTGLOBALFLAG) & 0x70u) != 0) return 1; /* NtGlobalFlag */
    return 0;
}

static int adKernelApi(ARMOR_CTX* c)
{
    au64 port = 0, obj = 0;
    au32 flags = 1;
    BOOL remote = FALSE;

    if (c->pIsDebuggerPresent && c->pIsDebuggerPresent()) return 1;
    if (c->pCheckRemoteDebuggerPresent && c->pGetCurrentProcess) {
        if (c->pCheckRemoteDebuggerPresent(c->pGetCurrentProcess(), &remote) && remote) return 1;
    }
    if (c->pNtQueryInformationProcess && c->pGetCurrentProcess) {
        HANDLE h = c->pGetCurrentProcess();
        /* ProcessDebugPort(7) 与 ProcessDebugObjectHandle(0x1E) 返回的是指针宽度的句柄，
           ProcessDebugFlags(0x1F) 返回 4 字节 ULONG。 */
        if (c->pNtQueryInformationProcess(h, 7, &port, (au32)ARMOR_PTR_BYTES, nullptr) == 0 && port) return 1;
        if (c->pNtQueryInformationProcess(h, 0x1E, &obj, (au32)ARMOR_PTR_BYTES, nullptr) == 0 && obj) return 1;
        if (c->pNtQueryInformationProcess(h, 0x1F, &flags, 4, nullptr) == 0 && !flags) return 1;
    }
    return 0;
}

static const char* kDbgWindows[] = {
    "OLLYDBG", "x64dbg", "SunAwtFrame", "IDA", "ImmunityDebugger",
    "WinDbgFrameClass", "Qt5152QWindowIcon", nullptr
};

static int adWindows(ARMOR_CTX* c)
{
    int i;
    HWND(WINAPI * pFindWindowA)(LPCSTR, LPCSTR);

    if (!c->pLoadLibraryA) return 0;
    {
        HMODULE hUser = c->pLoadLibraryA("user32.dll");
        if (!hUser) return 0;
        pFindWindowA = (HWND(WINAPI*)(LPCSTR, LPCSTR))getExportByName((void*)hUser, 0xF652BC95u);
    }
    if (!pFindWindowA) return 0;
    for (i = 0; kDbgWindows[i]; i++) {
        if (pFindWindowA(kDbgWindows[i], nullptr)) return 1;
    }
    return 0;
}

static const char* kDbgProcess[] = {
    "ollydbg.exe", "x64dbg.exe", "x32dbg.exe", "ida.exe", "ida64.exe",
    "idag.exe", "idaw.exe", "windbg.exe", "immunitydebugger.exe",
    "devenv.exe", "dumpcap.exe", "wireshark.exe", "processhacker.exe", nullptr
};

static int adProcessList(ARMOR_CTX* c)
{
    HANDLE snap;
    ARMOR_PROCENT pe;
    int found = 0;

    if (!c->pCreateToolhelp32Snapshot || !c->pProcess32FirstA || !c->pProcess32NextA) return 0;
    snap = c->pCreateToolhelp32Snapshot(0x00000002u, 0); /* TH32CS_SNAPPROCESS */
    if (snap == INVALID_HANDLE_VALUE) return 0;
    armor_fill(&pe, 0, sizeof(pe));
    pe.dwSize = sizeof(pe);
    if (c->pProcess32FirstA(snap, &pe)) {
        do {
            int i;
            for (i = 0; kDbgProcess[i]; i++) {
                if (armor_cmpi(pe.szExeFile, kDbgProcess[i]) == 0) { found = 1; break; }
            }
            if (found) break;
            pe.dwSize = sizeof(pe);
        } while (c->pProcess32NextA(snap, &pe));
    }
    if (c->pCloseHandle) c->pCloseHandle(snap);
    return found;
}

static int adTiming(ARMOR_CTX* c)
{
    au64 t0, t1;
    (void)c;
    t0 = __rdtsc();
    {
        volatile au32 acc = 0;
        int i;
        for (i = 0; i < 4096; i++) acc = acc * 1664525u + 1013904223u;
        if (acc == 0x1234u) return 1;
    }
    t1 = __rdtsc();
    /* 阈值取得较宽松，避免虚拟机/调度抖动造成误报 */
    if (t1 > t0 && (t1 - t0) > 20000000ull) return 1;
    return 0;
}

static int antiDebugCheck(ARMOR_CTX* c, int level2)
{
    if (adPebMarkers()) return 1;
    if (adKernelApi(c)) return 1;
    if (level2) {
        if (adWindows(c)) return 1;
        if (adProcessList(c)) return 1;
        if (adTiming(c)) return 1;
    }
    return 0;
}

/* --------------------------------------------------------- 映像还原 */

/* 判断 RVA 是否落在保留节（chars==0，已由加载器重定位过，外壳不得再次修正）。
   保留节含导入/导出表（.rdata）、资源（.rsrc）、重定位表（.reloc）等。 */
static int armorRelocInKeptSection(ARMOR_CTX* c, au32 rva)
{
    if (!c->hdr) return 0;
    {
        const ARMOR_SECTION* secs = (const ARMOR_SECTION*)(c->base + c->hdr->sectionsRva);
        au32 i;
        for (i = 0; i < c->hdr->sectionCount; i++) {
            if (secs[i].chars != 0) continue;
            if (secs[i].vsize == 0) continue;
            if (rva >= secs[i].rva && rva < secs[i].rva + secs[i].vsize) return 1;
        }
    }
    return 0;
}

static void applyRelocations(ARMOR_CTX* c)
{
    au8* img = c->base;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)img;
    ARMOR_NT* nt;
    const IMAGE_DATA_DIRECTORY* dd;
    au8* p;
    au32 left;

    if (c->delta == 0) return;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    nt = (ARMOR_NT*)(img + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;
    dd = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (!dd->VirtualAddress || !dd->Size) return;

    p = img + dd->VirtualAddress;
    left = dd->Size;
    while (left >= 8) {
        au32 page = armor_rd32(p);
        au32 blk = armor_rd32(p + 4);
        au32 n, k;
        if (blk < 8 || blk > left) break;
        n = (blk - 8) / 2;
        for (k = 0; k < n; k++) {
            au16 item = armor_rd16(p + 8 + k * 2);
            au32 type = item >> 12;
            au32 off = item & 0xFFFu;
            /* HIGHLOW=32 位加增量（x86），DIR64=64 位加增量（x64）；ABSOLUTE 为填充项 */
            if (type == ARMOR_RELOC_HIGHLOW || type == ARMOR_RELOC_DIR64) {
                if (armorRelocInKeptSection(c, page + off)) continue;
                armor_reloc_apply(img + page + off, type, c->delta);
            }
        }
        p += blk;
        left -= blk;
        if (blk == 0) break;
    }
}

static void buildImports(ARMOR_CTX* c)
{
    au8* img = c->base;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)img;
    ARMOR_NT* nt;
    const IMAGE_DATA_DIRECTORY* dd;
    PIMAGE_IMPORT_DESCRIPTOR desc;
    au32 guard = 0;

    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    nt = (ARMOR_NT*)(img + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;
    dd = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dd->VirtualAddress || !dd->Size) return;

    desc = (PIMAGE_IMPORT_DESCRIPTOR)(img + dd->VirtualAddress);
    for (; guard < 4096; guard++, desc++) {
        au32 thunkRva, oftRva;
        const ARMOR_THUNK* oft;
        ARMOR_THUNK* thunk;
        HMODULE mod;

        if (desc->Name == 0 && desc->FirstThunk == 0) break;
        if (desc->Name == 0) continue;

        mod = c->pLoadLibraryA((LPCSTR)(img + desc->Name));
        thunkRva = desc->FirstThunk;
        oftRva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
        if (!thunkRva || !oftRva) continue;
        thunk = (ARMOR_THUNK*)(img + thunkRva);
        oft = (const ARMOR_THUNK*)(img + oftRva);

        for (;;) {
            au64 v = oft->u1.AddressOfData;
            void* addr = nullptr;
            if (v == 0) break;
            if (mod) {
#if ARMOR_IS64
                if (ARMOR_ORDINAL_BIT(v)) {
                    au16 ord = (au16)(v & 0xFFFFull);
                    addr = (void*)c->pGetProcAddress(mod, (LPCSTR)(size_t)ord);
                } else {
                    PIMAGE_IMPORT_BY_NAME ibn = (PIMAGE_IMPORT_BY_NAME)(img + (size_t)v);
                    addr = (void*)c->pGetProcAddress(mod, (LPCSTR)&ibn->Name);
                }
#else
                if (ARMOR_ORDINAL_BIT(v)) {
                    au16 ord = (au16)(v & 0xFFFFu);
                    addr = (void*)c->pGetProcAddress(mod, (LPCSTR)(size_t)ord);
                } else {
                    PIMAGE_IMPORT_BY_NAME ibn = (PIMAGE_IMPORT_BY_NAME)(img + (size_t)v);
                    addr = (void*)c->pGetProcAddress(mod, (LPCSTR)&ibn->Name);
                }
#endif
            }
            thunk->u1.Function = (au64)(size_t)addr;
            oft++;
            thunk++;
        }
    }
}

static void applyTls(ARMOR_CTX* c, au32 tlsIndex)
{
    if (c->hdr->tlsOrigIndexRva)
        armor_wr32(c->base + c->hdr->tlsOrigIndexRva, tlsIndex);

    if (c->hdr->tlsCallbackRva) {
        const au8* cb = c->base + c->hdr->tlsCallbackRva;
        au32 i;
        for (i = 0; i < 128; i++) {
            au64 va;
#if ARMOR_IS64
            va = armor_rd64(cb + (size_t)i * 8);
#else
            va = (au64)armor_rd32(cb + (size_t)i * 4);
#endif
            if (va == 0) break;
            {
                typedef void(WINAPI* TLSCB)(void*, au32, void*);
                TLSCB fn = (TLSCB)(size_t)va;
                fn((void*)c->base, 1 /* DLL_PROCESS_ATTACH */, nullptr);
            }
        }
    }
}

static DWORD charsToProtect(au32 chars)
{
    int exe = (chars & IMAGE_SCN_MEM_EXECUTE) != 0;
    int wr = (chars & IMAGE_SCN_MEM_WRITE) != 0;
    if (exe) return wr ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
    if (wr) return PAGE_READWRITE;
    return PAGE_READONLY;
}

static void restoreProtections(ARMOR_CTX* c)
{
    const ARMOR_SECTION* secs = (const ARMOR_SECTION*)(c->base + c->hdr->sectionsRva);
    au32 i;
    for (i = 0; i < c->hdr->sectionCount; i++) {
        DWORD oldProt = 0;
        if (secs[i].chars == 0) continue;
        if (secs[i].vsize == 0) continue;
        c->pVirtualProtect(c->base + secs[i].rva, secs[i].vsize,
                           charsToProtect(secs[i].chars), &oldProt);
    }
}

static au32 stubRnd(ARMOR_CTX* c)
{
    c->rndState ^= c->rndState << 13;
    c->rndState ^= c->rndState >> 17;
    c->rndState ^= c->rndState << 5;
    return c->rndState;
}

static void obfuscateHeaders(ARMOR_CTX* c)
{
    au8* img = c->base;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)img;
    ARMOR_NT* nt;
    au32 lfa;
    int i, k;

    c->rndState = (au32)__rdtsc() ^ (au32)(size_t)img;
    if (c->rndState == 0) c->rndState = 0x9E3779B9u;

    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    lfa = (au32)dos->e_lfanew;
    if (lfa > 0x40 && lfa < 0x1000) {
        /* keep e_magic(0..2) and e_lfanew(0x3C..0x40) intact, otherwise
           RtlImageDirectoryEntryToData/FindResource/LoadIcon fail and the
           window loses its icon; zero out the rest of the DOS header and stub */
        armor_fill(img + 2, 0, 0x3C - 2);
        armor_fill(img + 0x40, 0, lfa - 0x40);
    }

    nt = (ARMOR_NT*)(img + lfa);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;
    {
        IMAGE_SECTION_HEADER* sh = (IMAGE_SECTION_HEADER*)((au8*)&nt->OptionalHeader +
                                                           nt->FileHeader.SizeOfOptionalHeader);
        int n = nt->FileHeader.NumberOfSections;
        if (n < 0 || n > 96) return;
        for (i = 0; i < n; i++) {
            for (k = 0; k < 8; k++) sh[i].Name[k] = (char)('a' + (stubRnd(c) % 26));
        }
    }
}

/* --------------------------------------------------------- 调试标记 */

/* 不依赖 ctx 的早期标记：自行解析 CreateFileA/WriteFile/CloseHandle，
   用于判断 StubEntry 是否启动、initApi 是否成功，独立于 dbgMark。 */
static void earlyMark(const char* tag)
{
#if 0 /* debug marks disabled */
    void* k32 = pebFindModule(0x29CDD463u);
    typedef HANDLE(WINAPI* PCF)(LPCSTR, DWORD, BOOL, void*, DWORD, DWORD, HANDLE);
    typedef BOOL(WINAPI* PWF)(HANDLE, LPCVOID, SIZE_T, LPDWORD, void*);
    typedef BOOL(WINAPI* PCH)(HANDLE);
    PCF pCF; PWF pWF; PCH pCH;
    HANDLE h; DWORD w = 0;
    char path[64];
    const char* p = "c:\\Users\\Administrator\\Desktop\\shell\\armor_early.txt";
    int i;
    for (i = 0; p[i] && i < 63; i++) path[i] = p[i];
    path[i] = 0;
    if (!k32) return;
    pCF = (PCF)getExportByName(k32, 0xBDCAC9CEu);
    if (!pCF) return;
    h = pCF(path, 0x0004 /*FILE_APPEND_DATA*/, 0, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    pWF = (PWF)getExportByName(k32, 0x7F07C44Au);
    pCH = (PCH)getExportByName(k32, 0xFABA0065u);
    if (pWF) pWF(h, tag, (DWORD)armor_len(tag), &w, nullptr);
    if (pCH) pCH(h);
#endif
}

static void dbgMark(ARMOR_CTX* c, const char* tag)
{
#if 0 /* debug marks disabled */
    if (!c || !c->pCreateFileA || !c->pWriteFile || !c->pCloseHandle) return;
    if (!tag) return;
    {
        /* 绝对路径（不依赖进程 cwd）；优先追加，pSetFilePointer 不可用时退化为覆盖 */
        char path[64];
        const char* p = "c:\\Users\\Administrator\\Desktop\\shell\\armor_dbg.txt";
        int i;
        for (i = 0; p[i] && i < 63; i++) path[i] = p[i];
        path[i] = 0;
        HANDLE h;
        DWORD w = 0;
        h = c->pCreateFileA(path, GENERIC_WRITE, 0, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h == INVALID_HANDLE_VALUE) return;
        if (c->pSetFilePointer) c->pSetFilePointer(h, 0, NULL, 2 /*FILE_END*/);
        c->pWriteFile(h, tag, (DWORD)armor_len(tag), &w, nullptr);
        c->pCloseHandle(h);
    }
#endif
}

/* --------------------------------------------------------------- 入口 */

extern "C" DWORD __cdecl StubEntry(HINSTANCE hinst, DWORD reason, LPVOID reserved)
{
    /* 注意：不可用 findModuleByAddr(_ReturnAddress()) 回溯 kernel32 基址。
       kernel32 在靠近基址处存在不可读页（NOACCESS），向下逐页回溯会在抵达
       MZ 头之前触发读访问违规而崩溃（已在 _tmp/probe.c 中复现验证）。
       改用 PEB 遍历获取 kernel32 基址（initApi 的兜底路径，已验证可靠）。 */
    ARMOR_CTX ctx;
    const volatile ARMOR_STUB_PARAMS* pp;
    const ARMOR_HEADER* hdr;
    au8* buf = nullptr;
    au8* payload;
    au32 tlsIndex = 0;
    int dbgFound = 0;
    int level2;
    DWORD oldProt = 0;

    (void)hinst;
    (void)reserved;

    earlyMark("S");

    armor_fill(&ctx, 0, sizeof(ctx));

    if (!initApi(&ctx)) {
        /* 关键 API 无法解析，无法继续 */
        earlyMark("IA0");
        return 0;
    }
    earlyMark("IA1");
    dbgMark(&ctx, "0");
    dbgMark(&ctx, "A");

    /* 确定自身映像基址 */
    {
        MEMORY_BASIC_INFORMATION mbi;
        armor_fill(&mbi, 0, sizeof(mbi));
        if (ctx.pVirtualQuery(&StubEntry, &mbi, sizeof(mbi)) && mbi.AllocationBase)
            ctx.base = (au8*)mbi.AllocationBase;
        else
            ctx.base = (au8*)pebExeBase();
    }
    if (!ctx.base) return 0;
    dbgMark(&ctx, "B");

    pp = &g_armorParams; /* keep volatile: otherwise compiler constant-folds params reads (default headerRva=0) and never sees packer-written values */
    if (pp->magic[0] != ARMOR_STUB_MAGIC0) return 0;
    dbgMark(&ctx, "C");
    dbgDword(&ctx, (au32)(size_t)&g_armorParams);
    dbgDword(&ctx, (au32)(size_t)ctx.base);
    dbgDword(&ctx, pp->magic[0]);
    dbgDword(&ctx, pp->magic[1]);
    dbgDword(&ctx, pp->magic[2]);
    dbgDword(&ctx, pp->magic[3]);
    dbgDword(&ctx, pp->headerRva);
    dbgDword(&ctx, pp->stubRva);
    hdr = (const ARMOR_HEADER*)(ctx.base + pp->headerRva);
    dbgDword(&ctx, hdr->magic);
    if (hdr->magic != ARMOR_MAGIC) return 0;
    dbgMark(&ctx, "D");
    ctx.hdr = hdr;

    /* 架构一致性：外壳映像位宽必须与打包目标一致 */
    if (hdr->is64 != (au32)ARMOR_IS64) return 0;

    /* DLL 非 ATTACH 通知（DETACH / THREAD_ATTACH / THREAD_DETACH）：
       直接转发给原 DllMain，不重复解压/还原（已还原的入口即原 DllMain，
       但加载器在后续通知中仍调用外壳入口地址，须在此转发）。 */
    if ((hdr->flags & ARMOR_F_IS_DLL) && reason != DLL_PROCESS_ATTACH) {
        typedef BOOL(WINAPI* PFN_DLLMAIN)(HINSTANCE, DWORD, LPVOID);
        PFN_DLLMAIN dm = (PFN_DLLMAIN)(ctx.base + hdr->oepRva);
        return (DWORD)dm((HINSTANCE)(size_t)ctx.base, reason, reserved);
    }

    /* 头部完整性校验 */
    {
        ARMOR_HEADER tmp;
        armor_copy(&tmp, hdr, sizeof(tmp));
        tmp.headerCrc = 0;
        if (armor_crc32(&tmp, sizeof(tmp)) != hdr->headerCrc) return 0;
    }
    dbgMark(&ctx, "E");

    level2 = (hdr->flags & ARMOR_F_ANTIDBG_L2) != 0;

    /* 载荷完整性校验 */
    payload = ctx.base + hdr->payloadRva;
    if (hdr->flags & ARMOR_F_CHECK_CRC) {
        if (armor_crc32(payload, hdr->payloadSize) != hdr->payloadCrc) {
            if (ctx.pExitProcess) ctx.pExitProcess(0);
            return 0;
        }
    }
    dbgMark(&ctx, "F");

    /* 从调试器隐藏当前线程 */
    if (hdr->flags & (ARMOR_F_ANTIDBG_EXIT | ARMOR_F_ANTIDBG_FAKE)) {
        if (ctx.pNtSetInformationThread && ctx.pGetCurrentThread)
            ctx.pNtSetInformationThread(ctx.pGetCurrentThread(), 0x11u, nullptr, 0);
    }

    /* 解密载荷 */
    if (hdr->flags & ARMOR_F_ENCRYPT) {
        ARMOR_RC4 rc4;
        ctx.pVirtualProtect(payload, hdr->payloadSize, PAGE_READWRITE, &oldProt);
        armor_rc4_init(&rc4, hdr->key, 16);
        armor_rc4_apply(&rc4, payload, hdr->payloadSize);
        ctx.pVirtualProtect(payload, hdr->payloadSize, oldProt, &oldProt);
    }

    /* 读取 TLS 索引（必须在覆盖 .arm0 之前读取） */
    if (hdr->tlsIndexRva) tlsIndex = armor_rd32(ctx.base + hdr->tlsIndexRva);

    /* 解压 */
    buf = (au8*)ctx.pVirtualAlloc(nullptr, (SIZE_T)hdr->unpackedSize + 16,
                                  MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!buf) {
        if (ctx.pExitProcess) ctx.pExitProcess(0);
        return 0;
    }
    dbgMark(&ctx, "G");
    if (armor_decompress(payload, hdr->payloadSize, buf, hdr->unpackedSize) != hdr->unpackedSize) {
        if (ctx.pExitProcess) ctx.pExitProcess(0);
        return 0;
    }
    dbgMark(&ctx, "H");

    /* 反调试 */
    dbgMark(&ctx, "I");
    if (hdr->flags & (ARMOR_F_ANTIDBG_EXIT | ARMOR_F_ANTIDBG_FAKE)) {
        dbgFound = antiDebugCheck(&ctx, level2);
        if (dbgFound && (hdr->flags & ARMOR_F_ANTIDBG_EXIT)) {
            if (ctx.pExitProcess) ctx.pExitProcess(0);
            return 0;
        }
    }

    /* 易语言特征区域解密（按打包时相反的顺序） */
    if ((hdr->flags & ARMOR_F_HIDE_FEAT) && hdr->hideCount && !dbgFound) {
        const ARMOR_HIDE_ENT* ents = (const ARMOR_HIDE_ENT*)(ctx.base + hdr->hideRva);
        au32 i = hdr->hideCount;
        while (i > 0) {
            const ARMOR_HIDE_ENT* e = &ents[--i];
            if ((size_t)e->rva + (size_t)e->len <= (size_t)hdr->unpackedSize) {
                au8 hk[16];
                ARMOR_RC4 rc4;
                armor_hide_key(hk, hdr->key, e->rva, e->len);
                armor_rc4_init(&rc4, hk, 16);
                armor_rc4_apply(&rc4, buf + e->rva, e->len);
            }
        }
    }

    /* 还原节区 */
    dbgMark(&ctx, "J");
    ctx.delta = (au64)((au64)(size_t)ctx.base - hdr->imageBase);
    {
        const ARMOR_SECTION* secs = (const ARMOR_SECTION*)(ctx.base + hdr->sectionsRva);
        au32 i;
        for (i = 0; i < hdr->sectionCount; i++) {
            if (secs[i].chars == 0) continue;
            if (secs[i].vsize == 0) continue;
            if ((size_t)secs[i].rva + (size_t)secs[i].vsize > (size_t)hdr->unpackedSize) continue;
            armor_copy(ctx.base + secs[i].rva, buf + secs[i].rva, secs[i].vsize);
        }
    }

    /* 还原 PE 头并修正 ImageBase */
    if (hdr->headersSize) {
        DWORD hdrOldProt = 0;
        /* PE header region (RVA 0x0) not covered by any section, default read-only; make writable first */
        if (ctx.pVirtualProtect)
            ctx.pVirtualProtect(ctx.base, hdr->headersSize, PAGE_READWRITE, &hdrOldProt);
        armor_copy(ctx.base, buf, hdr->headersSize);
        {
            PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ctx.base;
            if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
                ARMOR_NT* nt = (ARMOR_NT*)(ctx.base + dos->e_lfanew);
                if (nt->Signature == IMAGE_NT_SIGNATURE) {
#if ARMOR_IS64
                    nt->OptionalHeader.ImageBase = (ULONGLONG)(size_t)ctx.base;
#else
                    nt->OptionalHeader.ImageBase = (DWORD)(size_t)ctx.base;
#endif
                }
            }
        }
    }
    dbgMark(&ctx, "K");

    /* 重定位 / 导入表 / TLS */
    applyRelocations(&ctx);
    dbgMark(&ctx, "L");
    if (!(hdr->flags & ARMOR_F_IS_DLL)) {
        /* DLL：IAT 已由加载器填充（.rdata 保留），外壳不重建导入表 */
        buildImports(&ctx);
    }
    dbgMark(&ctx, "M");
    applyTls(&ctx, tlsIndex);
    dbgMark(&ctx, "N");

    /* 还原节区保护属性 */
    restoreProtections(&ctx);
    dbgMark(&ctx, "O");

    /* 反 dump：混淆 PE 头（DLL 模式跳过——宿主进程与 GetProcAddress 仍需读取 PE 头） */
    if (!(hdr->flags & ARMOR_F_IS_DLL) && (hdr->flags & ARMOR_F_ANTIDUMP)) obfuscateHeaders(&ctx);

    if (hdr->flags & ARMOR_F_IS_DLL) {
        /* DLL_PROCESS_ATTACH：加载器已解析导入/导出并填好 IAT（.rdata 保留），
           外壳不重建导入表；解压还原完成后同步调用原 DllMain(ATTACH) 并返回其值。
           后续 DLL_THREAD_ATTACH / DLL_THREAD_DETACH / DLL_PROCESS_DETACH
           已在入口处转发给原 DllMain，不再进入本流程。 */
        if (ctx.pFlushInstructionCache && ctx.pGetCurrentProcess)
            ctx.pFlushInstructionCache(ctx.pGetCurrentProcess(), nullptr, 0);
        {
            typedef BOOL(WINAPI* PFN_DLLMAIN)(HINSTANCE, DWORD, LPVOID);
            PFN_DLLMAIN dm = (PFN_DLLMAIN)(ctx.base + hdr->oepRva);
            return (DWORD)dm((HINSTANCE)(size_t)ctx.base, DLL_PROCESS_ATTACH, nullptr);
        }
    }

    {
        typedef void(__cdecl* PFN_OEP)(void);
        PFN_OEP oep = (PFN_OEP)(ctx.base + hdr->oepRva);
        if (ctx.pFlushInstructionCache && ctx.pGetCurrentProcess)
            ctx.pFlushInstructionCache(ctx.pGetCurrentProcess(), nullptr, 0);
        oep();
    }
    dbgMark(&ctx, "P");

    if (ctx.pExitProcess) ctx.pExitProcess(0);
    return 0;
}
