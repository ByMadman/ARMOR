#ifndef ARMOR_PEFLAT_H
#define ARMOR_PEFLAT_H

/* 把一个 PE 文件转换成"扁平映像"（等价于被加载后的内存布局），
   供打包器嵌入为外壳代码。仅用于构建期工具（打包器 / mkstub），不进入外壳。
   同时支持 PE32（x86）与 PE32+（x64）两种输入。 */

#include "armor_base.h"

#include <string>
#include <vector>

struct FlatImage {
    std::vector<au8> image; /* 扁平映像，索引即 RVA，头部区域清零 */
    au64 imageBase = 0;
    au32 entryRva = 0;
    au32 sizeOfImage = 0;
    au32 paramRva = 0;   /* .apar 参数节 RVA */
    au32 paramSize = 0;
    au32 machine = 0;    /* IMAGE_FILE_MACHINE_* */
    bool is64 = false;   /* true = PE32+ */

    /* 需要重定位的项：ARMOR_RELOC_PACK(rva, type) 打包后的值 */
    std::vector<au32> relocs;

    std::string stubSection;  /* 参数节名称，供诊断使用 */
};

/* 成功返回 true，失败时 err 给出原因 */
bool peBuildFlatImage(const au8* fileData, size_t fileSize, FlatImage& out, std::string& err);

#endif /* ARMOR_PEFLAT_H */
