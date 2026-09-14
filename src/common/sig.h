#ifndef ARMOR_SIG_H
#define ARMOR_SIG_H

/* 易语言特征扫描引擎。
   特征文件格式：每行 "名称=十六进制串"，十六进制串允许空格分隔，"??" 表示通配字节。
   例如：按钮事件1=55 8B EC 83 EC 18 ... */

#include "armor_base.h"

#include <string>
#include <vector>

struct SigPattern {
    std::string name;
    std::vector<au8> bytes;
    std::vector<au8> mask; /* 1 表示必须匹配，0 表示通配 */
};

struct SigResult {
    int patternIndex = 0;
    std::string name;
    au32 hitCount = 0;
    std::vector<au32> hits; /* 命中的 RVA（截断到 maxHits） */
};

/* 解析特征文本，返回成功解析的条目数 */
size_t sigParseText(const std::string& text, std::vector<SigPattern>& out, std::string& err);

/* 在扁平映像中扫描。maxHits 为每个特征最多保存的命中数（计数不受限制） */
void sigScanImage(const au8* image, size_t imageSize,
                  const std::vector<SigPattern>& pats,
                  std::vector<SigResult>& out, size_t maxHits);

/* 内置默认特征（易语言部分特征），外部 signatures.txt 不存在时使用 */
const char* sigDefaultText();

#endif /* ARMOR_SIG_H */
