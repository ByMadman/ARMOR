#ifndef ARMOR_UTF8UTIL_H
#define ARMOR_UTF8UTIL_H

#include <string>

std::string wideToUtf8(const std::wstring& w);
std::wstring utf8ToWide(const std::string& s);

/* 读取整个文件到字符串（二进制安全） */
bool readFileToString(const std::wstring& path, std::string& out);

#endif /* ARMOR_UTF8UTIL_H */
