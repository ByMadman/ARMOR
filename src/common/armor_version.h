#ifndef ARMOR_VERSION_H
#define ARMOR_VERSION_H

/* ARMOR 工具自身的版本与作者信息。
 *
 * 本头文件同时被 C/C++ 源（main.cpp）与资源脚本（*.rc）包含，
 * 因此只使用两者都能理解的宏定义：
 *   - 数值宏供 .rc 的 FILEVERSION / PRODUCTVERSION 使用
 *   - 字符串宏供 .rc 的 VALUE 与 C++ 的 printf 使用
 *
 * 注意：这里的版本是"ARMOR 工具版本"，与打包格式版本
 * （packfmt.h 里的 ARMOR_VERSION，当前为 2）是两个不同的概念。
 *
 * .rc 文件请保持纯 ASCII：rc.exe 不保证按 UTF-8 解析源码，
 * 非 ASCII 字符串容易生成乱码的版本资源。 */

#define ARMOR_APP_NAME       "ARMOR"
#define ARMOR_APP_AUTHOR     "byHandsome"
#define ARMOR_APP_QQGroup    "647765957"
#define ARMOR_APP_VER_MAJOR  2
#define ARMOR_APP_VER_MINOR  0
#define ARMOR_APP_VER_PATCH  0
#define ARMOR_APP_VERSION    "2.0.0"
#define ARMOR_APP_COPYRIGHT  "Copyright (c) 2026 byHandsome"

#endif /* ARMOR_VERSION_H */
