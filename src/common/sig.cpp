#include "sig.h"
#include "sig_default.h"

#include <ctype.h>

namespace {

inline bool isSpaceCh(char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

std::string trimStr(const std::string& s)
{
    size_t a = 0, b = s.size();
    while (a < b && isSpaceCh(s[a])) a++;
    while (b > a && isSpaceCh(s[b - 1])) b--;
    return s.substr(a, b - a);
}

int hexVal(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

} /* namespace */

size_t sigParseText(const std::string& text, std::vector<SigPattern>& out, std::string& err)
{
    size_t pos = 0;
    size_t count = 0;
    err.clear();

    /* 跳过 UTF-8 BOM */
    if (text.size() >= 3 && (au8)text[0] == 0xEF && (au8)text[1] == 0xBB && (au8)text[2] == 0xBF)
        pos = 3;

    while (pos < text.size()) {
        size_t eol = text.find('\n', pos);
        if (eol == std::string::npos) eol = text.size();
        std::string line = trimStr(text.substr(pos, eol - pos));
        pos = eol + 1;

        if (line.empty() || line[0] == ';' || line[0] == '#') continue;
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;

        std::string name = trimStr(line.substr(0, eq));
        std::string hex = trimStr(line.substr(eq + 1));
        if (name.empty() || hex.empty()) continue;

        std::string compact;
        for (size_t i = 0; i < hex.size(); i++) {
            char c = hex[i];
            if (isSpaceCh(c)) continue;
            compact.push_back(c);
        }
        if (compact.size() < 2 || (compact.size() % 2) != 0) {
            err = "特征 " + name + " 的十六进制串长度非法";
            continue;
        }

        SigPattern pat;
        pat.name = name;
        bool bad = false;
        for (size_t i = 0; i < compact.size(); i += 2) {
            char c0 = compact[i], c1 = compact[i + 1];
            if (c0 == '?' && c1 == '?') {
                pat.bytes.push_back(0);
                pat.mask.push_back(0);
                continue;
            }
            int hi = hexVal(c0);
            int lo = hexVal(c1);
            if (hi < 0 || lo < 0) { bad = true; break; }
            pat.bytes.push_back((au8)((hi << 4) | lo));
            pat.mask.push_back(1);
        }
        if (bad || pat.bytes.empty()) {
            err = "特征 " + name + " 含非法字节";
            continue;
        }
        out.push_back(pat);
        count++;
    }
    return count;
}

void sigScanImage(const au8* image, size_t imageSize,
                  const std::vector<SigPattern>& pats,
                  std::vector<SigResult>& out, size_t maxHits)
{
    out.clear();
    for (size_t pi = 0; pi < pats.size(); pi++) {
        const SigPattern& pat = pats[pi];
        const size_t len = pat.bytes.size();
        SigResult res;
        res.patternIndex = (int)pi;
        res.name = pat.name;

        if (len > imageSize) { out.push_back(res); continue; }

        /* 取第一个确定字节作为锚点，用 memchr 快速定位 */
        size_t anchor = 0;
        bool found = false;
        for (size_t i = 0; i < len; i++) {
            if (pat.mask[i]) { anchor = i; found = true; break; }
        }

        const au8* p = image;
        const au8* last = image + (imageSize - len);

        if (!found) {
            for (const au8* q = image; q <= last; q++) {
                res.hitCount++;
                if (res.hits.size() < maxHits) res.hits.push_back((au32)(q - image));
            }
        } else {
            au8 anchorByte = pat.bytes[anchor];
            while (p <= last) {
                const au8* hit = (const au8*)memchr(p, (int)anchorByte, (size_t)(last - p) + 1);
                if (!hit) break;
                if (hit < image + anchor) { p = hit + 1; continue; }
                const au8* start = hit - anchor;
                if (start < image || start > last) { p = hit + 1; continue; }
                {
                    size_t i = 0;
                    bool ok = true;
                    for (i = 0; i < len; i++) {
                        if (pat.mask[i] && start[i] != pat.bytes[i]) { ok = false; break; }
                    }
                    if (ok) {
                        res.hitCount++;
                        if (res.hits.size() < maxHits) res.hits.push_back((au32)(start - image));
                    }
                }
                p = hit + 1;
            }
        }
        out.push_back(res);
    }
}

const char* sigDefaultText()
{
    return kArmorDefaultSignatures;
}
