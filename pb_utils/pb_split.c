/*
 * pb_split.c — protobuf 批量分列核心 (无 schema wire-format 解析)
 *
 * 设计要点 (对应 split_pb_fields 的 C 移植 + 修正):
 *   - varint 用 uint64_t: 毫秒时间戳/大 ID 不再溢出 (修复 BufferReader/C 版 int 溢出)
 *   - 所有读取带 buf_len 边界检查: 坏数据返回错误码, 不越界 (修复 segfault 风险)
 *   - shift >= 64 保护: 畸形 varint 可控报错
 *   - 每次消息只跨一次语言边界: rows 数组一次返回, 免逐 varint ctypes 开销
 *   - 输出带 depth/start/end: 分列展示可直接表达层级和字节定位
 *
 * 分类判定 (length_delimited value):
 *   1) 含控制字节 (0x00-0x08,0x0B,0x0C,0x0E-0x1F,0x7F) → 严格消息解析
 *      成功(恰好消费完) → Message(递归展开); 失败 → 走 2)
 *   2) 无控制字节 → UTF-8 校验 + 可读率 >= 0.68 → String; 否则 Bytes
 *   相比 Python 版的 string-first: 文本型子消息(如 f1{"cid=..."})不再被吞掉
 *
 * 构建:
 *   macOS:  clang -O2 -shared -fPIC -o libpb_split.dylib pb_split.c
 *   Linux:  gcc   -O2 -shared -fPIC -o libpb_split.so    pb_split.c
 *   Windows: cl /O2 /LD pb_split.c /Felibpb_split.dll
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __attribute__((visibility("default")))
#endif

#define WT_VARINT  0
#define WT_FIXED64 1
#define WT_LEN     2
#define WT_FIXED32 5

/* flags */
#define PF_VARINT  0x01
#define PF_STRING  0x02
#define PF_MESSAGE 0x04
#define PF_BYTES   0x08
#define PF_FIXED   0x10

/* error codes */
#define PB_OK            0
#define PB_ERR_TRUNCATED 1   /* 数据截断 */
#define PB_ERR_WIRETYPE  2   /* 非法 wire type / field 0 */
#define PB_ERR_VARINT    3   /* varint 超长 (>10 字节) */
#define PB_ERR_NOMEM     4

typedef struct {
    uint32_t field_num;
    uint32_t depth;
    uint64_t start;      /* tag 字节在输入中的偏移 */
    uint64_t end;        /* 字段末尾 (含值) */
    uint64_t value_off;  /* 值区起始偏移 (仅 wt==2/1/5 有效) */
    int64_t  value;      /* wt==0 时的 varint 原始值 (无符号解释) */
    uint8_t  wire_type;
    uint8_t  flags;
} PbFieldRow;

typedef struct {
    PbFieldRow *rows;
    size_t      count;
    int         error;
    size_t      error_offset;
} PbSplitResult;

typedef struct {
    PbFieldRow *rows;
    size_t      count;
    size_t      cap;
    int         max_depth;
    int         error;
    size_t      error_offset;
} Ctx;

static int rows_reserve(Ctx *c, size_t need)
{
    if (need <= c->cap) return 0;
    size_t ncap = c->cap ? c->cap * 2 : 4096;
    while (ncap < need) ncap *= 2;
    PbFieldRow *nr = (PbFieldRow *)realloc(c->rows, ncap * sizeof(PbFieldRow));
    if (!nr) { c->error = PB_ERR_NOMEM; return -1; }
    c->rows = nr;
    c->cap = ncap;
    return 0;
}

static int emit(Ctx *c, uint32_t fn, uint8_t wt, int depth,
                uint64_t start, uint64_t end, uint64_t voff,
                int64_t value, uint8_t flags)
{
    if (rows_reserve(c, c->count + 1) != 0) return -1;
    PbFieldRow *r = &c->rows[c->count++];
    r->field_num = fn;
    r->depth     = (uint32_t)depth;
    r->start     = start;
    r->end       = end;
    r->value_off = voff;
    r->value     = value;
    r->wire_type = wt;
    r->flags     = flags;
    return 0;
}

/* 返回 0 成功; -1 失败 (c->error/error_offset 已设置) */
static int read_varint(const unsigned char *buf, size_t len, size_t *pos, uint64_t *out)
{
    Ctx *noop = NULL; (void)noop;
    uint64_t v = 0;
    int shift = 0;
    while (1) {
        if (*pos >= len) return PB_ERR_TRUNCATED;
        unsigned char b = buf[(*pos)++];
        v |= (uint64_t)(b & 0x7F) << shift;
        if (!(b & 0x80)) break;
        shift += 7;
        if (shift >= 64) return PB_ERR_VARINT;
    }
    *out = v;
    return PB_OK;
}

/* 是否含控制字节 (0x09/0x0A/0x0D 与 0x20-0x7E 及 >=0x80 视为非控制) */
static int has_control_byte(const unsigned char *b, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        unsigned char x = b[i];
        if (x < 0x20 && x != 0x09 && x != 0x0A && x != 0x0D) return 1;
        if (x == 0x7F) return 1;
    }
    return 0;
}

/* UTF-8 严格校验 (含 overlong/代理区边界) + 可读率; 返回 1=合法 UTF-8 */
static int utf8_check(const unsigned char *b, size_t n, double *ratio)
{
    size_t i = 0, readable = 0;
    while (i < n) {
        unsigned char x = b[i];
        if (x == 0x09 || x == 0x0A || x == 0x0D || (x >= 0x20 && x <= 0x7E)) {
            readable++; i++; continue;
        }
        size_t cont; unsigned char lo = 0x80, hi = 0xBF;
        if (x >= 0xC2 && x <= 0xDF) cont = 1;
        else if (x >= 0xE0 && x <= 0xEF) { cont = 2; if (x == 0xE0) lo = 0xA0; if (x == 0xED) hi = 0x9F; }
        else if (x >= 0xF0 && x <= 0xF4) { cont = 3; if (x == 0xF0) lo = 0x90; if (x == 0xF4) hi = 0x8F; }
        else return 0;
        if (i + cont >= n) return 0;   /* 截断 */
        if (b[i + 1] < lo || b[i + 1] > hi) return 0;
        for (size_t k = 2; k <= cont; k++)
            if (b[i + k] < 0x80 || b[i + k] > 0xBF) return 0;
        readable += cont + 1;
        i += cont + 1;
    }
    *ratio = n ? (double)readable / (double)n : 0.0;
    return 1;
}

/*
 * 解析一层消息的所有字段并输出行 (子消息递归展开, 前序遍历).
 * 返回 0 成功 (恰好消费完 len); 非 0 失败 (c->error 已设置).
 * 失败时由调用方回滚 rows (try_parse_children).
 */
static int try_parse_children(Ctx *c, const unsigned char *buf, size_t len, int depth, uint64_t base);

static int parse_level(Ctx *c, const unsigned char *buf, size_t len, int depth, uint64_t base)
{
    size_t pos = 0;
    while (pos < len) {
        uint64_t start = base + pos;
        uint64_t tag;
        int rc = read_varint(buf, len, &pos, &tag);
        if (rc) { c->error = rc; c->error_offset = start; return -1; }

        uint32_t fn = (uint32_t)(tag >> 3);
        uint8_t  wt = (uint8_t)(tag & 7);
        if (fn == 0) { c->error = PB_ERR_WIRETYPE; c->error_offset = start; return -1; }

        if (wt == WT_VARINT) {
            uint64_t v;
            rc = read_varint(buf, len, &pos, &v);
            if (rc) { c->error = rc; c->error_offset = start; return -1; }
            if (emit(c, fn, wt, depth, start, base + pos, base + pos, (int64_t)v, PF_VARINT)) return -1;
        } else if (wt == WT_LEN) {
            uint64_t l;
            rc = read_varint(buf, len, &pos, &l);
            if (rc) { c->error = rc; c->error_offset = start; return -1; }
            if (pos + l > len) { c->error = PB_ERR_TRUNCATED; c->error_offset = base + pos; return -1; }
            const unsigned char *sub = buf + pos;
            size_t sublen = (size_t)l;

            double ratio = 0.0;
            int utf8ok = utf8_check(sub, sublen, &ratio);

            /* 消歧规则 (对齐 pb_split.py):
             *   乐观先发父行(MESSAGE) + 递归子行, 然后判定:
             *   - 子行存在(>=2 行, 含孙行) 或 值含控制字节 → Message
             *     (Poster 型 f1{标题}+f4{url}: tag/长度字节恰好全可打印,
     *      无控制字节, 但 >=2 个字符串字段足以认定结构)
             *   - 解析成功但仅 1 行 且 无控制字节 → 纯文本碰巧可解析 → String
             *   - 解析失败 → utf8 合法且可读率>=0.68 → String, 否则 Bytes
             *   空值 → Bytes */
            if (sublen > 0 && depth < c->max_depth) {
                if (rows_reserve(c, c->count + 1)) return -1;
                size_t parent_idx = c->count;
                if (emit(c, fn, wt, depth, start, base + pos + l, base + pos, 0, PF_MESSAGE)) return -1;
                size_t saved_count = c->count;
                int sub_ok = (try_parse_children(c, sub, sublen, depth + 1, base + pos) == 0);
                size_t nf = c->count - saved_count;          /* 子行数 (含孙行) */
                int has_ctrl = has_control_byte(sub, sublen);
                /* 单 len-delim 子行且内容为文本 = 内嵌消息特征 (如 Poster 只含 f4{url}) */
                int any_len_text = 0;
                for (size_t k = saved_count; k < c->count; k++)
                    if (c->rows[k].wire_type == WT_LEN &&
                        (c->rows[k].flags & (PF_STRING | PF_MESSAGE))) { any_len_text = 1; break; }
                if (!(sub_ok && (has_ctrl || nf >= 2 || any_len_text))) {
                    c->count = saved_count;   /* 回滚子行 */
                    c->rows[parent_idx].flags =
                        (utf8ok && ratio >= 0.68) ? PF_STRING : PF_BYTES;
                }
            } else {
                /* 空值 / 深度超限 → 直接叶子 */
                uint8_t flags = (utf8ok && ratio >= 0.68 && sublen > 0) ? PF_STRING : PF_BYTES;
                if (emit(c, fn, wt, depth, start, base + pos + l, base + pos, 0, flags)) return -1;
            }
            pos += l;
        } else if (wt == WT_FIXED32) {
            if (pos + 4 > len) { c->error = PB_ERR_TRUNCATED; c->error_offset = base + pos; return -1; }
            if (emit(c, fn, wt, depth, start, base + pos + 4, base + pos, 0, PF_FIXED)) return -1;
            pos += 4;
        } else if (wt == WT_FIXED64) {
            if (pos + 8 > len) { c->error = PB_ERR_TRUNCATED; c->error_offset = base + pos; return -1; }
            if (emit(c, fn, wt, depth, start, base + pos + 8, base + pos, 0, PF_FIXED)) return -1;
            pos += 8;
        } else {
            c->error = PB_ERR_WIRETYPE; c->error_offset = start; return -1;
        }
    }
    return 0;
}

/* 尝试性解析: 失败则回滚 rows 和 error 状态, 返回非 0 */
static int try_parse_children(Ctx *c, const unsigned char *buf, size_t len, int depth, uint64_t base)
{
    size_t saved_count = c->count;
    int    saved_error = c->error;
    size_t saved_off   = c->error_offset;
    c->error = PB_OK;
    if (parse_level(c, buf, len, depth, base) != 0) {
        c->count = saved_count;
        c->error = saved_error;
        c->error_offset = saved_off;
        return -1;
    }
    return 0;
}

EXPORT PbSplitResult pb_split(const unsigned char *buf, size_t len, int max_depth)
{
    Ctx c;
    memset(&c, 0, sizeof(c));
    c.max_depth = max_depth > 0 ? max_depth : 64;
    if (rows_reserve(&c, 4096) != 0) {
        PbSplitResult bad = { NULL, 0, PB_ERR_NOMEM, 0 };
        return bad;
    }
    parse_level(&c, buf, len, 0, 0);
    PbSplitResult r;
    r.rows = c.rows;
    r.count = c.count;
    r.error = c.error;
    r.error_offset = c.error_offset;
    return r;
}

EXPORT void pb_split_free(PbSplitResult *r)
{
    if (r && r->rows) { free(r->rows); r->rows = NULL; }
    if (r) r->count = 0;
}
