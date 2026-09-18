#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pb_split.py — 无 schema protobuf 批量分列工具
==============================================
自动选择引擎:
  - libpb_split (C 扩展) 存在 → ctypes 批量解析 (3MB ≈ 0.7s)
  - 不存在 → 纯 Python 降级实现 (语义与 C 版完全一致, 慢 ~3.5x)

两引擎输出逐行一致, API 相同:

    from pb_split import split_fields, rows_to_tree

    rows = split_fields(data)            # [(depth, field_num, wire_type, value, start, end), ...]
    tree = rows_to_tree(rows)            # 嵌套 dict 树
    rows = split_fields(data, engine='python')   # 强制纯 Python
    rows = split_fields(data, engine='c')        # 强制 C (缺库时报错)

行语义:
    depth        嵌套深度, 0 = 顶层
    field_num    字段号
    wire_type    'varint' / 'fixed64' / 'length_delimited' / 'fixed32'
    value        varint → 无符号 int; string → str; message → '(Message)';
                 bytes/fixed → bytes
    start/end    字段(含 tag)在输入中的字节偏移, 可回定位

分类规则 (length_delimited value):
    含控制字节(0x00-0x08,0x0B,0x0C,0x0E-0x1F,0x7F) → 尝试严格消息解析,
    恰好消费完 → Message; 失败 → UTF-8 合法且可读率>=0.68 → String, 否则 Bytes.
    纯文本(无控制字节) → 直接 String. 空值 → Bytes.

C 库构建 (可选, 不构建则自动降级):
    macOS:   clang -O2 -shared -fPIC -o libpb_split.dylib pb_split.c
    Linux:   gcc   -O2 -shared -fPIC -o libpb_split.so    pb_split.c
    Windows: cl /O2 /LD pb_split.c /Felibpb_split.dll
"""

import ctypes
import os
import sys

__all__ = ['split_fields', 'rows_to_tree', 'rows_to_dict', 'interpret_fixed', 'WireError']

WT_NAMES = {0: 'varint', 1: 'fixed64', 2: 'length_delimited', 5: 'fixed32'}
PF_VARINT, PF_STRING, PF_MESSAGE, PF_BYTES, PF_FIXED = 0x01, 0x02, 0x04, 0x08, 0x10
_MASK64 = (1 << 64) - 1


class WireError(ValueError):
    """wire 数据畸形 (带 offset)"""

    def __init__(self, msg, offset):
        super().__init__(f'malformed protobuf: {msg} at offset {offset}')
        self.offset = offset


# ============================================================================
# 公共字节级判定 (C 速: translate 删除法)
# ============================================================================

# 控制字节: <0x20 且非 \t\n\r, 以及 0x7F
_CTRL_BYTES = bytes(i for i in range(256)
                    if (i < 0x20 and i not in (9, 10, 13)) or i == 0x7F)


def _utf8_ratio(data):
    """返回 (是否合法 UTF-8, 可读字节率). 与 C 版 utf8_check 语义一致."""
    if not data:
        return True, 0.0
    try:
        data.decode('utf-8')
    except UnicodeDecodeError:
        return False, 0.0
    kept = data.translate(None, _CTRL_BYTES)
    return True, len(kept) / len(data)


def _has_control(data):
    return len(data.translate(None, _CTRL_BYTES)) < len(data)


# ============================================================================
# 纯 Python 引擎 (降级用; 语义与 pb_split.c 严格对齐)
# ============================================================================

class _Malformed(Exception):
    def __init__(self, msg, offset):
        super().__init__(msg)
        self.msg = msg
        self.offset = offset


def _read_varint(buf, pos, n):
    v = 0
    shift = 0
    while True:
        if pos >= n:
            raise _Malformed('数据截断', -1)   # offset 由调用方按字段起点补
        b = buf[pos]
        pos += 1
        v |= (b & 0x7F) << shift
        if not (b & 0x80):
            return v, pos
        shift += 7
        if shift >= 64:
            raise _Malformed('varint 超长 (>10 字节)', -1)


def _parse_py(buf, base, depth, out, max_depth, err):
    """
    解析一层消息, 前序追加行到 out.
    成功返回 True; 失败设置 err[0]=(msg, offset), 回滚 out, 返回 False.
    错误状态传递镜像 pb_split.c 的 Ctx.error / try_parse_children 恢复逻辑.
    """
    mark = len(out)
    saved = err[0]
    err[0] = None
    try:
        pos = 0
        n = len(buf)
        while pos < n:
            start = base + pos
            try:
                tag, pos = _read_varint(buf, pos, n)
            except _Malformed as e:
                raise _Malformed(e.msg, start) from None
            fn = tag >> 3
            wt = tag & 7
            if fn == 0:
                raise _Malformed('field 0', start)

            if wt == 0:
                try:
                    v, pos = _read_varint(buf, pos, n)
                except _Malformed as e:
                    raise _Malformed(e.msg, start) from None
                out.append((depth, fn, 'varint', v & _MASK64, start, base + pos))

            elif wt == 2:
                try:
                    l, pos = _read_varint(buf, pos, n)
                except _Malformed as e:
                    raise _Malformed(e.msg, start) from None
                if pos + l > n:
                    raise _Malformed('数据截断', base + pos)
                vstart, vend = base + pos, base + pos + l
                sub = bytes(buf[pos:pos + l])
                pos += l

                # 消歧规则 (对齐 pb_split.c):
                #   乐观先发父行(MESSAGE) + 递归子行, 然后判定:
                #   - 子行 >=2 (含孙行) 或 值含控制字节 → Message
                #     (Poster 型 f1{标题}+f4{url}: tag/长度字节恰好全可打印,
                #      无控制字节, 但 >=2 个字符串字段足以认定结构)
                #   - 解析成功但仅 1 行 且 无控制字节 → 纯文本碰巧可解析 → String
                #   - 解析失败 → utf8 合法且可读率 >=0.68 → String, 否则 Bytes
                #   空值 → Bytes
                if sub and depth < max_depth:
                    out.append((depth, fn, 'length_delimited', '(Message)', start, vend))
                    mark_children = len(out)
                    ok = _parse_py(sub, vstart, depth + 1, out, max_depth, err)
                    n_children = len(out) - mark_children      # 子行数 (含孙行)
                    has_ctrl = _has_control(sub)
                    if not (ok and (has_ctrl or n_children >= 2)):
                        del out[mark_children - 1:]
                        err[0] = saved          # 镜像 C: 恢复调用方错误状态
                        ok_u, ratio = _utf8_ratio(sub)
                        val = sub.decode('utf-8') if (ok_u and ratio >= 0.68) else sub
                        out.append((depth, fn, 'length_delimited', val, start, vend))
                else:
                    # 空值 / 深度超限 → 直接叶子
                    ok, ratio = _utf8_ratio(sub)
                    val = sub.decode('utf-8') if (ok and ratio >= 0.68 and sub) else sub
                    out.append((depth, fn, 'length_delimited', val, start, vend))

            elif wt == 5:
                if pos + 4 > n:
                    raise _Malformed('数据截断', base + pos)
                out.append((depth, fn, 'fixed32', bytes(buf[pos:pos + 4]), start, base + pos + 4))
                pos += 4

            elif wt == 1:
                if pos + 8 > n:
                    raise _Malformed('数据截断', base + pos)
                out.append((depth, fn, 'fixed64', bytes(buf[pos:pos + 8]), start, base + pos + 8))
                pos += 8

            else:
                raise _Malformed(f'非法 wire type {wt}', start)
        return True
    except _Malformed as e:
        del out[mark:]
        err[0] = (e.msg, e.offset)
        return False


def _split_py(data, max_depth):
    err = [None]
    rows = []
    if not _parse_py(data, 0, 0, rows, max_depth, err):
        msg, off = err[0] if err[0] else ('未知错误', 0)
        raise WireError(msg, off)
    return rows


# ============================================================================
# C 引擎 (ctypes 绑定)
# ============================================================================

class _PbFieldRow(ctypes.Structure):
    _fields_ = [
        ("field_num", ctypes.c_uint32),
        ("depth",     ctypes.c_uint32),
        ("start",     ctypes.c_uint64),
        ("end",       ctypes.c_uint64),
        ("value_off", ctypes.c_uint64),
        ("value",     ctypes.c_int64),
        ("wire_type", ctypes.c_uint8),
        ("flags",     ctypes.c_uint8),
    ]


class _PbSplitResult(ctypes.Structure):
    _fields_ = [
        ("rows",         ctypes.POINTER(_PbFieldRow)),
        ("count",        ctypes.c_size_t),
        ("error",        ctypes.c_int),
        ("error_offset", ctypes.c_size_t),
    ]


_LIB = None
_LIB_FAILED = False

_ERROR_MSG = {
    1: '数据截断',
    2: '非法 wire type / field 0',
    3: 'varint 超长 (>10 字节)',
    4: '内存分配失败',
}


def _load():
    global _LIB, _LIB_FAILED
    if _LIB is not None:
        return _LIB
    if _LIB_FAILED:
        return None
    if sys.platform == 'darwin':
        name = 'libpb_split.dylib'
    elif sys.platform == 'win32':
        name = 'libpb_split.dll'
    else:
        name = 'libpb_split.so'
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), name)
    try:
        lib = ctypes.CDLL(path)
        lib.pb_split.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_int]
        lib.pb_split.restype = _PbSplitResult
        lib.pb_split_free.argtypes = [ctypes.POINTER(_PbSplitResult)]
        _LIB = lib
        return lib
    except OSError:
        _LIB_FAILED = True     # 缓存失败, 后续直接走纯 Python
        return None


def _split_c(data, max_depth):
    lib = _load()
    if lib is None:
        raise OSError('libpb_split 不可用')
    res = lib.pb_split(bytes(data), len(data), max_depth)
    try:
        if res.error:
            msg = _ERROR_MSG.get(res.error, f'错误码{res.error}')
            raise WireError(msg, res.error_offset)
        rows = []
        for i in range(res.count):
            r = res.rows[i]
            wt = WT_NAMES.get(r.wire_type, f'wt{r.wire_type}')
            flags = r.flags
            if flags & PF_MESSAGE:
                value = '(Message)'
            elif flags & PF_STRING:
                value = data[r.value_off:r.end].decode('utf-8')
            elif flags & PF_VARINT:
                value = r.value & _MASK64
            else:
                value = bytes(data[r.value_off:r.end])
            rows.append((r.depth, r.field_num, wt, value, r.start, r.end))
        return rows
    finally:
        lib.pb_split_free(ctypes.byref(res))


# ============================================================================
# 公共 API
# ============================================================================

def split_fields(data, max_depth=64, engine='auto'):
    """
    解析 protobuf 字节流 (不含帧头/trpc 封装).

    engine: 'auto' (默认, C 可用用 C) / 'c' (强制, 缺库抛错) / 'python' (强制纯 Python)
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError('data must be bytes')
    if engine not in ('auto', 'c', 'python'):
        raise ValueError(f'unknown engine: {engine!r}')
    data = bytes(data)

    if engine in ('auto', 'c'):
        try:
            return _split_c(data, max_depth)
        except OSError:
            if engine == 'c':
                raise
    return _split_py(data, max_depth)




def interpret_fixed(raw):
    """
    fixed32/fixed64 原始字节的多解释 (盲解析的极限辅助).

    fixed32 → {'u32', 'i32', 'f32', 'hex'}
    fixed64 → {'u64', 'i64', 'f64', 'hex'}

    例: b'\x00\x00\x10\x3f' → {'f32': 0.5625, ...}  (stream_ratio 9:16)
    wire format 不携带类型信息, float/int 无法唯一确定 — 并列展示供人工判断.
    """
    import struct as _s
    if len(raw) == 4:
        return {'u32': int.from_bytes(raw, 'little'),
                'i32': int.from_bytes(raw, 'little', signed=True),
                'f32': _s.unpack('<f', raw)[0],
                'hex': raw.hex()}
    if len(raw) == 8:
        return {'u64': int.from_bytes(raw, 'little'),
                'i64': int.from_bytes(raw, 'little', signed=True),
                'f64': _s.unpack('<d', raw)[0],
                'hex': raw.hex()}
    return {'hex': raw.hex()}


_interpret_fixed_fn = interpret_fixed


def rows_to_dict(rows, interpret_fixed=False):
    """
    把 split_fields 的前序行拼回 message 风格的嵌套 dict.

    - 键为字符串字段号 (JSON 友好)
    - 重复字段 → list
    - '(Message)' 行 → 嵌套 dict (子行填充)
    - interpret_fixed=True: fixed32/64 字段输出多解释 dict
      {'u32','i32','f32'/'f64','hex'} 而非原始字节

    例: b'\x08\x05\x12\x02hi' → {'1': 5, '2': 'hi'}
        嵌套 f1{f1=5,f4='url'} → {'1': {'1': 5, '4': 'url'}}
    """
    root = {}
    stack = [(-1, root)]
    for depth, fn, wt, value, start, end in rows:
        if interpret_fixed and wt in ('fixed32', 'fixed64') and isinstance(value, (bytes, bytearray)):
            value = _interpret_fixed_fn(bytes(value))
        elif interpret_fixed and wt in ('fixed32', 'fixed64'):
            value = _interpret_fixed_fn(value)
        while stack and stack[-1][0] >= depth:
            stack.pop()
        parent = stack[-1][1]
        key = str(fn)
        if value == '(Message)':
            child = {}
            if key in parent:
                if isinstance(parent[key], list):
                    parent[key].append(child)
                else:
                    parent[key] = [parent[key], child]
            else:
                parent[key] = child
            stack.append((depth, child))
        else:
            if key in parent:
                if isinstance(parent[key], list):
                    parent[key].append(value)
                else:
                    parent[key] = [parent[key], value]
            else:
                parent[key] = value
    return root


def rows_to_tree(rows):
    """把前序行列表还原成嵌套结构: [{'field','type','value','start','end','children'}, ...]"""
    root = []
    stack = [(-1, root)]
    for depth, fn, wt, value, start, end in rows:
        node = {'field': fn, 'type': wt, 'value': value, 'start': start, 'end': end}
        while stack and stack[-1][0] >= depth:
            stack.pop()
        stack[-1][1].append(node)
        if value == '(Message)':
            node['children'] = []
            stack.append((depth, node['children']))
    return root


def engine_name():
    """当前 'auto' 实际使用的引擎名"""
    return 'c' if _load() is not None else 'python'


if __name__ == '__main__':
    # 自测: 文本型子消息展开 + 引擎一致性
    demo = b'\x0a\x19\x0a\x0c' + b'cid=mzc003q5' + b'\x12\x09operation'
    for eng in ('c', 'python'):
        try:
            rows = split_fields(demo, engine=eng)
        except (OSError, WireError):
            continue
        print(f"[{eng}]")
        for r in rows:
            print(' ', r)
    print('当前 auto 引擎:', engine_name())
