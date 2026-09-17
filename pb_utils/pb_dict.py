#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pb_dict.py — protobuf message → dict 工具链
===========================================
与 pb_split (无 schema wire 分列) 互补的"强类型"路径:
已有编译好的 pb2 模块时, 把二进制响应里的 google.protobuf.Any(type_url)
动态解包成强类型 message, 再递归转成可 JSON 序列化的 dict.

    import pb_dict
    import my_pb2

    pb_dict.register_module(my_pb2)                    # 注册全部 message 类
    pb_dict.register_module(other_pb2)                 # 可注册多个模块

    rows = pb_dict.scan_all_anys(raw_bytes)            # 扫描二进制中的 Any
    msg   = pb_dict.unpack_any(type_url, value)        # type_url → 强类型 message
    d     = pb_dict.message_to_dict(msg)               # message → dict (JSON 可序列化)

    fields = pb_dict.parse_wire(raw_bytes)             # 通用 wire-format 扫描

兼容 protobuf >= 4 的 upb 实现:
  - FieldDescriptor 无 .label 属性 → is_repeated / is_map
  - map 字段无 presence → 不走 HasField
  - 无 presence 的 message 字段按序列化内容判断
Any 字段自动按 @type 解包 (注册表命中) 或降级为 @value (hex/utf-8).
"""

import re
import struct

try:
    from google.protobuf.descriptor import FieldDescriptor as _FD
except ImportError:   # 允许仅使用 wire 工具时无 protobuf
    _FD = None


# ============================================================================
# wire-format 基础工具
# ============================================================================

def read_varint(b, p):
    """读取 varint, 返回 (value, next_pos)"""
    r = 0
    s = 0
    while p < len(b):
        x = b[p]
        p += 1
        r |= (x & 0x7f) << s
        if not (x & 0x80):
            break
        s += 7
    return r, p


def parse_wire(b, start=0, end=None):
    """
    通用 wire-format 扫描.
    返回字段列表: [(field_num, wire_type, value, value_off, value_len)]
    wire_type: 0=varint, 1=i64, 2=len-delimited, 5=i32
    """
    if end is None:
        end = len(b)
    out = []
    p = start
    while p < end:
        tag_pos = p
        tag = b[p]
        p += 1
        fn = tag >> 3
        wt = tag & 7
        if fn == 0:
            break
        if wt == 0:
            v, p = read_varint(b, p)
            out.append((fn, 0, v, tag_pos, p - tag_pos))
        elif wt == 2:
            ln, p = read_varint(b, p)
            out.append((fn, 2, None, p, ln))
            p += ln
        elif wt == 5:
            out.append((fn, 5, struct.unpack('<I', b[p:p + 4])[0], tag_pos, 4))
            p += 4
        elif wt == 1:
            out.append((fn, 1, struct.unpack('<Q', b[p:p + 8])[0], tag_pos, 8))
            p += 8
        else:
            break
    return out


def try_utf8(bs):
    """尝试把 bytes 解码为可读 UTF-8 字符串, 失败返回 None"""
    try:
        s = bs.decode('utf-8')
        for ch in s:
            o = ord(ch)
            if o < 32 and ch not in '\t\n\r':
                return None
        return s
    except (UnicodeDecodeError, ValueError):
        return None


# ============================================================================
# Any 动态分发注册表
# ============================================================================

_ANY_URL_RE = re.compile(rb'type\.googleapis\.com/[A-Za-z0-9._/]+')

_TYPE_REGISTRY = {}   # type_url 短名 -> message 类


def register_module(mod):
    """
    注册一个编译好的 pb2 模块中的全部 message 类 (按类短名索引).
    模块名可能带 proto. 前缀 (protoc --python_out 的包路径), 用 basename 匹配.
    同名类先注册者优先, 返回本次注册数量.
    """
    mod_base = mod.__name__.split('.')[-1]
    count = 0
    for name in dir(mod):
        obj = getattr(mod, name, None)
        if (isinstance(obj, type) and hasattr(obj, 'DESCRIPTOR')
                and hasattr(obj, 'ParseFromString')
                and obj.__module__.split('.')[-1] == mod_base):
            if name not in _TYPE_REGISTRY:
                _TYPE_REGISTRY[name] = obj
                count += 1
    return count


def clear_registry():
    _TYPE_REGISTRY.clear()


def registered_types():
    return dict(_TYPE_REGISTRY)


def unpack_any(type_url, value_bytes):
    """
    根据 type_url 把 Any.value 解包成强类型 message.
    未注册类型或解析失败返回 None.
    """
    short = type_url.rsplit('.', 1)[-1] if type_url else ''
    cls = _TYPE_REGISTRY.get(short)
    if cls is None:
        return None
    try:
        m = cls()
        m.ParseFromString(value_bytes)
        return m
    except Exception:
        return None


def scan_all_anys(data):
    """
    在二进制数据中扫描所有 google.protobuf Any 编码
    (0a <len> type_url  12 <len> value).
    返回 [(type_url, value_bytes, value_offset), ...]
    """
    results = []
    for m in _ANY_URL_RE.finditer(data):
        p = m.end()
        if p >= len(data) or data[p] != 0x12:
            continue
        p += 1
        vlen, p = read_varint(data, p)
        if p + vlen > len(data):
            continue
        results.append((m.group().decode('ascii'), data[p:p + vlen], p))
    return results


# ============================================================================
# message -> dict (递归, Any 自动解包)
# ============================================================================

_MAX_DEPTH = 8

# google.protobuf 包装类型的 value 字段名
_WKT_WRAPPERS = {
    'google.protobuf.BoolValue': 'value',
    'google.protobuf.BytesValue': 'value',
    'google.protobuf.DoubleValue': 'value',
    'google.protobuf.FloatValue': 'value',
    'google.protobuf.Int32Value': 'value',
    'google.protobuf.Int64Value': 'value',
    'google.protobuf.UInt32Value': 'value',
    'google.protobuf.UInt64Value': 'value',
    'google.protobuf.StringValue': 'value',
}


def _unwrap_wkt(msg):
    """
    Well-Known Types 的友好输出; 非 WKT 返回 None (哨兵).
      Value      → 解包 oneof (None/数值/字符串/布尔/嵌套)
      ListValue  → list
      Struct     → {k: 展开}
      Timestamp  → ISO 8601 字符串
      Duration   → 秒 (float)
      XxxValue   → 标量 value
    """
    full = msg.DESCRIPTOR.full_name
    if full == 'google.protobuf.Value':
        kind = msg.WhichOneof('kind')
        if kind is None:
            return None
        v = getattr(msg, kind)
        if kind == 'null_value':
            return None
        if kind in ('struct_value', 'list_value'):
            return message_to_dict(v)
        return v
    if full == 'google.protobuf.ListValue':
        return [message_to_dict(v) for v in msg.values]
    if full == 'google.protobuf.Struct':
        return {k: message_to_dict(v) for k, v in msg.fields.items()}
    if full == 'google.protobuf.Timestamp':
        return msg.ToJsonString()
    if full == 'google.protobuf.Duration':
        return msg.ToTimedelta().total_seconds()
    if full in _WKT_WRAPPERS:
        return getattr(msg, _WKT_WRAPPERS[full])
    return None


def _is_repeated(fd):
    """repeated 判定 (兼容 upb: 无 .label 属性, 用 is_repeated)"""
    if hasattr(fd, 'is_repeated'):
        return fd.is_repeated
    try:
        return fd.label == 3  # LABEL_REPEATED
    except AttributeError:
        return False


def _is_map(fd):
    """map 判定"""
    return getattr(fd, 'is_map', False) or (
        fd.message_type is not None and fd.message_type.has_options
        and fd.message_type.GetOptions().map_entry
    )


def _has_field(msg, fd):
    """字段存在性判定 (proto3: map/repeated 按非空, message 按 presence)"""
    if _is_map(fd) or _is_repeated(fd):
        return len(getattr(msg, fd.name)) > 0
    if fd.cpp_type == fd.CPPTYPE_MESSAGE:
        try:
            return msg.HasField(fd.name)
        except ValueError:
            # 无 presence 的 message 字段, 按序列化内容判断
            return getattr(msg, fd.name).SerializePartialToString() != b''
    return bool(getattr(msg, fd.name))


def _scalar_to_json(v, fd):
    if isinstance(v, bytes):
        s = try_utf8(v)
        return s if s is not None else v.hex()
    if fd is not None and fd.cpp_type in (fd.CPPTYPE_FLOAT, fd.CPPTYPE_DOUBLE):
        return float(v)
    if fd is not None and fd.cpp_type == fd.CPPTYPE_ENUM:
        return int(v)
    return v


def message_to_dict(msg, depth=0):
    """
    protobuf message → 可 JSON 序列化的 dict.
    - 嵌套 message 递归 (max depth 8, 防循环引用)
    - google.protobuf.Any 字段按注册表解包, 带 @type 标记
    - bytes 字段 UTF-8 优先, 失败输出 hex
    - 空值字段 (默认值) 不输出
    """
    if depth > _MAX_DEPTH:
        return '<max depth>'
    # Well-Known Types 友好输出
    w = _unwrap_wkt(msg)
    if w is not None or msg.DESCRIPTOR.full_name == 'google.protobuf.Value':
        return w
    out = {}
    for fd in msg.DESCRIPTOR.fields:
        name = fd.name
        if _is_map(fd):
            raw = getattr(msg, name)
            if len(raw) == 0:
                continue
            vfd = fd.message_type.fields_by_name['value']
            out[name] = {str(k): _value_to_json(raw[k], vfd, depth) for k in raw}
            continue
        if _is_repeated(fd):
            raw = getattr(msg, name)
            if len(raw) == 0:
                continue
            if fd.message_type is None:
                out[name] = [_scalar_to_json(x, fd) for x in raw]
            else:
                out[name] = [message_to_dict(item, depth) for item in raw]
            continue
        if fd.message_type is None:
            if _has_field(msg, fd):
                out[name] = _scalar_to_json(getattr(msg, name), fd)
        else:
            if not _has_field(msg, fd):
                continue
            sub = getattr(msg, name)
            if fd.message_type.full_name == 'google.protobuf.Any':
                out[name] = any_to_dict(sub, depth)
            else:
                out[name] = message_to_dict(sub, depth)
    return out


def _value_to_json(v, vfd, depth):
    """map 的 value 列转换"""
    if vfd.message_type is None:
        return _scalar_to_json(v, vfd)
    if vfd.message_type.full_name == 'google.protobuf.Any':
        return any_to_dict(v, depth)
    return message_to_dict(v, depth)


def any_to_dict(any_msg, depth=0):
    """
    google.protobuf.Any → dict.
    注册表命中: {'@type': 短名, '@unpacked': message_dict}
    未命中:     {'@type': 短名, '@value': utf-8 或 hex}
    """
    type_url = any_msg.type_url
    short = type_url.rsplit('.', 1)[-1] if type_url else ''
    value = any_msg.value
    out = {'@type': short}
    if depth > _MAX_DEPTH:
        out['@value_hex'] = value.hex()
        return out
    m = unpack_any(type_url, value)
    if m is not None:
        out['@unpacked'] = message_to_dict(m, depth + 1)
    else:
        s = try_utf8(value)
        out['@value'] = s if s is not None else value.hex()
    return out


# 向后兼容别名
_any_to_dict = any_to_dict
