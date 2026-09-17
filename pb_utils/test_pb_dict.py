#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_pb_dict.py — pb_dict 工具链测试 (自包含, 仅依赖 google.protobuf 自带类型)
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

from google.protobuf import struct_pb2, wrappers_pb2, any_pb2
import pb_dict

PASS = 0
FAIL = 0


def check(name, cond, detail=''):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ✓ {name}")
    else:
        FAIL += 1
        print(f"  ✗ {name}  {detail}")


# 注册 struct/wrappers 模块 (模拟 pb2 模块注册)
n = pb_dict.register_module(struct_pb2) + pb_dict.register_module(wrappers_pb2)
check("register_module", n > 0, f"registered={n}")
check("注册表含 Struct", 'Struct' in pb_dict.registered_types())

# --- unpack_any ---
st = struct_pb2.Struct()
st.update({'cid': 'mzc003', 'count': 5, 'tags': ['修真', '逆袭'], 'nested': {'a': 1}})
any_msg = any_pb2.Any()
any_msg.Pack(st)

m = pb_dict.unpack_any(any_msg.type_url, any_msg.value)
check("unpack_any 解包成功", m is not None and m['cid'] == 'mzc003')

# 未注册类型
m2 = pb_dict.unpack_any('type.googleapis.com/com.unknown.Thing', b'\x08\x01')
check("未注册类型返回 None", m2 is None)

# --- scan_all_anys ---
raw = b'\x08\x01' + any_msg.SerializeToString() + b'\x12\x02ok'
anys = pb_dict.scan_all_anys(raw)
check("scan_all_anys 定位 Any", len(anys) == 1 and anys[0][0].endswith('.Struct'))
check("scan_all_anys 值可解包", pb_dict.unpack_any(anys[0][0], anys[0][1]) is not None)

# --- message_to_dict: map / repeated / 嵌套 / 标量 (Struct 经 WKT 解包为扁平 dict) ---
d = pb_dict.message_to_dict(st)
check("map 字段 → dict", d.get('cid') == 'mzc003' and d.get('count') == 5)
check("repeated → list", d.get('tags') == ['修真', '逆袭'])
check("嵌套 message 递归", d.get('nested', {}).get('a') == 1)

# --- Any 字段自动解包 (@type/@unpacked) ---
holder = struct_pb2.Struct()
holder['inner'] = 1
holder2 = struct_pb2.Struct()
holder2.update({})
# 用 Value 包装 Any 场景: 直接测 any_to_dict
ad = pb_dict.any_to_dict(any_msg)
check("any_to_dict 带 @type", ad.get('@type') == 'Struct')
check("any_to_dict 带 @unpacked",
      ad.get('@unpacked', {}).get('cid') == 'mzc003')

# 未注册 Any → @value 降级
unknown = any_pb2.Any(type_url='type.googleapis.com/com.x.Thing', value=b'\x08\x01')
ad2 = pb_dict.any_to_dict(unknown)
check("未注册 Any 降级 @value", '@value' in ad2 or '@value_hex' in ad2)

# --- bool/bytes 标量 ---
bv = wrappers_pb2.BoolValue(value=True)
check("BoolValue 解包", pb_dict.unpack_any(bv.type_url if hasattr(bv, 'type_url') else
                                            'type.googleapis.com/google.protobuf.BoolValue',
                                            bv.SerializeToString()).value is True)

# --- wire 工具 ---
v, p = pb_dict.read_varint(varint := b'\xac\x02', 0)   # 300
check("read_varint", v == 300 and p == 2)
fields = pb_dict.parse_wire(b'\x08\x05\x12\x03abc')
check("parse_wire", fields[0][:3] == (1, 0, 5) and fields[1][0] == 2 and fields[1][3] == 4)
check("try_utf8 失败返回 None", pb_dict.try_utf8(b'\xff\xfe\x01') is None)
check("try_utf8 成功", pb_dict.try_utf8('修真'.encode()) == '修真')

# --- upb 兼容: descriptor 无 .label ---
s_fd = struct_pb2.Struct.DESCRIPTOR.fields_by_name['fields']
check("_is_map/_is_repeated 兼容", pb_dict._is_map(s_fd) and pb_dict._is_repeated(s_fd))

print(f"\n{'=' * 50}\n通过 {PASS} / 失败 {FAIL}")
sys.exit(1 if FAIL else 0)
