#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_pb_split.py — pb_split 双引擎测试
======================================
[1] 单元测试 (C / Python 两引擎分别跑, 结果必须一致)
[2] 引擎一致性对拍 (同一数据两引擎逐行 diff, 必须零差异)
[3] 降级测试 (强制纯 Python / 缺库场景)
[4] 3MB 基准
"""
import os
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

import pb_split
from pb_split import split_fields, rows_to_tree, WireError

PASS = 0
FAIL = 0
ENGINES = []


def check(name, cond, detail=''):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ✓ {name}")
    else:
        FAIL += 1
        print(f"  ✗ {name}  {detail}")


def varint(v):
    out = b''
    while v > 0x7f:
        out += bytes([(v & 0x7f) | 0x80])
        v >>= 7
    return out + bytes([v])


# 探测可用引擎
try:
    split_fields(b'\x08\x01', engine='c')
    ENGINES = ['c', 'python']
except (OSError, WireError):
    ENGINES = ['python']
print(f"可用引擎: {ENGINES}\n")


# ============================================================
# [1] 单元测试 (双引擎)
# ============================================================
print("[1] 单元测试 (双引擎)")

def unit_cases():
    """(名称, 输入, 期望行[不含start/end])"""
    ts = 1785836381000
    return [
        ("毫秒时间戳 uint64",
         b'\x08' + varint(ts),
         [(0, 1, 'varint', ts)]),
        ("文本型子消息展开",
         b'\x0a' + bytes([len(b'\x0a\x0ccid=mzc003q5\x12\x09operation')])
         + b'\x0a\x0ccid=mzc003q5\x12\x09operation',
         [(0, 1, 'length_delimited', '(Message)'),
          (1, 1, 'length_delimited', 'cid=mzc003q5'),
          (1, 2, 'length_delimited', 'operation')]),
        ("纯文本判 string",
         b'\x0a\x0bhello world',
         [(0, 1, 'length_delimited', 'hello world')]),
        ("全字母不误判 Message",
         b'\x0a\x08abcdefgh',
         [(0, 1, 'length_delimited', 'abcdefgh')]),
        ("空值判 bytes",
         b'\x1a\x00',
         [(0, 3, 'length_delimited', b'')]),
        ("CJK 字符串",
         b'\x0a\x0c' + '修真小说'.encode(),
         [(0, 1, 'length_delimited', '修真小说')]),
        ("fixed32/64 原始字节",
         b'\x0d\x01\x02\x03\x04\x09\x01\x02\x03\x04\x05\x06\x07\x08',
         [(0, 1, 'fixed32', b'\x01\x02\x03\x04'),
          (0, 1, 'fixed64', b'\x01\x02\x03\x04\x05\x06\x07\x08')]),
        ("三层嵌套 depth",
         b'\x0a\x04\x12\x02\x08\x05',
         [(0, 1, 'length_delimited', '(Message)'),
          (1, 2, 'length_delimited', '(Message)'),
          (2, 1, 'varint', 5)]),
        ("Poster 型 (f1{标题}+f4{url}, 全可打印)",
         b'\x62\x0c' + b'\x0a\x04name\x22\x04http',
         [(0, 12, 'length_delimited', '(Message)'),
          (1, 1, 'length_delimited', 'name'),
          (1, 4, 'length_delimited', 'http')]),
    ]


for eng in ENGINES:
    print(f"  --- engine={eng} ---")
    for name, data, expect in unit_cases():
        try:
            rows = split_fields(data, engine=eng)
            got = [(r[0], r[1], r[2], r[3]) for r in rows]
            check(f"{name}", got == expect, f"got={got}")
        except Exception as e:
            check(f"{name}", False, f"{type(e).__name__}: {e}")

# 异常类单测 (不区分引擎, 语义相同)
print("  --- 异常与边界 ---")
for eng in ENGINES:
    try:
        split_fields(b'\x0a\xff\xff\xff', engine=eng)
        check(f"[{eng}] 畸形数据抛 WireError", False)
    except WireError as e:
        check(f"[{eng}] 畸形数据抛 WireError (offset={e.offset})",
              isinstance(e.offset, int) and e.offset >= 0, str(e))
    except Exception as e:
        check(f"[{eng}] 畸形数据抛 WireError", False, f"{type(e).__name__}: {e}")

# 深嵌套
deep = b'\x08\x05'
for _ in range(300):
    deep = b'\x7a' + bytes([len(deep)]) + deep if len(deep) < 128 else deep
for eng in ENGINES:
    try:
        rows = split_fields(deep, engine=eng)
        check(f"[{eng}] 300 层深嵌套不崩 (深度截断)", True)
    except RecursionError:
        check(f"[{eng}] 300 层深嵌套不崩", False, "RecursionError")

check("空输入", all(split_fields(b'', engine=e) == [] for e in ENGINES))

# 树重建
rows = split_fields(b'\x0a\x04\x12\x02\x08\x05', engine=ENGINES[0])
tree = rows_to_tree(rows)
check("树重建正确", tree[0]['children'][0]['children'][0]['value'] == 5)

# rows_to_dict
rd = pb_split.rows_to_dict(split_fields(b'\x08\x05\x12\x02hi\x62\x0c\x0a\x04name\x22\x04http', engine=ENGINES[0]))
check("rows_to_dict 嵌套", rd == {'1': 5, '2': 'hi', '12': {'1': 'name', '4': 'http'}}, f"{rd}")
rd2 = pb_split.rows_to_dict(split_fields(b'\x08\x01\x08\x02', engine=ENGINES[0]))
check("rows_to_dict 重复字段 → list", rd2 == {'1': [1, 2]}, f"{rd2}")
rd3 = pb_split.rows_to_dict(split_fields(b'\x62\x0c' + b'\x0a\x04name\x22\x04http', engine=ENGINES[0]))
check("rows_to_dict Poster 型", rd3 == {'12': {'1': 'name', '4': 'http'}}, f"{rd3}")


# ============================================================
# [2] 引擎一致性对拍
# ============================================================
print("\n[2] 引擎一致性对拍 (C vs Python 逐行 diff)")

if len(ENGINES) < 2:
    print("  (仅一个引擎可用, 跳过)")
else:
    parity_cases = []
    # 边界向量
    for name, data, _ in unit_cases():
        parity_cases.append((name, data))
    parity_cases += [
        ("负数 varint (-1, 10字节补码)", b'\x08' + varint((1 << 64) - 1)),
        ("大 packed-like 二进制", b'\x12\x08' + bytes(range(8))),
        ("超长字符串字段", b'\x0a\x40' + b'x' * 64),
    ]
    # 真实抓包
    for tag in ['detail_immersive_shenyi_resp.bin', 'hlmj_rank_resp.bin',
                'hlmj_sec_detail_immersive.bin', 'hlmj_detail_immersive.bin']:
        p = os.path.join(_HERE, '..', 'tencent_kairos', 'bin', tag)
        if not os.path.exists(p):
            p = os.path.join(_HERE, '..', 'tencent_kairos', 'bin', 'har', tag)
        if os.path.exists(p):
            with open(p, 'rb') as f:
                raw = f.read()
            pos = raw.find(b'\x0a\x06normal')
            if pos >= 0:
                parity_cases.append((tag, raw[pos:]))

    all_match = True
    for name, data in parity_cases:
        rc = split_fields(data, engine='c')
        rp = split_fields(data, engine='python')
        if rc == rp:
            check(f"{name}: {len(rc)} 行一致", True)
        else:
            all_match = False
            diffs = [(a, b) for a, b in zip(rc, rp) if a != b][:2]
            extra = abs(len(rc) - len(rp))
            check(f"{name}: 行数 {len(rc)} vs {len(rp)}", False,
                  f"首处差异 {diffs} (尾部多余 {extra})")
    check("引擎一致性总检", all_match)


# ============================================================
# [3] 降级测试
# ============================================================
print("\n[3] 降级测试")

# 强制纯 Python 不依赖 C 库
rows = split_fields(b'\x08\x01', engine='python')
check("engine='python' 可独立工作", rows[0][3] == 1)

# auto 引擎与显式指定一致
auto = split_fields(b'\x0a\x04\x12\x02\x08\x05')
check("auto 与显式引擎一致",
      auto == split_fields(b'\x0a\x04\x12\x02\x08\x05', engine=pb_split.engine_name()))

# 缺库降级模拟: 清掉已加载的库句柄并标记失败, auto 应回退纯 Python
saved_lib, saved_failed = pb_split._LIB, pb_split._LIB_FAILED
try:
    pb_split._LIB = None
    pb_split._LIB_FAILED = True
    rows = split_fields(b'\x0a\x04\x12\x02\x08\x05')   # auto → 应降级
    check("模拟缺库 auto 降级纯 Python", rows[0][3] == '(Message)')
    try:
        split_fields(b'\x08\x01', engine='c')
        check("模拟缺库 engine='c' 抛 OSError", False)
    except OSError:
        check("模拟缺库 engine='c' 抛 OSError", True)
finally:
    pb_split._LIB = saved_lib
    pb_split._LIB_FAILED = saved_failed

# engine 参数校验
try:
    split_fields(b'\x08\x01', engine='bad')
    check("非法 engine 抛 ValueError", False)
except ValueError:
    check("非法 engine 抛 ValueError", True)
try:
    split_fields('not bytes')
    check("非 bytes 输入抛 TypeError", False)
except TypeError:
    check("非 bytes 输入抛 TypeError", True)


# ============================================================
# [4] 3MB 基准
# ============================================================
print("\n[4] 3MB 基准")

with open(os.path.join(_HERE, '..', 'tencent_kairos', 'bin', 'har',
                       'detail_immersive_shenyi_resp.bin'), 'rb') as f:
    raw = f.read()
pos = raw.find(b'\x0a\x06normal')
unit = raw[pos:]
big = unit * 39
size_mb = len(big) / 1024 / 1024
print(f"  数据量: {size_mb:.2f} MB")

results = {}
for eng in ENGINES:
    t0 = time.perf_counter()
    rows = split_fields(big, engine=eng)
    dt = time.perf_counter() - t0
    results[eng] = dt
    print(f"  [{eng:<6}] {dt*1000:8.1f} ms  ({size_mb/dt:5.1f} MB/s)  rows={len(rows)}")

if len(results) == 2:
    ratio = results['python'] / results['c']
    print(f"  加速比: {ratio:.1f}x")


print(f"\n{'=' * 50}\n通过 {PASS} / 失败 {FAIL}")
sys.exit(1 if FAIL else 0)
