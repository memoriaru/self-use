# pb_utils — 无 schema protobuf 批量分列工具

对未知 protobuf 字节流（抓包还原、协议逆向）做 wire-format 级分列，不需要 .proto 文件。
纯 Python 实现，可选 C 扩展加速；C 库缺失时自动降级，两引擎输出逐行一致。

## 特性

- **批量解析**：每次调用解析整条消息，返回前序字段行（比逐 varint 的 ctypes 调用快数倍）
- **双引擎自动切换**：`libpb_split` 存在走 C，缺失自动降级纯 Python，行为完全一致
- **文本型子消息展开**：含控制字节的 length-delim 值严格按子消息解析（字符串优先的
  传统启发式会把 `f1{"cid=..."}` 这类子消息吞成叶子）
- **uint64 varint**：毫秒时间戳 / 大 ID 不溢出
- **每行带 depth 与字节偏移**：分列展示可表达层级，可直接回定位原始字节
- **坏数据可控报错**：截断 / 非法 wire type / varint 超长均抛带偏移的 `WireError`，
  深度上限 64 层，不会越界读或无限递归

## 行格式

```python
from pb_split import split_fields, rows_to_tree

rows = split_fields(data)
# [(depth, field_num, wire_type, value, start, end), ...]
# value: varint → int; string → str; message → '(Message)'; bytes/fixed → bytes

tree = rows_to_tree(rows)   # 嵌套 dict 树
```

引擎选择：

```python
split_fields(data)                    # auto: 有 C 库用 C，否则纯 Python
split_fields(data, engine='python')   # 强制纯 Python
split_fields(data, engine='c')        # 强制 C（缺库抛 OSError）
```

## 构建 C 引擎（可选）

```bash
make          # macOS / Linux
cmake -S . -B build && cmake --build build   # 三端（含 Windows/MSVC）
```

产物 `libpb_split.{dylib,so,dll}` 放在 `pb_split.py` 同目录即可被自动加载；
不构建则纯 Python 模式，行为一致、速度约为 C 的 1/1.5~1/2.5。

## 分类规则（length_delimited value）

| 条件 | 判定 |
|------|------|
| 含控制字节（0x00-0x08, 0x0B, 0x0C, 0x0E-0x1F, 0x7F）且严格解析恰好消费完 | Message（递归展开） |
| 含控制字节但解析失败；或无控制字节且 UTF-8 合法、可读率 ≥ 0.68 | String |
| 其余 | Bytes |

纯文本（如 `"hello world"`、`"abcdefgh"`）即使碰巧能被 wire 解析器走完也会被判为
字符串——文本守卫（可读率 + 控制字节）用于阻止误拆。

## 测试

```bash
python test_pb_split.py    # 双引擎单元 / 引擎一致性对拍 / 降级 / 3MB 基准
```

## 基准参考

3MB 真实抓包数据（13 万字段行）：C 引擎 ~0.8-1.2 s，纯 Python ~1.0-1.5 s。
作为对照，blackboxprotobuf 在同数据上慢约 3 倍且对病态嵌套有卡死风险。

## 已知取舍

- 空字段（`1a 00`）判为 Bytes 而非空 Message（信息等价）
- 全可打印字节构成的真消息（无任何控制字节，极罕见）会按字符串展示
- packed repeated 不做二次解释（可作为后续增强）
