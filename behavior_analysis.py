#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AGT-002 判定逻辑 v0.1（behavior_analysis.py）——影子计算模式
================================================
对应设计稿：SecureScan_AGT-002_非授权交互模式设计稿_20261021.md 第二、六节

定位：
  - 读取 behavior_recorder.py 攒下的 L0 快照序列（JSONL），对每个地址的时间序列做判定计算。
  - **影子模式（默认）**：只输出计算结果，不触发任何报警。设计稿：基线积累 2-4 周、校准阈值后才启用报警。
  - 本版本是 **L0-lite 判定**：L0 快照只有余额+nonce 点值序列，没有交易对手方数据（那要 L1 历史交易），
    所以这里实现的是设计稿五维度中可在 L0 序列上计算的两个 lite 版：

    D1-lite 余额骤降（drain lite）
        相邻快照余额比 < 1% 且 nonce 增长（有交易发生）→ 9101 候选
        （完整版 D1 需"新对手方占比>80%"，L1 数据源到位后升级）

    D2-lite 睡帐激活（dormant lite）
        快照间 nonce 长期无变化（≥ dormant_days 天）后突然活跃且余额比 < 5% → 9102 候选
        （设计稿默认 >90 天；L0 影子期攒不满 90 天序列，参数可下调用于测试，上生产前恢复 90）

  - 判定全部为确定性规则，无 LLM（设计稿第五节 R8 原则：模型无关执行）。

诚实边界：
  - 快照间隔是每天 1 次（chain_scan 链路），序列本身很稀疏——lite 版误报/漏报特性未知，
    影子期（≥2 周）的目标是攒出统计特征再校准，本文件的输出当前只配做研究参考。
  - JSONL 中 balance=null（快照失败）的记录跳过参与计算，不中断。

用法：
  python behavior_analysis.py                    # 分析全部 JSONL，打印 JSON
  python behavior_analysis.py --shadow           # 同上（显式影子模式）
  python3 -c "from behavior_analysis import analyze_dir, _selftest; _selftest()"
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

# 判定参数（设计稿第六节默认值；dormant_days 在影子期可临时下调做功能验证）
THRESHOLDS = {
    "drain_ratio": 0.01,      # D1：相邻快照余额比 < 1%
    "drain_nonce_min": 1,     # D1：要求 nonce 至少增长 1（有交易）
    "dormant_ratio": 0.05,    # D2：激活后余额比 < 5%
    "dormant_days": 90,       # D2：沉睡判定天数（影子期功能验证时可临时下调）
}

DRAIN_CODE = 9101
DORMANT_CODE = 9102


def _parse_ts(ts: str) -> Optional[datetime]:
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def _load_series(jsonl_dir: Path) -> Dict[str, List[dict]]:
    """读取目录下全部 *.jsonl，按 (chain, address) 聚合为按时间排序的快照序列。"""
    series: Dict[str, List[dict]] = {}
    if not jsonl_dir.exists():
        return series
    for f in sorted(jsonl_dir.glob("*.jsonl")):
        for line in f.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            key = f"{rec.get('chain')}|{rec.get('address')}"
            series.setdefault(key, []).append(rec)
    for k in series:
        series[k].sort(key=lambda r: r.get("ts") or "")
    return series


def analyze_address(records: List[dict], thresholds: Optional[dict] = None) -> dict:
    """对单地址快照序列执行 L0-lite 判定，返回影子计算结果（无副作用）。"""
    th = {**THRESHOLDS, **(thresholds or {})}
    # 只留有效快照（余额可得）
    valid = [r for r in records
             if r.get("balance") is not None and _parse_ts(r.get("ts") or "")]
    out = {
        "snapshots_used": len(valid),
        "span_days": 0,
        "findings": [],
    }
    if len(valid) < 2:
        out["note"] = "insufficient_series"  # 序列不足，诚实标注
        return out

    span = (_parse_ts(valid[-1]["ts"]) - _parse_ts(valid[0]["ts"])).days
    out["span_days"] = span

    # ---------- D1-lite 余额骤降 ----------
    for prev, cur in zip(valid, valid[1:]):
        b0, b1 = int(prev["balance"]), int(cur["balance"])
        n0, n1 = int(prev.get("nonce") or 0), int(cur.get("nonce") or 0)
        if b0 > 0 and (b1 / b0) < th["drain_ratio"] and (n1 - n0) >= th["drain_nonce_min"]:
            out["findings"].append({
                "code": DRAIN_CODE,
                "severity": "critical",
                "description": (
                    f"余额骤降 lite：{prev['ts']} 余额 {b0} → {cur['ts']} 余额 {b1} "
                    f"(比例 {b1/b0:.4f})，nonce {n0}→{n1}。L0 依据，缺对手方维度，需 L1 复核"
                ),
                "window": [prev["ts"], cur["ts"]],
            })

    # ---------- D2-lite 睡帐激活 ----------
    for prev, cur in zip(valid, valid[1:]):
        gap_days = (_parse_ts(cur["ts"]) - _parse_ts(prev["ts"])).days
        n0, n1 = int(prev.get("nonce") or 0), int(cur.get("nonce") or 0)
        b0, b1 = int(prev["balance"]), int(cur["balance"])
        if gap_days >= th["dormant_days"] and n1 > n0 and b0 > 0 and (b1 / b0) < th["dormant_ratio"]:
            out["findings"].append({
                "code": DORMANT_CODE,
                "severity": "high",
                "description": (
                    f"睡帐激活 lite：沉睡 {gap_days} 天后活跃（nonce {n0}→{n1}），"
                    f"余额 {b0}→{b1} (比例 {b1/b0:.4f})。L0 依据，需 L1 复核"
                ),
                "window": [prev["ts"], cur["ts"]],
            })
    return out


def analyze_dir(jsonl_dir: Optional[Path] = None) -> dict:
    """影子模式全量分析。返回 {chain|address: analyze_address 结果}。"""
    d = Path(jsonl_dir) if jsonl_dir else Path(__file__).parent / "data" / "behavior_log"
    series = _load_series(d)
    result = {}
    for key, recs in sorted(series.items()):
        result[key] = analyze_address(recs)
    return result


def _selftest() -> bool:
    """三用例：正常序列 / 骤降序列 / 睡帐激活序列（合成数据）。"""
    cases = []

    # 用例1 正常：余额平稳 → 无 findings
    cases.append(("normal_clean", [
        {"ts": "2026-10-01T00:00:00Z", "chain": "bsc", "address": "0xA", "balance": "1000", "nonce": 5},
        {"ts": "2026-10-02T00:00:00Z", "chain": "bsc", "address": "0xA", "balance": "1000", "nonce": 5},
    ], []))

    # 用例2 骤降：余额 1000→5 且 nonce 增长 → 9101
    cases.append(("drain", [
        {"ts": "2026-10-01T00:00:00Z", "chain": "bsc", "address": "0xB", "balance": "1000", "nonce": 5},
        {"ts": "2026-10-02T00:00:00Z", "chain": "bsc", "address": "0xB", "balance": "5", "nonce": 6},
    ], [DRAIN_CODE]))

    # 用例3 睡帐激活：dormant_days 临时下调到 30 验证逻辑（生产恢复 90）
    th = {**THRESHOLDS, "dormant_days": 30}
    cases.append(("dormant", [
        {"ts": "2026-09-01T00:00:00Z", "chain": "tron", "address": "TRC", "balance": "100000", "nonce": 2},
        {"ts": "2026-10-05T00:00:00Z", "chain": "tron", "address": "TRC", "balance": "1000", "nonce": 3},
    ], [DORMANT_CODE]))

    ok = True
    for name, recs, expected in cases:
        th_arg = th if name == "dormant" else None
        r = analyze_address(recs, th_arg)
        got = sorted({f["code"] for f in r["findings"]})
        status = "PASS" if got == sorted(expected) else "FAIL"
        if status == "FAIL":
            ok = False
        print(f"[{status}] {name}: expect={sorted(expected)} got={got}")
    print("selftest:", "PASS" if ok else "FAIL")
    return ok


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(0 if _selftest() else 1)
    # 影子模式全量分析
    print(json.dumps(analyze_dir(), ensure_ascii=False, indent=2))
