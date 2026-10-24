#!/usr/bin/env python3
"""
每日扫描执行器 - 2026-06-24
扫描BSC和TRON代币，对比baseline，决定是否发日报
"""
import json
import time
import sys
import os
import subprocess
from datetime import datetime

SCANNER_DIR = "/app/data/所有对话/主对话/contract_scanner"
sys.path.insert(0, SCANNER_DIR)

# === 1. 准备地址列表 ===
# BSC: 用 addresses_bsc.txt
# TRON: addresses_tron.txt 是空的，用 baseline 的9个（保持一致性）

def load_addresses_bsc():
    addrs = []
    with open(f"{SCANNER_DIR}/addresses_bsc.txt") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "|" in line:
                addrs.append(line.split("|")[0].strip())
            else:
                addrs.append(line)
    return addrs

def load_addresses_tron():
    # baseline里有9个，用baseline的保持一致
    with open(f"{SCANNER_DIR}/baseline_20260624.json") as f:
        baseline = json.load(f)
    return list(baseline["tron_fingerprint"].keys())

# === 2. 扫描（用v5.0） ===
def run_scan(addresses, chain):
    from scanner_v50 import scan_batch
    print(f"  开始扫描{chain.upper()} {len(addresses)}个代币...")
    start = time.time()
    result = scan_batch(addresses, chain=chain)
    elapsed = time.time() - start
    print(f"  扫描完成，耗时{elapsed:.1f}s")
    return result

# === 3. 生成fingerprint ===
def make_fingerprint(scan_data, chain):
    fp = {}
    results = scan_data.get("results", {})
    for addr, data in results.items():
        if not isinstance(data, dict) or "error" in data:
            fp[addr] = {"error": data.get("error", "unknown") if isinstance(data, dict) else "unknown"}
            continue
        contract = data.get("contract", {})
        risks = data.get("risks", [])
        fp[addr] = {
            "symbol": contract.get("symbol", ""),
            "risk_level": data.get("risk_level", "unknown"),
            "risk_score": data.get("risk_score", 0),
            "risk_codes": sorted([r.get("code", 0) for r in risks]),
        }
    return fp

# === 4. 对比baseline ===
def compare(baseline_fp, today_fp, chain):
    """返回变化列表"""
    changes = []
    new_tokens = []
    removed_tokens = []
    level_changed = []  # 风险等级变化
    score_changed_significantly = []  # 风险分大幅变化
    new_honeypot = []  # 新蜜罐
    resolved_honeypot = []  # 风险解除

    base_addrs = set(baseline_fp.keys())
    today_addrs = set(today_fp.keys())

    # 新增代币
    for addr in today_addrs - base_addrs:
        new_tokens.append((addr, today_fp[addr]))
    # 移除代币
    for addr in base_addrs - today_addrs:
        removed_tokens.append((addr, baseline_fp[addr]))

    # 共同代币的对比
    for addr in base_addrs & today_addrs:
        b = baseline_fp[addr]
        t = today_fp[addr]
        if b.get("error") or t.get("error"):
            continue

        # 等级变化
        if b.get("risk_level") != t.get("risk_level"):
            level_changed.append((addr, b, t))

        # 风险分变化超过10分
        b_score = b.get("risk_score", 0)
        t_score = t.get("risk_score", 0)
        if abs(t_score - b_score) >= 10:
            score_changed_significantly.append((addr, b_score, t_score))

        # 新蜜罐
        # 通过 risk_codes 是否新增 critical 蜜罐代码（4007=蜜罐疑似）
        b_codes = set(b.get("risk_codes", []))
        t_codes = set(t.get("risk_codes", []))
        new_codes = t_codes - b_codes
        # 蜜罐/严重风险代码
        critical_new = [c for c in new_codes if c in [4007, 4009, 4010, 5007, 5006]]  # HONEYPOT_SUSPECTED/BLACKLIST_DETECTED/WHITELIST_ONLY/FREEZE/MINTABLE_OWNER
        if critical_new:
            new_honeypot.append((addr, b, t, critical_new))

    return {
        "new_tokens": new_tokens,
        "removed_tokens": removed_tokens,
        "level_changed": level_changed,
        "score_changed": score_changed_significantly,
        "new_honeypot": new_honeypot,
    }

# === 5. 生成简明日报markdown ===
def build_daily_md(chain, today_fp, changes, scan_data):
    results = scan_data.get("results", {})
    total = len(results)

    # 统计
    risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "safe": 0, "unknown": 0}
    for addr, fp in today_fp.items():
        if "error" in fp:
            risk_counts["unknown"] += 1
            continue
        level = fp.get("risk_level", "unknown")
        risk_counts[level] = risk_counts.get(level, 0) + 1

    chain_name = "BSC (币安智能链)" if chain == "bsc" else "TRON (波场)"

    md = f"""🛡️ {chain_name} 代币安全扫描日报 · {datetime.now().strftime('%Y-%m-%d')}

📊 本期概览
━━━━━━━━━━━━━━━
扫描代币: {total} 个

🔴 严重: {risk_counts['critical']}
🟠 高危: {risk_counts['high']}
🟡 中等: {risk_counts['medium']}
🔵 低风险: {risk_counts['low']}
🟢 安全: {risk_counts['safe']}
⚪ 异常/失败: {risk_counts['unknown']}
"""

    # 变化部分（重点）
    if changes["new_honeypot"]:
        md += "\n🍯 蜜罐/严重风险预警\n━━━━━━━━━━━━━━━\n"
        for addr, b, t, codes in changes["new_honeypot"]:
            md += f"- ⚠️ **{t.get('symbol','?')}** `{addr[:8]}...{addr[-6:]}` 风险分 {b.get('risk_score',0)}→{t.get('risk_score',0)} 新增风险码 {codes}\n"

    if changes["level_changed"]:
        md += "\n⚠️ 风险等级变化\n━━━━━━━━━━━━━━━\n"
        for addr, b, t in changes["level_changed"]:
            md += f"- **{t.get('symbol','?')}** `{addr[:8]}...{addr[-6:]}` {b.get('risk_level','').upper()}({b.get('risk_score',0)}) → {t.get('risk_level','').upper()}({t.get('risk_score',0)})\n"

    if changes["score_changed"]:
        md += "\n📈 风险分大幅波动（±10分）\n━━━━━━━━━━━━━━━\n"
        for addr, b_score, t_score in changes["score_changed"]:
            sym = today_fp.get(addr, baseline_fp_global.get(addr, {})).get("symbol", "?") if 'baseline_fp_global' in dir() else "?"
            md += f"- **{today_fp.get(addr,{}).get('symbol','?')}** `{addr[:8]}...{addr[-6:]}` {b_score}→{t_score}\n"

    if changes["new_tokens"]:
        md += "\n🆕 新增代币\n━━━━━━━━━━━━━━━\n"
        for addr, fp in changes["new_tokens"]:
            md += f"- **{fp.get('symbol','?')}** `{addr[:8]}...{addr[-6:]}` {fp.get('risk_level','').upper()}({fp.get('risk_score',0)})\n"

    if changes["removed_tokens"]:
        md += "\n🗑️ 移除代币\n━━━━━━━━━━━━━━━\n"
        for addr, fp in changes["removed_tokens"]:
            md += f"- **{fp.get('symbol','?')}** `{addr[:8]}...{addr[-6:]}`\n"

    # 全量排名（按风险分）
    md += "\n📋 全量代币风险一览\n━━━━━━━━━━━━━━━\n"
    sorted_tokens = sorted(
        [(a, f) for a, f in today_fp.items() if "error" not in f],
        key=lambda x: x[1].get("risk_score", 0),
        reverse=True
    )
    for i, (addr, fp) in enumerate(sorted_tokens, 1):
        emoji = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🔵","safe":"🟢"}.get(fp.get("risk_level",""), "⚪")
        md += f" {i:2d}. {emoji} {fp.get('symbol','?'):8s} - {fp.get('risk_score',0):3d}分 - {fp.get('risk_level','')}\n"

    md += f"""
🔖 说明
━━━━━━━━━━━━━━━
• 本报告由 SecureScan v5.0 自动生成
• 风险等级仅供参考，不构成投资建议
• 蜜罐检测基于字节码特征分析，可能存在误判
• 如需详细报告或API接入，请私信联系

#SecureScan #{chain.upper()} #链上安全 #智能合约安全 #蜜罐检测 #投资理财
"""
    return md

# === 主流程 ===
if __name__ == "__main__":
    today = datetime.now().strftime("%Y%m%d")
    print(f"=== 每日扫描 {today} ===\n")

    # 加载baseline
    with open(f"{SCANNER_DIR}/baseline_20260624.json") as f:
        baseline = json.load(f)
    baseline_fp_global = baseline  # 给build_daily_md用

    summary = {"date": today, "scans": {}}

    for chain in ["bsc", "tron"]:
        print(f"\n--- {chain.upper()} ---")
        if chain == "bsc":
            addresses = load_addresses_bsc()
        else:
            addresses = load_addresses_tron()

        print(f"地址数: {len(addresses)}")

        # 扫描
        scan_data = run_scan(addresses, chain)

        # 保存raw
        raw_path = f"{SCANNER_DIR}/daily_scan_{chain}_{today}.json"
        with open(raw_path, "w", encoding="utf-8") as f:
            json.dump(scan_data, f, ensure_ascii=False, indent=2)
        print(f"  原始结果: {raw_path}")

        # 生成fingerprint
        fp = make_fingerprint(scan_data, chain)
        baseline_fp = baseline[f"{chain}_fingerprint"]
        changes = compare(baseline_fp, fp, chain)

        # 生成报告
        md = build_daily_md(chain, fp, changes, scan_data)
        md_path = f"{SCANNER_DIR}/daily_scan_{chain}_{today}.md"
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md)
        print(f"  报告: {md_path}")

        # 汇总
        summary["scans"][chain] = {
            "total": len(addresses),
            "fp": fp,
            "changes": {k: len(v) for k, v in changes.items()},
        }
        print(f"  变化: 新增{len(changes['new_tokens'])} 等级变化{len(changes['level_changed'])} 分变化{len(changes['score_changed'])} 蜜罐{len(changes['new_honeypot'])}")

    # 写summary
    sum_path = f"{SCANNER_DIR}/daily_scan_summary_{today}.json"
    with open(sum_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    print(f"\n=== 汇总: {sum_path} ===")
