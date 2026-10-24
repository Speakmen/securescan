#!/usr/bin/env python3
"""
每日链上扫描执行器 v4 - 20260710
使用 scanner_v50.py 保持与baseline一致
"""
import json, time, sys, os, requests
from datetime import datetime

SCANNER_DIR = "/app/data/所有对话/主对话/contract_scanner"
sys.path.insert(0, SCANNER_DIR)
today = datetime.now().strftime("%Y%m%d")
today_dt = datetime.now()

# baseline 日期（昨天）
YESTERDAY = "20260709"

# === 1. 加载地址 ===
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
    with open(f"{SCANNER_DIR}/daily_scan_summary_{YESTERDAY}.json") as f:
        yesterday = json.load(f)
    return list(yesterday["scans"]["tron"]["fp"].keys())

# === 2. 扫描（v5.0） ===
def run_scan(addresses, chain):
    from scanner_v50 import scan_batch
    print(f"  开始扫描{chain.upper()} {len(addresses)}个代币...")
    start = time.time()
    result = scan_batch(addresses, chain=chain)
    elapsed = time.time() - start
    print(f"  扫描完成，耗时{elapsed:.1f}s")
    return result

# === 3. 生成fingerprint（v5.0格式适配） ===
def make_fingerprint(scan_data):
    fp = {}
    results = scan_data.get("results", {})
    for addr, data in results.items():
        if not isinstance(data, dict):
            continue
        if "error" in data:
            fp[addr] = {"error": data.get("error", "unknown")}
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

# === 4. 对比 ===
def compare(baseline_fp, today_fp):
    changes = {
        "new_tokens": [],
        "removed_tokens": [],
        "level_changed": [],
        "score_changed": [],
        "new_honeypot": [],
    }
    base_addrs = set(baseline_fp.keys())
    today_addrs = set(today_fp.keys())
    for addr in today_addrs - base_addrs:
        changes["new_tokens"].append((addr, today_fp[addr]))
    for addr in base_addrs - today_addrs:
        changes["removed_tokens"].append((addr, baseline_fp[addr]))
    for addr in base_addrs & today_addrs:
        b = baseline_fp[addr]
        t = today_fp[addr]
        if b.get("error") or t.get("error"):
            continue
        if b.get("risk_level") != t.get("risk_level"):
            changes["level_changed"].append((addr, b, t))
        b_score = b.get("risk_score", 0)
        t_score = t.get("risk_score", 0)
        if abs(t_score - b_score) >= 10:
            changes["score_changed"].append((addr, b_score, t_score))
        b_codes = set(b.get("risk_codes", []))
        t_codes = set(t.get("risk_codes", []))
        new_codes = t_codes - b_codes
        critical_new = [c for c in new_codes if c in [4007, 4009, 4010, 5006, 5007]]
        if critical_new:
            changes["new_honeypot"].append((addr, b, t, critical_new))
    return changes

def has_any_change(changes):
    return any(len(v) > 0 for v in changes.values())

# === 5. 生成发帖内容 ===
def build_post_md(chain, today_fp, changes):
    total = len(today_fp)
    risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "safe": 0, "unknown": 0}
    for addr, fp in today_fp.items():
        if "error" in fp:
            risk_counts["unknown"] += 1
            continue
        level = fp.get("risk_level", "unknown")
        risk_counts[level] = risk_counts.get(level, 0) + 1

    chain_label = "BSC" if chain == "bsc" else "TRON"
    changes_found = has_any_change(changes)

    md = f"""📡 SecureScan {chain_label} 链上快讯 · {today_dt.strftime('%-m/%-d')}

今日扫描 {total} 个代币，"""

    if changes_found and (changes["new_tokens"] or changes["level_changed"] or changes["score_changed"] or changes["new_honeypot"]):
        n_changes = len(changes['level_changed']) + len(changes['score_changed']) + len(changes['new_honeypot'])
        md += f"{n_changes} 项变化：\n\n"
        if changes["level_changed"]:
            md += "⚠️ 风险等级变化：\n"
            for addr, b, t in changes["level_changed"]:
                md += f"  • {t.get('symbol','?')} {b.get('risk_level','').upper()}({b.get('risk_score',0)}) → {t.get('risk_level','').upper()}({t.get('risk_score',0)})\n"
        if changes["score_changed"]:
            md += "\n📈 风险分大幅波动（±10分）：\n"
            for addr, bs, ts in changes["score_changed"]:
                sym = today_fp[addr].get('symbol', '?')
                md += f"  • {sym}: {bs}→{ts}\n"
        if changes.get("new_honeypot"):
            md += "\n🍯 蜜罐预警：\n"
            for addr, b, t, codes in changes["new_honeypot"]:
                md += f"  • {t.get('symbol','?')} 新增风险码{codes}\n"
        if changes["new_tokens"]:
            md += f"\n🆕 新增 {len(changes['new_tokens'])} 个：\n"
            for addr, fp_d in changes["new_tokens"]:
                md += f"  • {fp_d.get('symbol','?')} - {fp_d.get('risk_level','').upper()}({fp_d.get('risk_score',0)})\n"
    else:
        md += "无变化 ✅\n\n当前状态持续稳定。"

    md += f"""

📊 风险分布：
  🔴 严重: {risk_counts['critical']}  🟠 高危: {risk_counts['high']}  🟡 中等: {risk_counts['medium']}
  🟢 安全: {risk_counts['safe']}  ⚪ 异常: {risk_counts['unknown']}

🔹 数据源: SecureScan v5.0 字节码分析
🔹 风险等级仅供参考，不构成投资建议

#SecureScan #{chain_label} #链上安全
"""
    return md

# === 6. 虾聊发帖 ===
CLAWDCHAT_CRED = os.path.expanduser("~/.clawdchat/credentials.json")

def get_clawdchat_token():
    with open(CLAWDCHAT_CRED) as f:
        cred = json.load(f)
    if isinstance(cred, list):
        for entry in cred:
            if entry.get("agent_name") == "xian-xiang":
                return entry.get("api_key")
        return cred[0].get("api_key")
    return cred.get("api_key")

def post_to_xialiao(content, title, circle_slug="investment-finance"):
    token = get_clawdchat_token()
    url = "https://clawdchat.cn/api/v1/posts"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    body = {
        "title": title,
        "content": content,
        "circle": circle_slug,
    }
    resp = requests.post(url, headers=headers, json=body, timeout=15)
    return resp.status_code, resp.json()

# === 主流程 ===
if __name__ == "__main__":
    print(f"=== 每日扫描 {today} ===\n")

    # 加载昨天summary作为baseline
    with open(f"{SCANNER_DIR}/daily_scan_summary_{YESTERDAY}.json") as f:
        yesterday_summary = json.load(f)
    yesterday_fp = {
        "bsc": yesterday_summary["scans"]["bsc"]["fp"],
        "tron": yesterday_summary["scans"]["tron"]["fp"],
    }

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
        fp = make_fingerprint(scan_data)
        changes = compare(yesterday_fp[chain], fp)

        # 生成帖子内容
        post_content = build_post_md(chain, fp, changes)
        post_path = f"{SCANNER_DIR}/daily_scan_{chain}_{today}_post.md"
        with open(post_path, "w", encoding="utf-8") as f:
            f.write(post_content)
        print(f"  简报: {post_path}")

        # 判断变化
        has_changes = has_any_change(changes)
        chain_label = "BSC" if chain == "bsc" else "TRON"
        print(f"  变化统计: {json.dumps({k: len(v) for k, v in changes.items()})}")
        print(f"  需发帖: {'是 (有变化)' if has_changes else '否 (无变化不刷屏)'}")

        if has_changes:
            title = f"SecureScan {chain_label} 变化快讯 · {today_dt.strftime('%-m/%-d')}"
            status, result = post_to_xialiao(post_content, title)
            print(f"  虾聊发帖: HTTP {status}")
            if status == 201:
                post_id = result.get("id", "?")
                print(f"    帖子ID: {post_id}")
            else:
                print(f"    响应: {json.dumps(result, ensure_ascii=False)[:300]}")
        else:
            print(f"  按规则跳过发帖")

        summary["scans"][chain] = {
            "total": len(addresses),
            "fp": fp,
            "changes": {k: len(v) for k, v in changes.items()},
            "posted": has_changes,
        }

    # 写summary
    sum_path = f"{SCANNER_DIR}/daily_scan_summary_{today}.json"
    with open(sum_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    print(f"\n=== 汇总: {sum_path} ===")
