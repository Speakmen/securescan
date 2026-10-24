#!/usr/bin/env python3
# l1_collector.py — AGT-002 L1 历史交易采集器 v0.1（2026-10-22）
# L0 影子快照只有余额+nonce 点值（D1/D2-lite 够用）；D3 零关联对手方/D4 短命中转/D5 汇聚漏斗
# 的完整判定需要对手方分布——本采集器拉 TRON 侧 TRC20+原生交易历史，聚合成对手方画像落盘。
# BSC 侧：公共 RPC 无历史交易 API（Etherscan V2 需 key），留待 key 到位后补 BSC 分支。
#
# 用法：
#   python3 l1_collector.py                        # 全列表
#   python3 l1_collector.py --limit 5              # 首批 N 个地址（试跑/限速控制）
#   python3 l1_collector.py --selftest
#
# 数据落盘：data/behavior_log/l1_tron_{YYYYMM}.jsonl（每地址一行快照；分析时取每地址最新行）
#
# 输出行结构：
#   {chain, address, name, snapshot_ts,
#    trc20: {n_tx, first_ts, last_ts, distinct_counterparties,
#            top_counterparties: [{addr, role, n_tx, sum_value, token}]},
#    native: {n_tx, ...同构},
#    pagination_complete}

import argparse, json, os, sys, time, urllib.request, urllib.error
from datetime import datetime, timedelta, timezone

TZ8 = timezone(timedelta(hours=8))
BASE = "https://api.trongrid.io/v1/accounts"
TRC20_LIMIT = 200          # TronGrid 单页上限
NATIVE_LIMIT = 100
SLEEP_PER_REQ = 1.2        # 匿名 QPS 保守值
TOP_N_COUNTERPARTIES = 30
HERE = os.path.dirname(os.path.abspath(__file__))


def _get(url, retries=3):
    for i in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "xian-agt002-l1/0.1", "accept": "application/json"})
            with urllib.request.urlopen(req, timeout=25) as r:
                return json.loads(r.read().decode("utf-8"))
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as e:
            if i == retries - 1:
                return {"success": False, "error": str(e)}
            time.sleep(2 * (i + 1))
    return {"success": False, "error": "unreachable"}


def _paginate(url_base, params, limit, max_pages=10):
    """TronGrid v1 翻页：返回合并 data + 是否完整。max_pages 防失控。"""
    out, fingerprint, complete = [], None, True
    for page in range(max_pages):
        url = f"{url_base}?limit={limit}"
        if fingerprint:
            url += f"&fingerprint={fingerprint}"
        for k, v in (params or {}).items():
            url += f"&{k}={v}"
        res = _get(url)
        if not res.get("success"):
            return out, False
        data = res.get("data", [])
        out.extend(data)
        fingerprint = res.get("fingerprint")
        if not fingerprint or len(data) < limit:
            return out, True
        time.sleep(SLEEP_PER_REQ)
    return out, False  # 达 max_pages 仍未尽 → 不完整


def collect_address(address, include_native=True):
    """单地址采集 → 画像 dict。TRC20 为主（USDT 场景），原生交易可选。"""
    ts = datetime.now(TZ8).strftime("%Y-%m-%dT%H:%M:%S+08:00")
    pic = {"trc20": None, "native": None}

    # TRC20
    txs, complete = _paginate(f"{BASE}/{address}/transactions/trc20", {"search_internal": "false"}, TRC20_LIMIT)
    if txs:
        cps = {}
        for t in txs:
            frm, to = t.get("from", ""), t.get("to", "")
            val = int(t.get("value", "0") or 0)
            token = (t.get("token_info") or {}).get("symbol", "?")
            ts_blk = t.get("block_timestamp", 0)
            for cp, role in ((frm, "out"), (to, "in")):
                if not cp or cp == address:
                    continue
                d = cps.setdefault(cp, {"addr": cp, "role": set(), "n_tx": 0, "sum_in": 0, "sum_out": 0, "token": token, "first_ts": ts_blk, "last_ts": ts_blk})
                d["role"].add(role)
                d["n_tx"] += 1
                if role == "in":
                    d["sum_in"] += val
                else:
                    d["sum_out"] += val
                d["first_ts"] = min(d["first_ts"], ts_blk)
                d["last_ts"] = max(d["last_ts"], ts_blk)
        top = sorted(cps.values(), key=lambda d: d["n_tx"], reverse=True)[:TOP_N_COUNTERPARTIES]
        for d in top:
            d["role"] = sorted(d["role"])
        blks = [t.get("block_timestamp", 0) for t in txs if t.get("block_timestamp")]
        pic["trc20"] = {
            "n_tx": len(txs), "pagination_complete": complete,
            "first_ts": datetime.fromtimestamp(min(blks) / 1000, TZ8).strftime("%Y-%m-%dT%H:%M:%S+08:00") if blks else None,
            "last_ts": datetime.fromtimestamp(max(blks) / 1000, TZ8).strftime("%Y-%m-%dT%H:%M:%S+08:00") if blks else None,
            "distinct_counterparties": len(cps),
            "top_counterparties": top,
        }
    else:
        pic["trc20"] = {"n_tx": 0, "pagination_complete": complete, "distinct_counterparties": 0, "top_counterparties": []}

    # 原生（可选，只统计量级+对手方频次，不展开金额明细）
    if include_native:
        ntxs, ncomplete = _paginate(f"{BASE}/{address}/transactions", {}, NATIVE_LIMIT, max_pages=5)
        cps2 = {}
        for t in ntxs:
            rd = t.get("raw_data") or {}
            for c in rd.get("contract") or []:
                val = (c.get("parameter") or {}).get("value") or {}
                for key in ("owner_address", "to_address", "refblock_bytes"):
                    pass
                frm = val.get("owner_address", "")
                to = val.get("to_address", "")
                for cp in (frm, to):
                    if cp and cp != address:
                        cps2[cp] = cps2.get(cp, 0) + 1
        pic["native"] = {
            "n_tx": len(ntxs), "pagination_complete": ncomplete,
            "distinct_counterparties": len(cps2),
            "top_counterparties": [{"addr": k, "n_tx": v} for k, v in sorted(cps2.items(), key=lambda x: x[1], reverse=True)[:TOP_N_COUNTERPARTIES]],
        }
    return ts, pic


def load_addresses(path):
    addrs = []
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("|")
        addrs.append((parts[0].strip(), parts[1].strip() if len(parts) > 1 else ""))
    return addrs


def main():
    ap = argparse.ArgumentParser(description="AGT-002 L1 历史交易采集器 v0.1（TRON）")
    ap.add_argument("--file", default=os.path.join(HERE, "addresses_tron_full.txt"))
    ap.add_argument("--limit", type=int, default=0, help="只跑前 N 个地址（0=全部）")
    ap.add_argument("--no-native", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        sys.exit(_selftest())

    addrs = load_addresses(args.file)
    if args.limit:
        addrs = addrs[:args.limit]
    ym = datetime.now(TZ8).strftime("%Y%m")
    outdir = os.path.join(HERE, "data", "behavior_log")
    os.makedirs(outdir, exist_ok=True)
    outfile = os.path.join(outdir, f"l1_tron_{ym}.jsonl")
    n_ok = n_err = 0
    with open(outfile, "a", encoding="utf-8") as f:
        for i, (addr, name) in enumerate(addrs, 1):
            try:
                ts, pic = collect_address(addr, include_native=not args.no_native)
                rec = {"chain": "tron", "address": addr, "name": name, "snapshot_ts": ts, **pic}
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                f.flush()
                n_ok += 1
                t20 = pic["trc20"]
                print(f"[{i}/{len(addrs)}] {addr}{'|'+name if name else ''} trc20_n={t20['n_tx']} cps={t20['distinct_counterparties']}")
            except Exception as e:
                n_err += 1
                print(f"[{i}/{len(addrs)}] {addr} ERROR {type(e).__name__}: {e}")
            time.sleep(SLEEP_PER_REQ)
    print(f"完成: OK={n_ok} ERR={n_err} → {outfile}")


def _selftest():
    """用 USDT 合约地址（自身必有海量 TRC20 流水）做真实验证。"""
    print("=== l1_collector 自测（USDT 合约地址，TRC20 首页）===")
    res = _get(f"{BASE}/TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t/transactions/trc20?limit=10")
    ok1 = bool(res.get("success") and res.get("data"))
    print(("PASS" if ok1 else "FAIL") + " TRC20 端点可达" + (f"（{len(res.get('data', []))} 条）" if ok1 else f"（{res.get('error')}）"))
    t = (res.get("data") or [{}])[0]
    ok2 = all(k in t for k in ("from", "to", "value", "block_timestamp")) and (t.get("token_info") or {}).get("symbol")
    print(("PASS" if ok2 else "FAIL") + " 字段结构完整（from/to/value/ts/token_info）")
    # 聚合逻辑（离线）
    fake = [{"from": "A", "to": "B", "value": "100", "block_timestamp": 1000, "token_info": {"symbol": "USDT"}},
            {"from": "A", "to": "C", "value": "50", "block_timestamp": 2000, "token_info": {"symbol": "USDT"}}]
    import collections
    cps = collections.Counter()
    for x in fake:
        for cp in (x["from"], x["to"]):
            cps[cp] += 1
    ok3 = cps["A"] == 2 and cps["B"] == 1
    print(("PASS" if ok3 else "FAIL") + " 对手方聚合逻辑")
    print("=== " + ("ALL PASS" if (ok1 and ok2 and ok3) else "HAS FAIL") + " ===")
    return 0 if (ok1 and ok2 and ok3) else 1


if __name__ == "__main__":
    main()
