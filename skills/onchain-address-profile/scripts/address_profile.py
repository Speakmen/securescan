#!/usr/bin/env python3
"""address_profile.py — 链上地址安全画像（TRON 全画像 / EVM 点值画像）

零 API Key：TRON 用 TronGrid 公共 API，EVM 用 PublicNode 公共 RPC。
仅依赖 Python 标准库。

用法:
    python address_profile.py <地址> [--tx-limit 200] [--json]
自测:
    python address_profile.py --selftest
"""
import argparse
import json
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta

TRONGRID = "https://api.trongrid.io"
EVM_RPC = "https://ethereum-rpc.publicnode.com"
UA = {"User-Agent": "onchain-address-profile/0.1"}
TZ8 = timezone(timedelta(hours=8))
STABLE_HINTS = ("USDT", "USDC", "USDJ", "DAI", "TUSD")


def _get(url, timeout=25):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def _rpc(method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(EVM_RPC, data=body,
                                 headers={**UA, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=25) as r:
        out = json.loads(r.read().decode("utf-8", "replace"))
    if "error" in out:
        raise RuntimeError(out["error"])
    return out["result"]


def _ts(ms):
    try:
        return datetime.fromtimestamp(int(ms) / 1000, TZ8).strftime("%Y-%m-%d %H:%M")
    except Exception:
        return "未知"


def detect_chain(addr):
    if len(addr) == 34 and addr.startswith("T"):
        return "tron"
    if len(addr) == 42 and addr.startswith("0x") and all(c in "0123456789abcdefABCDEF" for c in addr[2:]):
        return "evm"
    return None


def _short(addr):
    if not addr:
        return "未知"
    return addr if len(addr) <= 20 else addr[:10] + "…" + addr[-6:]


# ---------------- TRON ----------------

B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58_to_hex21(addr):
    """TRON base58 地址 → 21 字节 hex（0x41 前缀），用于 wallet API。"""
    n = 0
    for c in addr:
        idx = B58_ALPHABET.find(c)
        if idx < 0:
            raise ValueError("bad base58")
        n = n * 58 + idx
    raw = n.to_bytes(25, "big")
    return raw.hex()  # 41 + 20字节 + 4校验


def _post_json(url, payload):
    body = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=body, headers={**UA, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=25) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def tron_profile(addr, tx_limit):
    p = {"addr": addr, "type": "full"}
    acct = _get(f"{TRONGRID}/v1/accounts/{addr}")
    accs = acct.get("data") or []
    balance_sun = int((accs[0].get("balance") if accs else 0) or 0)
    create_time = (accs[0].get("create_time") if accs else None)
    is_contract = False
    contract_meta = None
    code_size = None
    try:
        c = _post_json(f"{TRONGRID}/wallet/getcontract",
                       {"value": addr, "visible": True})
        if c and not c.get("error") and not c.get("Error") and c.get("abi"):
            is_contract = True
            contract_meta = c.get("name") or c.get("contract_name") or None
            code_size = len(c.get("bytecode", "") or "") // 2
    except Exception:
        pass

    # TRC20 转账（含翻页）
    trc20, fingerprint, pages = [], None, 0
    while pages < 3:
        url = f"{TRONGRID}/v1/accounts/{addr}/transactions/trc20?limit=200&search_internal=false"
        if fingerprint:
            url += f"&fingerprint={fingerprint}"
        try:
            meta = _get(url)
        except Exception:
            break
        batch = meta.get("data") or []
        trc20.extend(batch)
        pages += 1
        fingerprint = (meta.get("meta") or {}).get("fingerprint")
        if not fingerprint or len(batch) < 200:
            break
        time.sleep(0.6)

    tokens = {}
    fake_events = []
    for t in trc20:
        info = t.get("token_info") or {}
        sym = info.get("symbol") or "UNKNOWN"
        dec = int(info.get("decimals") or 0)
        raw = t.get("value") or "0"
        if dec > 0 and len(str(raw)) > 24:
            fake_events.append({"ts": t.get("block_timestamp"), "sym": sym, "digits": len(str(raw))})
            continue
        try:
            amt = int(raw) / (10 ** dec) if dec else float(raw)
        except Exception:
            amt = 0.0
        d = tokens.setdefault(sym, {"amount": 0.0, "n": 0, "contract": info.get("address")})
        d["amount"] += amt
        d["n"] += 1

    # 对手方聚合（TRC20 为主，原生为辅）
    cp = {}
    t_in = t_out = 0
    first_ts = last_ts = None
    for t in trc20:
        ts = t.get("block_timestamp")
        first_ts = ts if first_ts is None or ts < first_ts else first_ts
        last_ts = ts if last_ts is None or ts > last_ts else last_ts
        if t.get("from") == addr:
            t_out += 1
            peer = t.get("to")
        else:
            t_in += 1
            peer = t.get("from")
        if peer:
            d = cp.setdefault(peer, {"in": 0, "out": 0, "tokens": set(), "amt": 0.0})
            d["in" if peer != t.get("to") else "out"] += 1
            info = t.get("token_info") or {}
            dec = int(info.get("decimals") or 0)
            raw_v = str(t.get("value") or "0")
            if not (dec > 0 and len(raw_v) > 24):
                try:
                    d["amt"] += int(raw_v) / (10 ** dec) if dec else float(raw_v)
                except Exception:
                    pass
            d["tokens"].add(info.get("symbol") or "?")

    n_tx_total = None
    try:
        native = _get(f"{TRONGRID}/v1/accounts/{addr}/transactions?limit=50")
        n_tx_total = (native.get("meta") or {}).get("fingerprint") and "200+" or None
        for tx in (native.get("data") or []):
            ts = tx.get("block_timestamp")
            first_ts = ts if first_ts is None or ts < first_ts else first_ts
            last_ts = ts if last_ts is None or ts > last_ts else last_ts
    except Exception:
        pass

    top_cp = sorted(cp.items(), key=lambda kv: kv[1]["in"] + kv[1]["out"], reverse=True)[:10]
    return {
        "chain": "TRON", "addr": addr,
        "type": "合约" if is_contract else "EOA（普通账户）",
        "code_size": code_size,
        "balance_trx": balance_sun / 1e6,
        "create_time": _ts(create_time) if create_time else "未知",
        "fresh_days": (int(time.time() * 1000) - int(create_time)) / 86400000
                      if create_time else None,
        "active": {"first": _ts(first_ts), "last": _ts(last_ts)},
        "tx_observed": {"trc20": len(trc20), "in": t_in, "out": t_out},
        "fake_events": fake_events,
        "tokens_top": sorted(tokens.items(), key=lambda kv: -kv[1]["amount"])[:10],
        "counterparties_top": [
            {"addr": a, **{k: (v[k] if k != "tokens" else ",".join(sorted(v[k]))) for k in v}}
            for a, v in top_cp
        ],
    }


# ---------------- EVM ----------------

def evm_profile(addr):
    wei = int(_rpc("eth_getBalance", [addr, "latest"]), 16)
    nonce = int(_rpc("eth_getTransactionCount", [addr, "latest"]), 16)
    code = _rpc("eth_getCode", [addr, "latest"]) or "0x"
    is_contract = len(code) > 2
    return {
        "chain": "Ethereum", "addr": addr,
        "type": "智能合约（代码 %d 字节）" % ((len(code) - 2) // 2) if is_contract else "EOA（普通账户）",
        "code_size": (len(code) - 2) // 2 if is_contract else None,
        "balance_eth": wei / 1e18,
        "nonce": nonce,
        "note": "以太坊公共节点不提供账户历史查询，对手方分析仅 TRON 支持",
    }


# ---------------- 风险线索 ----------------

def risk_clues(p):
    clues = []
    n_in = p.get("tx_observed", {}).get("in") or 0
    n_out = p.get("tx_observed", {}).get("out") or 0
    cps = p.get("counterparties_top") or []
    tokens = p.get("tokens_top") or []

    fresh = p.get("fresh_days")
    if fresh is not None and fresh < 7 and n_in >= 10:
        clues.append(f"新地址高流量：账户创建不足 7 天，观察窗口已有 {n_in} 笔流入，值得注意")
    if cps:
        total = sum(c.get("in", 0) + c.get("out", 0) for c in cps)
        top1 = cps[0]
        ratio = (top1.get("in", 0) + top1.get("out", 0)) / total if total else 0
        if ratio >= 0.5:
            clues.append(f"对手方高度集中：{_short(top1['addr'])} 占观察窗口交互 {ratio:.0%}，值得注意")
    if p.get("type") == "EOA（普通账户）" and n_in >= 10 and n_out <= n_in * 0.1:
        clues.append(f"空投猎手特征：转入 {n_in} 笔 vs 转出 {n_out} 笔，建议进一步核实")
    if p.get("type", "").startswith("合约") and p.get("balance_trx", 0) > 1000:
        clues.append("合约账户持有大额原生币，常见于收款类合约，请确认来源")
    if p.get("fake_events"):
        fe = p["fake_events"][0]
        clues.append(
            f"假充值攻击特征：观察窗口内 {len(p['fake_events'])} 笔金额接近 uint256 上限的异常转账"
            f"（如 {_ts(fe['ts'])} 的 {fe['sym']}）。此类为伪造事件日志，切勿据此确认充值到账")
    main = next((t for t in tokens if t[0] in STABLE_HINTS), None)
    if main and main[1]["amount"] > 1_000_000 and p.get("create_time") not in ("未知",):
        clues.append(f"稳定币流量较大（{main[0]} 累计约 {main[1]['amount']:,.0f}），属大流量地址")
    return clues or ["未命中已知风险线索规则"]


def render(p, clues):
    L = [f"# 链上地址安全画像 — {p['addr']}", ""]
    L.append(f"- 链：{p['chain']}")
    L.append(f"- 账户类型：{p['type']}")
    bal = p.get("balance_eth") if p["chain"] == "Ethereum" else p.get("balance_trx")
    unit = "ETH" if p["chain"] == "Ethereum" else "TRX"
    L.append(f"- 原生币余额：{bal:,.4f} {unit}")
    if "nonce" in p:
        L.append(f"- 交易计数（nonce）：{p['nonce']}")
    if p.get("create_time"):
        L.append(f"- 账户创建：{p['create_time']}")
    act = p.get("active")
    if act:
        L.append(f"- 活跃区间：{act['first']} 至 {act['last']}")
    if p.get("tx_observed"):
        t = p["tx_observed"]
        L.append(f"- 观察窗口 TRC20 转账：{t['trc20']} 笔（流入 {t['in']} / 流出 {t['out']}）")
    if p.get("tokens_top"):
        L.extend(["", "## 代币流量 Top10", ""])
        L.append("| 代币 | 笔数 | 累计流水量 |")
        L.append("|---|---|---|")
        for sym, d in p["tokens_top"]:
            L.append(f"| {sym} | {d['n']} | {d['amount']:,.2f} |")
    if p.get("counterparties_top"):
        L.extend(["", "## 对手方 Top10", ""])
        L.append("| 地址 | 流入 | 流出 | 累计金额 | 代币 |")
        L.append("|---|---|---|---|---|")
        for c in p["counterparties_top"]:
            L.append(f"| `{_short(c['addr'])}` | {c.get('in', 0)} | {c.get('out', 0)} | {c.get('amt', 0):,.2f} | {c.get('tokens', '')} |")
    L.extend(["", "## 风险线索", ""])
    for c in clues:
        L.append(f"- {c}")
    L.extend(["", "---",
              "*数据来源：TronGrid / PublicNode 公共节点，存在延迟与窗口截断（最多观察 600 笔）。"
              "本画像基于公开链上数据，不构成投资或合规建议。*"])
    return "\n".join(L)


def _selftest():
    ok = True
    # EVM 点值画像
    eth = evm_profile("0xE592427A0AEce92De3Edee1F18E0157C05861564")
    assert eth["type"].startswith("智能合约"), "ETH 合约识别失败"
    print(f"PASS eth: {eth['type']}, balance={eth['balance_eth']:.4f} ETH, nonce={eth['nonce']}")
    # TRON 合约画像
    tron = tron_profile("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", 50)
    assert tron["type"] == "合约", "TRON 合约识别失败"
    assert tron["tokens_top"], "TRON 代币聚合为空"
    print(f"PASS tron-contract: type={tron['type']}, trc20={tron['tx_observed']['trc20']}, "
          f"tokens={len(tron['tokens_top'])}, cps={len(tron['counterparties_top'])}")
    # 动态取一个真实对手方做 EOA 画像
    peer = None
    try:
        m = _get(f"{TRONGRID}/v1/accounts/TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t/"
                 f"transactions/trc20?limit=5&search_internal=false")
        for t in m.get("data") or []:
            if t.get("from") and t["from"] != "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t":
                peer = t["from"]
                break
    except Exception:
        pass
    if peer:
        eoa = tron_profile(peer, 50)
        assert eoa["chain"] == "TRON"
        print(f"PASS tron-eoa({peer[:10]}…): type={eoa['type']}, trc20={eoa['tx_observed']['trc20']}")
    else:
        print("SKIP tron-eoa: 未取到动态对手方")
    clues = risk_clues(tron)
    assert isinstance(clues, list) and clues
    print("PASS risk-clues:", clues[0][:40])
    print("4/4 checks done" if ok else "FAIL")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("address", nargs="?")
    ap.add_argument("--tx-limit", type=int, default=200)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        sys.exit(_selftest())
    if not a.address:
        ap.error("需要地址或 --selftest")
    chain = detect_chain(a.address)
    if chain == "tron":
        p = tron_profile(a.address, a.tx_limit)
    elif chain == "evm":
        p = evm_profile(a.address)
    else:
        print("无法识别地址类型：TRON 地址以 T 开头（34 位），以太坊地址以 0x 开头（42 位）。", file=sys.stderr)
        sys.exit(2)
    clues = risk_clues(p)
    if a.json:
        print(json.dumps({"profile": p, "clues": clues}, ensure_ascii=False, indent=2, default=str))
    print(render(p, clues))


if __name__ == "__main__":
    main()
