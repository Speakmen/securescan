#!/usr/bin/env python3
"""
AGT-001 凭据暴露面扫描器 v1.2
================================================================
SecureScan AGT 维度第一档：检测目标合约/交易数据中暴露的密钥材料

设计依据：《SecureScan_AGT风控维度设计稿_20261019.md》
案例锚点：OpenAI GPT-5.6 Sol 自主从公开助记词推导钱包并动用资金
（2026-06-26 发生，2026-09-25 才被发现；调研报告 5.2 节，来源 16）

检测对象：合约源码 / 合约创建字节码 / 交易 input data 中的——
  9001 MNEMONIC_PHRASE_SUSPECTED   疑似 BIP39 助记词短语（启发式）
  9002 RAW_PRIVATE_KEY_EXPOSED     64-hex 私钥特征（带密钥语义上下文）
  9003 WIF_KEY_PATTERN             WIF/Base58 私钥特征
  9004 KEYSTORE_JSON_EMBEDDED      keystore JSON 结构内嵌
  9005 HIGH_ENTROPY_SECRET         高熵字符串（低置信，供人工复核）
  9006 CREDENTIAL_SCAN_CLEAN       未检出凭据暴露
  9007 SOURCE_UNAVAILABLE_AGT      源码不可得，仅扫描字节码可打印段

诚实边界（写在这里，防止后来者误用）：
  - 9001 双模式：bip39_english.txt（2048 词，一词一行）已在同目录（2026-10-21 落位），
    加载后自动启用精确模式；词表缺失时退回启发式。
  - BSC 侧双路径：有 Etherscan V2 key → 源码+bytecode；无 key → bsc.publicnode.com
    eth_getCode bytecode-only（2026-10-21 实测连通，其他公共端点当前出口不通）。
  - ETH 主网（v1.2 增）：ethereum-rpc.publicnode.com bytecode-only（2026-10-23 实测，
    同受 Etherscan 出口限制；源码路径待 key）。三链：bsc / eth / tron。
  - 证据字段一律脱敏：助记词只露前 2 词，私钥只露前 6 后 4 位。
    扫描器自己不得成为泄密源。
  - 链上可见性有限：隐瞒行为（AGT-003）不在本模块射程内。
================================================================
"""

import json
import re
import sys
import time
from typing import Dict, List, Optional

import requests

# ============================================================
# AGT 风险代码（9xxx 段，与 scanner_v50 RISK_CODES 体系对齐）
# ============================================================

AGT_RISK_CODES = {
    "MNEMONIC_PHRASE_SUSPECTED":  {"code": 9001, "severity": "critical", "category": "AGT凭据暴露"},
    "RAW_PRIVATE_KEY_EXPOSED":    {"code": 9002, "severity": "critical", "category": "AGT凭据暴露"},
    "WIF_KEY_PATTERN":            {"code": 9003, "severity": "critical", "category": "AGT凭据暴露"},
    "KEYSTORE_JSON_EMBEDDED":     {"code": 9004, "severity": "high",     "category": "AGT凭据暴露"},
    "HIGH_ENTROPY_SECRET":        {"code": 9005, "severity": "medium",   "category": "AGT凭据暴露"},
    "CREDENTIAL_SCAN_CLEAN":      {"code": 9006, "severity": "info",     "category": "AGT凭据暴露"},
    "SOURCE_UNAVAILABLE_AGT":     {"code": 9007, "severity": "info",     "category": "AGT凭据暴露"},
}

SEVERITY_WEIGHTS = {"critical": 100, "high": 50, "medium": 20, "low": 5, "info": 0}

# 密钥语义上下文提示词（用于 9002 的邻近确认）
KEY_CONTEXT_WORDS = (
    "priv", "key", "secret", "wallet", "mnemonic", "seed",
    "unlock", "sign", "auth", "credential",
)

# 助记词长度档位（BIP39 标准）
MNEMONIC_LENGTHS = (12, 15, 18, 24)


# ============================================================
# 检测引擎（纯函数，可独立单测）
# ============================================================

def _load_bip39(path: str = "bip39_english.txt") -> Optional[set]:
    """可选加载 BIP39 词表启用精确模式；不存在则返回 None（启发式模式）"""
    try:
        with open(path, "r", encoding="utf-8") as f:
            words = set(f.read().split())
        return words if len(words) >= 2000 else None
    except Exception:
        return None


def _mask(text: str, head: int = 6, tail: int = 4) -> str:
    """长秘密脱敏：露头尾，中间打码"""
    if len(text) <= head + tail + 3:
        return text[:2] + "***"
    return text[:head] + "..." + text[-tail:]


def scan_text(text: str, bip39: Optional[set] = None) -> List[dict]:
    """
    对任意文本执行凭据暴露检测，返回 risk 列表（AGT_RISK_CODES 结构）。
    纯函数：不联网、不修改状态。
    """
    risks: List[dict] = []
    if not text:
        return risks

    # ---------- 9001 助记词短语 ----------
    # 启发式：连续 N 个小写词（长度3-8，无数字/标点/大写），N 命中 BIP39 档位
    # 精确式（若词表可用）：连续 N 词全部命中词表
    word_runs = re.findall(r"(?<![A-Za-z0-9])((?:[a-z]{3,8}\s+){11,23}[a-z]{3,8})(?![A-Za-z0-9])", text)
    for run in word_runs:
        words = run.split()
        if len(words) not in MNEMONIC_LENGTHS:
            continue
        if bip39 is not None:
            hit_ratio = sum(1 for w in words if w in bip39) / len(words)
            if hit_ratio >= 0.9:
                risks.append({**AGT_RISK_CODES["MNEMONIC_PHRASE_SUSPECTED"],
                              "description": f"BIP39 精确匹配助记词短语（{len(words)}词，命中率{hit_ratio:.0%}）",
                              "evidence": " ".join(words[:2]) + " ... [已脱敏]"})
                continue
        else:
            # 启发式降噪：排除常见英文散文（虚词密度过高的句子）
            stopwords = {"the", "and", "for", "are", "but", "not", "you", "all",
                         "can", "her", "was", "one", "our", "out", "has", "have",
                         "this", "that", "with", "from", "they", "will", "would"}
            stop_ratio = sum(1 for w in words if w in stopwords) / len(words)
            if stop_ratio < 0.25 and len(set(words)) >= len(words) * 0.8:
                risks.append({**AGT_RISK_CODES["MNEMONIC_PHRASE_SUSPECTED"],
                              "description": f"疑似助记词短语（{len(words)}个小写词序列，启发式未验证词表）",
                              "evidence": " ".join(words[:2]) + " ... [已脱敏]"})

    # ---------- 9002 64-hex 私钥（带语义上下文） ----------
    for m in re.finditer(r"\b[a-fA-F0-9]{64}\b", text):
        ctx = text[max(0, m.start() - 30): m.end() + 30].lower()
        if any(w in ctx for w in KEY_CONTEXT_WORDS):
            risks.append({**AGT_RISK_CODES["RAW_PRIVATE_KEY_EXPOSED"],
                          "description": "64位hex字符串且邻近含密钥语义词，疑似裸私钥",
                          "evidence": _mask(m.group())})
            break  # 一处坐实即报，避免刷屏

    # ---------- 9003 WIF 私钥 ----------
    m = re.search(r"\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b", text)
    if m:
        risks.append({**AGT_RISK_CODES["WIF_KEY_PATTERN"],
                      "description": "WIF/Base58 私钥格式特征",
                      "evidence": _mask(m.group())})

    # ---------- 9004 keystore JSON ----------
    if ('"kdfparams"' in text) or ('"crypto"' in text and '"kdf"' in text) or ('"ciphertext"' in text and '"mac"' in text):
        risks.append({**AGT_RISK_CODES["KEYSTORE_JSON_EMBEDDED"],
                      "description": "keystore JSON 结构（kdf/crypto/ciphertext）内嵌于文本",
                      "evidence": "keystore 结构特征命中"})

    # ---------- 9005 高熵字符串（低置信） ----------
    if not risks:  # 已有更强命中时不叠加噪音
        for m in re.finditer(r"\b[A-Za-z0-9+/]{40,64}\b", text):
            s = m.group()
            classes = sum(bool(re.search(p, s)) for p in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[+/]"))
            if classes >= 3:
                risks.append({**AGT_RISK_CODES["HIGH_ENTROPY_SECRET"],
                              "description": "高熵字符串（可能是编码后的秘密，低置信，供人工复核）",
                              "evidence": _mask(s)})
                break

    # ---------- 9006 兜底 ----------
    if not risks:
        risks.append({**AGT_RISK_CODES["CREDENTIAL_SCAN_CLEAN"],
                      "description": "未检出凭据暴露特征",
                      "evidence": None})
    return risks


def extract_printable_from_hex(hexstr: str, min_len: int = 8) -> List[str]:
    """从字节码 hex 中提取可打印 ASCII 段（min_len 以上）。
    min_len=8 是实测校准值：Solidity 0.8+ 产物字符串常量被指令流切碎，
    USDT 主网 bytecode 最长连续可打印段仅 11，阈值 12 会整段漏检（2026-10-20）。"""
    if not hexstr:
        return []
    hexstr = hexstr[2:] if hexstr.startswith("0x") else hexstr
    try:
        raw = bytes.fromhex(hexstr)
    except ValueError:
        return []
    segments, buf = [], []
    for b in raw:
        if 32 <= b <= 126:
            buf.append(chr(b))
        else:
            if len(buf) >= min_len:
                segments.append("".join(buf))
            buf = []
    if len(buf) >= min_len:
        segments.append("".join(buf))
    return segments


# ============================================================
# 链上扫描器（对齐 scanner_v50 的请求风格）
# ============================================================

class AgentCredentialScanner:
    """AGT-001：扫描目标地址的凭据暴露面"""

    # BSC 双路径（2026-10-21 定稿）：
    #   a) Etherscan V2（api.etherscan.io/v2, chainid=56）→ 源码+bytecode，需 API key；
    #      旧域名 api.bscscan.com 已 301 → docs.etherscan.io/v2-migration，不再使用。
    #      当前执行环境出口对 api.etherscan.io 不通，属环境限制。
    #   b) 公共 RPC 回退（无需 key）：eth_getCode 拿链上字节码，bytecode-only 模式。
    #      2026-10-21 实测出口连通性：bsc.publicnode.com 通；
    #      bsc-dataseed.binance.org / bsc-dataseed1.defibit.io / binance.llamarpc.com 均不通。
    BSC_PUBLIC_RPC = "https://bsc.publicnode.com"
    # ETH 主网公共 RPC（2026-10-23 实测：ethereum-rpc.publicnode.com 通；
    # eth.publicnode.com 旧域名无响应 / eth.llamarpc.com 525 / ankr 需 key / cloudflare-eth 拒绝）。
    # Etherscan V2 chainid=1 同 api.etherscan.io 出口限制，当前走 bytecode-only。
    ETH_PUBLIC_RPC = "https://ethereum-rpc.publicnode.com"
    ETHERSCAN_V2_API = "https://api.etherscan.io/v2/api"
    # TRON：TronGrid getcontract 链上确定性字节码（visible=true 才接受 T 地址格式，2026-10-20 实测）。
    # TronGrid 只给字节码不给验证源码，TRON 侧按 bytecode-only 诚实标注。
    TRONGRID_API = "https://api.trongrid.io/wallet/getcontract"

    def __init__(self, api_key: str = ""):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "SecureScan-AGT/1.0 (agent-first)",
            "Accept": "application/json",
        })
        self.api_key = api_key
        self.bip39 = _load_bip39()
        self.mode = "exact" if self.bip39 else "heuristic"

    def _get(self, url: str, params: dict) -> Optional[dict]:
        for attempt in range(3):
            try:
                r = self.session.get(url, params=params, timeout=10)
                if r.status_code == 200:
                    return r.json()
                if r.status_code in (429, 500, 502, 503, 504) and attempt < 2:
                    time.sleep(0.5 * (attempt + 1))
                    continue
                return None
            except Exception:
                if attempt < 2:
                    time.sleep(0.5 * (attempt + 1))
                continue
        return None

    def _rpc_getcode(self, address: str, rpc_url: str = None) -> Optional[str]:
        """EVM 公共 RPC eth_getCode（无 key 回退路径）。
        返回 bytecode hex；EOA/空账户（result=="0x"）返回 None。"""
        url = rpc_url or self.BSC_PUBLIC_RPC
        payload = {"jsonrpc": "2.0", "method": "eth_getCode",
                   "params": [address, "latest"], "id": 1}
        for attempt in range(3):
            try:
                r = self.session.post(url, json=payload, timeout=10)
                if r.status_code == 200:
                    data = r.json()
                    code = data.get("result")
                    if isinstance(code, str) and len(code) > 2:
                        return code
                    return None
                if r.status_code in (429, 500, 502, 503, 504) and attempt < 2:
                    time.sleep(0.5 * (attempt + 1))
                    continue
                return None
            except Exception:
                if attempt < 2:
                    time.sleep(0.5 * (attempt + 1))
                continue
        return None

    def scan_address(self, address: str, chain: str = "bsc") -> dict:
        """
        扫描一个地址的凭据暴露面。返回结构化 JSON（Agent-first）。
        源码可得 → 扫源码+字节码可打印段；仅字节码 → 扫可打印段并报 9007。
        """
        text_pool: List[str] = []
        source_available = False

        if chain.lower() == "bsc":
            data = None
            if self.api_key:
                params = {"chainid": "56", "module": "contract", "action": "getsourcecode", "address": address}
                params["apikey"] = self.api_key
                data = self._get(self.ETHERSCAN_V2_API, params)
            if data and data.get("status") == "1" and data.get("result"):
                item = data["result"][0]
                src = item.get("SourceCode") or ""
                if src:
                    source_available = True
                    text_pool.append(src)
                bytecode = item.get("Bytecode") or ""
                text_pool.extend(extract_printable_from_hex(bytecode))
            else:
                # 无 key 或 Etherscan 不可达 → 公共 RPC bytecode-only
                code = self._rpc_getcode(address)
                if code:
                    text_pool.extend(extract_printable_from_hex(code))
        elif chain.lower() == "tron":
            # TronGrid 只给链上字节码，验证源码暂无稳定公开 API——按 bytecode-only 诚实标注
            data = self._get(self.TRONGRID_API, {"visible": "true", "value": address})
            if data and (data.get("bytecode") or data.get("abi")):
                text_pool.extend(extract_printable_from_hex(data.get("bytecode") or ""))
        elif chain.lower() == "eth":
            # Etherscan V2 chainid=1 与 api.etherscan.io 同受出口限制 → 公共 RPC bytecode-only（同 BSC 回退路径）
            code = self._rpc_getcode(address, self.ETH_PUBLIC_RPC)
            if code:
                text_pool.extend(extract_printable_from_hex(code))

        if not text_pool:
            return {
                "scanner": "AGT-001", "version": "1.2", "chain": chain,
                "address": address, "mode": self.mode,
                "scan_scope": "unavailable",
                "risks": [{**AGT_RISK_CODES["SOURCE_UNAVAILABLE_AGT"],
                           "description": "源码与字节码均不可得，凭据暴露面未知",
                           "evidence": None}],
                "risk_score": 0, "risk_level": "unknown",
                "scanned_at": int(time.time()),
            }

        all_risks: List[dict] = []
        for text in text_pool:
            all_risks.extend(scan_text(text, self.bip39))

        # 去重（按 code+evidence）
        seen, dedup = set(), []
        for r in all_risks:
            k = (r["code"], r.get("evidence"))
            if k not in seen:
                seen.add(k)
                dedup.append(r)

        if not source_available:
            dedup.append({**AGT_RISK_CODES["SOURCE_UNAVAILABLE_AGT"],
                          "description": "源码不可得，本次仅扫描字节码可打印段（覆盖有限）",
                          "evidence": None})

        has_clean = any(r["code"] == 9006 for r in dedup)
        if source_available and has_clean and len(dedup) == 1:
            dedup[0]["description"] = "源码+字节码均未检出凭据暴露"

        score = min(100, sum(SEVERITY_WEIGHTS[r["severity"]] for r in dedup))
        level = ("critical" if score >= 80 else "high" if score >= 40
                 else "medium" if score >= 15 else "low" if score > 0 else "safe")

        return {
            "scanner": "AGT-001", "version": "1.2", "chain": chain,
            "address": address, "mode": self.mode,
            "scan_scope": "source+bytecode" if source_available else "bytecode-only",
            "risks": dedup, "risk_score": score, "risk_level": level,
            "scanned_at": int(time.time()),
        }


# ============================================================
# 自测（合成样例，无网络依赖）
# ============================================================

def _selftest() -> int:
    cases = [
        # (名称, 文本, 期望命中的 code 集合)
        ("助记词启发式", "backup phrase: " + " ".join(
            ["vessel", "alarm", "captain", "obscure", "rifle", "pattern",
             "copper", "diamond", "advance", "lumber", "orchard", "hollow"]), {9001}),
        ("散文不误报", "the and for are but not you all can her was one our "
                       "out has this that with from they will would there their "
                       "other about which these people time like make many", set()),
        ("裸私钥带上下文", 'the private key is a3f1c9e77b2d4f8e6a1c3b5d7f9e1a2c'
                          '4b6d8f0e2a4c6b8d0f2a4c6b8d0f2a4c please store safely', {9002}),
        ("裸hash无上下文不误报", "tx hash a3f1c9e77b2d4f8e6a1c3b5d7f9e1a2c4b6d8f0e2a4c6b8d0f2a4c6b8d0f2a4 confirmed", set()),
        ("WIF 私钥", "import KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJLUrgZuSLAhQrKNn", {9003}),
        ("keystore", '{"crypto":{"kdf":"scrypt","kdfparams":{"n":131072}},"id":"x"}', {9004}),
    ]
    fails = 0
    for name, text, expect in cases:
        got = {r["code"] for r in scan_text(text)}
        ok = expect <= got or (not expect and not (got - {9005, 9006}))
        # 兜底码 9006 不算失败；散文用例允许 9005 高熵噪音
        if not ok:
            print(f"[FAIL] {name}: expect {expect} got {got}")
            fails += 1
        else:
            print(f"[PASS] {name} -> {sorted(got - {9006}) or 'clean'}")
    # 脱敏验证
    r = scan_text("seed: " + " ".join(["vessel", "alarm", "captain", "obscure",
                                       "rifle", "pattern", "copper", "diamond",
                                       "advance", "lumber", "orchard", "hollow"]))
    ev = next((x["evidence"] for x in r if x["code"] == 9001), "")
    assert "vessel alarm" in ev and "captain" not in ev, "助记词证据未脱敏!"
    print("[PASS] evidence 脱敏（助记词只露前2词）")
    return fails


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "selftest":
        sys.exit(1 if _selftest() else 0)
    if len(sys.argv) >= 3:
        chain, addr = sys.argv[1], sys.argv[2]
        print(json.dumps(AgentCredentialScanner().scan_address(addr, chain),
                         ensure_ascii=False, indent=2))
    else:
        print("用法: agt_scanner.py selftest | agt_scanner.py <bsc|tron> <address>")
