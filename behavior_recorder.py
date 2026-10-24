#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AGT-002 L0 影子记录器 v0.1（behavior_recorder.py）
================================================
对应设计稿：SecureScan_AGT-002_非授权交互模式设计稿_20261021.md 第五节（数据依赖分层 L0 层）

定位：
  - 对监控列表地址做 L0 快照（余额 / nonce / 是否合约），追加写入 JSONL 行为日志。
  - **影子模式**：只记录，不做任何判定与报警（设计稿第六节：基线积累 2-4 周后再校准阈值）。
  - 数据落盘后即构成 AGT-002 基线建模（滑窗基线 / 时间衰减）的原始序列。

数据源（2026-10-21 实测）：
  - BSC：公共 RPC https://bsc.publicnode.com（bsc-dataseed / defibit / llamarpc 当前出口不通）
  - TRON：https://api.trongrid.io（getaccount，visible=true）

诚实边界：
  - L0 只能看"现在"（余额快照），看不到历史交易——历史回填依赖 L1（区块浏览器 API key）。
  - 快照是点值，行为模式判定需要序列；本文件只负责攒序列，判定逻辑在 AGT-002 二期实现。

用法：
  python behavior_recorder.py bsc 0x55d398326f99059fF775485246999027B3197955
  python behavior_recorder.py tron --file addresses_tron.txt
"""

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

import requests

# BSC 公共 RPC 复用 AGT-001 类常量（单一事实源）；
# TRON 快照在 _tron_post 内按 endpoint 参数拼 URL（getaccount/getcontract 同域不同方法）
from agt_scanner import AgentCredentialScanner

BSC_PUBLIC_RPC = AgentCredentialScanner.BSC_PUBLIC_RPC
ETH_PUBLIC_RPC = AgentCredentialScanner.ETH_PUBLIC_RPC

LOG_DIR = Path(__file__).parent / "data" / "behavior_log"

# TRON 最小单位 sun；BSC 最小单位 wei。均以字符串存储避免精度丢失。
TRON_DEFAULT_BALANCE = 0


class BehaviorRecorder:
    """L0 快照记录器：余额/nonce/合约标志 → JSONL 追加。"""

    def __init__(self, chain: str, timeout: int = 10):
        self.chain = chain.lower()
        if self.chain not in ("bsc", "tron", "eth"):
            raise ValueError(f"不支持的链: {chain}（仅 bsc/eth/tron）")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "SecureScan-AGT002-L0/0.2"})
        # EVM 链（bsc/eth）共用 eth_* 方法族，仅 RPC URL 不同；TRON 走 _tron_post
        self.rpc_url = {"bsc": BSC_PUBLIC_RPC, "eth": ETH_PUBLIC_RPC}.get(self.chain)

    # ---------- EVM（BSC/ETH 公共 RPC，方法族同构仅 URL 不同） ----------
    def _evm_rpc(self, method: str, params: list) -> Optional[dict]:
        payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
        for attempt in range(3):
            try:
                r = self.session.post(self.rpc_url, json=payload, timeout=self.timeout)
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

    # ---------- TRON（TronGrid getaccount + getcontract 探测） ----------
    def _tron_post(self, body: dict, endpoint: str = "getaccount") -> Optional[dict]:
        url = f"https://api.trongrid.io/wallet/{endpoint}"
        for attempt in range(3):
            try:
                r = self.session.post(url, json=body, timeout=self.timeout)
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

    # ---------- 快照 ----------
    def snapshot(self, address: str) -> dict:
        """取单地址 L0 快照；字段缺失时以 null 标注（诚实原则：拿不到就说拿不到）。"""
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        rec = {
            "ts": ts,
            "chain": self.chain,
            "address": address,
            "balance": None,          # 最小单位（wei/sun），字符串
            "nonce": None,            # BSC=交易计数；TRON=account 判存即 1
            "is_contract": None,
            "source": "L0",
        }
        try:
            if self.chain in ("bsc", "eth"):
                bal = self._evm_rpc("eth_getBalance", [address, "latest"])
                if bal and "result" in bal:
                    rec["balance"] = str(int(bal["result"], 16))
                nonce = self._evm_rpc("eth_getTransactionCount", [address, "latest"])
                if nonce and "result" in nonce:
                    rec["nonce"] = int(nonce["result"], 16)
                code = self._evm_rpc("eth_getCode", [address, "latest"])
                if code and isinstance(code.get("result"), str):
                    rec["is_contract"] = len(code["result"]) > 2
            else:  # tron
                acct = self._tron_post({"address": address, "visible": True})
                if acct is not None:  # 请求成功（空对象=链上不存在的账户）
                    rec["balance"] = str(int(acct.get("balance", TRON_DEFAULT_BALANCE)))
                    rec["nonce"] = 1 if acct else 0
                # 合约判定：getaccount 无 code 字段（2026-10-21 实测），改用 getcontract 探测。
                # 注意：getcontract 的地址参数名是 value 不是 address（TronGrid 命名不一致坑）
                probe = self._tron_post({"value": address, "visible": True},
                                        endpoint="getcontract")
                if probe is not None:
                    rec["is_contract"] = bool(
                        probe.get("bytecode") or probe.get("abi") or probe.get("contractName")
                    )
        except Exception as e:
            rec["error"] = f"snapshot_failed: {type(e).__name__}"
        return rec

    def record(self, address: str) -> dict:
        """快照并追加落盘。返回记录内容（便于 CLI 展示）。"""
        rec = self.snapshot(address)
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        month = datetime.now(timezone.utc).strftime("%Y%m")
        path = LOG_DIR / f"{self.chain}_{month}.jsonl"
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        return rec


def _load_addresses(args: List[str]) -> List[str]:
    """支持 --file addresses.txt 或直接列出地址。"""
    if args and args[0] == "--file":
        if len(args) < 2:
            raise SystemExit("--file 需要指定地址文件路径")
        path = Path(args[1])
        if not path.exists():
            raise SystemExit(f"地址文件不存在: {path}")
        lines = []
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip().split("|")[0].strip()  # 兼容 "0x...|WBNB" 命名尾巴
            if line and not line.startswith("#"):
                lines.append(line)
        return lines
    return [a.strip() for a in args if a.strip()]


def main():
    import sys
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    chain = sys.argv[1].lower()
    addresses = _load_addresses(sys.argv[2:])
    if not addresses:
        raise SystemExit("未解析到任何地址")

    recorder = BehaviorRecorder(chain)
    print(f"[AGT-002 L0 影子记录] chain={chain} 地址数={len(addresses)} → {LOG_DIR}")
    for i, addr in enumerate(addresses):
        rec = recorder.record(addr)
        print(json.dumps(rec, ensure_ascii=False))
        if i < len(addresses) - 1:
            time.sleep(0.8 if chain == "tron" else 0.3)
    print("[完成] 影子模式：仅记录，无判定。")


if __name__ == "__main__":
    main()
