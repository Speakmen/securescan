#!/usr/bin/env python3
"""
多链智能合约安全扫描器 v4.0
================================================================
Agent-first 链上安全基础设施 - 为Agent设计，人类顺便能用

设计原则：
1. 输出优先JSON结构化，人类可读只是附加品
2. 风险代码标准化，Agent可直接程序化判断
3. 错误码清晰，便于Agent异常处理
4. 统一多链接口，上层Agent无需关心链差异
5. 无依赖、纯Python、可直接嵌入Agent运行时
================================================================
"""

import requests
import json
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict


# ============================================================
# 标准化风险代码
# ============================================================

RISK_CODES = {
    # 基本信息类 (1xxx)
    "NOT_A_CONTRACT":          {"code": 1001, "severity": "critical", "category": "基本信息"},
    "VERIFICATION_UNAVAILABLE": {"code": 1002, "severity": "medium",  "category": "信息透明度"},
    "UNVERIFIED_SOURCE":       {"code": 1003, "severity": "high",    "category": "信息透明度"},
    "VERIFIED":                {"code": 1004, "severity": "info",    "category": "信息透明度"},
    
    # 流动性类 (2xxx)
    "EXTREMELY_LOW_VOLUME":    {"code": 2001, "severity": "high",    "category": "流动性"},
    "LOW_VOLUME":              {"code": 2002, "severity": "medium",  "category": "流动性"},
    "GOOD_VOLUME":             {"code": 2003, "severity": "info",    "category": "流动性"},
    "HIGH_VOLUME":             {"code": 2004, "severity": "info",    "category": "流动性"},
    
    # 去中心化类 (3xxx)
    "EXTREME_CENTRALIZATION":  {"code": 3001, "severity": "critical", "category": "去中心化程度"},
    "VERY_FEW_HOLDERS":        {"code": 3002, "severity": "high",    "category": "去中心化程度"},
    "FEW_HOLDERS":             {"code": 3003, "severity": "medium",  "category": "去中心化程度"},
    "MANY_HOLDERS":            {"code": 3004, "severity": "info",    "category": "去中心化程度"},
    "WIDELY_DISTRIBUTED":      {"code": 3005, "severity": "info",    "category": "去中心化程度"},
    "SINGLE_WHALE":            {"code": 3006, "severity": "high",    "category": "筹码分布"},
    
    # 字节码异常类 (4xxx)
    "ABNORMAL_SIZE_SMALL":     {"code": 4001, "severity": "medium",  "category": "异常特征"},
    "LARGE_CONTRACT":          {"code": 4002, "severity": "low",     "category": "异常特征"},
    "MANY_INVALID_OPCODES":    {"code": 4003, "severity": "low",     "category": "异常特征"},
    "PROXY_CONTRACT_POSSIBLE": {"code": 4004, "severity": "medium",  "category": "可升级性"},
    "SELFDESTRUCT_POSSIBLE":   {"code": 4005, "severity": "high",    "category": "风险特征"},
    "MANY_ZERO_BALANCE":       {"code": 4006, "severity": "low",     "category": "异常特征"},
    
    # 权限控制类 (5xxx)
    "BLACKLIST_FUNCTION":      {"code": 5001, "severity": "medium",  "category": "权限控制"},
    "PAUSE_FUNCTION":          {"code": 5002, "severity": "low",     "category": "权限控制"},
    "OWNER_FUNCTION":          {"code": 5003, "severity": "low",     "category": "权限控制"},
    "OWNER_WITH_TIMELOCK":     {"code": 5004, "severity": "info",    "category": "权限控制"},
    "WHITELIST_FUNCTION":      {"code": 5005, "severity": "info",    "category": "权限控制"},
    
    # 代币经济学类 (6xxx)
    "MINT_FUNCTION_WITH_PERMISSION": {"code": 6001, "severity": "medium", "category": "代币经济学"},
    "MINT_FUNCTION_UNCONTROLLED":    {"code": 6002, "severity": "high",   "category": "代币经济学"},
    "BURN_FUNCTION":                 {"code": 6003, "severity": "info",   "category": "代币经济学"},
    "ZERO_TOTAL_SUPPLY":             {"code": 6004, "severity": "high",   "category": "代币经济学"},
    "SMALL_TOTAL_SUPPLY":            {"code": 6005, "severity": "low",    "category": "代币经济学"},
    
    # 标准符合性类 (7xxx)
    "ERC20_COMPLIANT":         {"code": 7001, "severity": "info",    "category": "标准符合性"},
    "NON_STANDARD_ERC20":      {"code": 7002, "severity": "low",     "category": "标准符合性"},
}


# ============================================================
# 数据结构 - 完全结构化，Agent友好
# ============================================================

@dataclass
class RiskItem:
    """风险项 - 100% 机器可读"""
    risk_code: str         # 标准化风险代码，如 "NOT_A_CONTRACT"
    severity: str          # critical/high/medium/low/info
    category: str          # 分类
    title: str             # 人类可读标题
    description: str       # 人类可读描述
    suggestion: str        # 人类可读建议
    confidence: float      # 置信度 0-1
    numeric_code: int = 0  # 数字风险码，便于比较
    
    def __post_init__(self):
        if self.risk_code in RISK_CODES:
            self.numeric_code = RISK_CODES[self.risk_code]["code"]


@dataclass
class ScanResult:
    """扫描结果 - 统一结构，跨链一致"""
    contract_address: str
    chain: str = "unknown"
    chain_id: int = 0
    
    # 合约元数据
    contract_name: str = ""
    token_name: str = ""
    token_symbol: str = ""
    token_decimals: int = 0
    total_supply: str = ""
    deployer: str = ""
    create_time: str = ""
    
    # 合约状态
    is_contract: bool = False
    is_verified: bool = False
    is_erc20: bool = False
    bytecode_size: int = 0
    transaction_count: int = 0
    holder_count: int = 0
    
    # 安全评分
    overall_score: int = 100
    risk_level: str = "unknown"  # safe/low/medium/high/critical
    risk_counts: Dict[str, int] = field(default_factory=lambda: {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
    })
    
    # 风险列表
    risks: List[RiskItem] = field(default_factory=list)
    
    # 元数据
    scan_time: str = ""
    scanner_version: str = "4.0"
    scanner_type: str = "agent-first"
    
    def __post_init__(self):
        self.scan_time = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    
    def add_risk(self, risk_code: str, **kwargs):
        """添加风险项 - 使用标准化风险代码"""
        if risk_code not in RISK_CODES:
            # 未注册的风险代码，降级处理
            info = {"severity": "low", "category": "未分类"}
        else:
            info = RISK_CODES[risk_code]
        
        risk = RiskItem(
            risk_code=risk_code,
            severity=kwargs.get("severity", info["severity"]),
            category=kwargs.get("category", info["category"]),
            title=kwargs.get("title", risk_code),
            description=kwargs.get("description", ""),
            suggestion=kwargs.get("suggestion", ""),
            confidence=kwargs.get("confidence", 0.8),
        )
        
        self.risks.append(risk)
        self.risk_counts[risk.severity] = self.risk_counts.get(risk.severity, 0) + 1
        
        # 动态计算评分
        score_map = {"critical": 40, "high": 20, "medium": 10, "low": 3, "info": 0}
        penalty = score_map.get(risk.severity, 0) * risk.confidence
        self.overall_score = max(0, self.overall_score - int(penalty))
        
        # 更新风险等级
        if self.overall_score >= 80:
            self.risk_level = "safe"
        elif self.overall_score >= 60:
            self.risk_level = "low"
        elif self.overall_score >= 40:
            self.risk_level = "medium"
        elif self.overall_score >= 20:
            self.risk_level = "high"
        else:
            self.risk_level = "critical"
    
    def to_dict(self) -> dict:
        """输出为字典 - Agent调用直接返回JSON"""
        return {
            "contract_address": self.contract_address,
            "chain": self.chain,
            "chain_id": self.chain_id,
            "metadata": {
                "contract_name": self.contract_name,
                "token_name": self.token_name,
                "token_symbol": self.token_symbol,
                "token_decimals": self.token_decimals,
                "total_supply": self.total_supply,
                "deployer": self.deployer,
                "create_time": self.create_time,
            },
            "status": {
                "is_contract": self.is_contract,
                "is_verified": self.is_verified,
                "is_erc20": self.is_erc20,
                "bytecode_size": self.bytecode_size,
                "transaction_count": self.transaction_count,
                "holder_count": self.holder_count,
            },
            "security": {
                "overall_score": self.overall_score,
                "risk_level": self.risk_level,
                "risk_counts": self.risk_counts,
                "risks": [asdict(r) for r in self.risks],
            },
            "meta": {
                "scan_time": self.scan_time,
                "scanner_version": self.scanner_version,
                "scanner_type": self.scanner_type,
            }
        }
    
    def to_json(self) -> str:
        """直接输出JSON字符串"""
        return json.dumps(self.to_dict(), ensure_ascii=False)
    
    def to_human_markdown(self) -> str:
        """人类可读格式 - 这是附赠的，不是主输出"""
        lines = []
        emoji_map = {"safe": "✅", "low": "🟢", "medium": "🟡", "high": "🟠", "critical": "🔴", "unknown": "⚪"}
        emoji = emoji_map.get(self.risk_level, "⚪")
        title = self.token_symbol or self.contract_name or "未知合约"
        
        lines.append(f"## {emoji} {title} (安全分: {self.overall_score}/100)")
        lines.append("")
        lines.append(f"- **链**: {self.chain.upper()}")
        lines.append(f"- **合约**: `{self.contract_address}`")
        lines.append(f"- **风险等级**: {self.risk_level.upper()}")
        lines.append("")
        lines.append("### 风险明细")
        lines.append("")
        
        for sev in ["critical", "high", "medium", "low", "info"]:
            items = [r for r in self.risks if r.severity == sev]
            if not items:
                continue
            for r in items:
                sev_emoji = emoji_map.get(sev, "⚪")
                lines.append(f"- {sev_emoji} **{r.title}** [{r.risk_code}]")
                lines.append(f"  置信度: {int(r.confidence*100)}% | {r.description}")
            lines.append("")
        
        lines.append("---")
        lines.append(f"*扫描时间: {self.scan_time} | v{self.scanner_version}*")
        return "\n".join(lines)


# ============================================================
# 基础扫描器 - 通用检测逻辑
# ============================================================

class BaseScanner:
    """基础扫描器抽象基类"""
    
    def __init__(self, chain: str, chain_id: int = 0):
        self.chain = chain
        self.chain_id = chain_id
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "SecureScan/4.0 (Agent-first; +https://github.com/)"
        })
    
    def scan(self, address: str) -> ScanResult:
        """扫描合约 - 子类实现"""
        raise NotImplementedError
    
    # ---------- 字节码风险检测（EVM通用） ----------
    
    def _analyze_bytecode(self, result: ScanResult, bytecode: str):
        """EVM字节码静态分析"""
        bc = bytecode.lower()
        
        # 1. 合约大小
        size = len(bc) // 2
        result.bytecode_size = size
        
        if size < 200:
            result.add_risk("ABNORMAL_SIZE_SMALL",
                description=f"合约字节码仅 {size} 字节，远小于标准ERC20的3-10KB")
        elif size > 50000:
            result.add_risk("LARGE_CONTRACT",
                description=f"合约字节码约 {size/1024:.1f} KB，属于大型复杂合约")
        
        # 2. DELEGATECALL 代理特征
        # 统计真正的操作码（不是数据中的）
        # 简单启发：f4 出现频率 + 上下文模式
        dc_patterns = ['60f4', '61f4', 'f460', 'f461', '3d60']
        dc_score = sum(bc.count(p) for p in dc_patterns)
        if dc_score >= 3 or bc.count('f4') > 8:
            result.add_risk("PROXY_CONTRACT_POSSIBLE",
                description="检测到多个DELEGATECALL操作码特征，可能是可升级代理合约")
        
        # 3. SELFDESTRUCT 特征
        sd_patterns = ['ff00', 'ff5b', '3dff', '60ff', 'ff60']
        sd_score = sum(bc.count(p) for p in sd_patterns)
        if sd_score >= 2:
            result.add_risk("SELFDESTRUCT_POSSIBLE",
                description="检测到SELFDESTRUCT操作码特征，存在自毁风险")
        
        # 4. INVALID 操作码
        invalid_count = bc.count('fe')
        if invalid_count > 20:
            result.add_risk("MANY_INVALID_OPCODES",
                description=f"检测到 {invalid_count} 个INVALID操作码，可能存在代码混淆")
    
    # ---------- ABI 功能检测 ----------
    
    def _analyze_abi(self, result: ScanResult, abi: list):
        """基于ABI的功能风险检测"""
        if not abi:
            return
        
        func_names = {item.get('name', '') for item in abi if item.get('type') == 'function'}
        
        # 黑名单功能
        blacklist_funcs = {'blacklist', 'addBlackList', 'removeBlackList', 'freezeAccount', 'destroyBlackFunds'}
        if func_names & blacklist_funcs:
            result.add_risk("BLACKLIST_FUNCTION",
                description="合约包含黑名单或资产冻结功能")
        
        # 增发功能
        mint_funcs = {'mint', '_mint', 'issue', 'mintToken', 'increaseSupply'}
        found_mint = func_names & mint_funcs
        if found_mint:
            has_owner = any('owner' in f.lower() for f in func_names)
            has_role = any('role' in f.lower() for f in func_names)
            if has_owner or has_role:
                result.add_risk("MINT_FUNCTION_WITH_PERMISSION",
                    description=f"存在受权限控制的增发功能: {', '.join(found_mint)}")
            else:
                result.add_risk("MINT_FUNCTION_UNCONTROLLED",
                    description=f"存在增发功能但权限控制不明确: {', '.join(found_mint)}")
        
        # 暂停功能
        pause_funcs = {'pause', 'unpause', 'paused', 'setPaused'}
        if func_names & pause_funcs:
            result.add_risk("PAUSE_FUNCTION",
                description="合约包含暂停功能，可暂停核心操作")
        
        # 所有权
        owner_funcs = {'owner', 'transferOwnership', 'renounceOwnership', 'getOwner'}
        if func_names & owner_funcs:
            has_timelock = any('timelock' in f.lower() for f in func_names)
            if has_timelock:
                result.add_risk("OWNER_WITH_TIMELOCK",
                    description="存在所有权机制且配置了时间锁")
            else:
                result.add_risk("OWNER_FUNCTION",
                    description="存在所有权机制，owner地址有特殊权限")
        
        # 销毁功能
        burn_funcs = {'burn', '_burn', 'burnFrom', 'destroy'}
        if func_names & burn_funcs:
            result.add_risk("BURN_FUNCTION",
                description="存在代币销毁功能")
        
        # 白名单
        whitelist_funcs = {'whitelist', 'addWhitelist', 'removeWhitelist', 'isWhitelisted'}
        if func_names & whitelist_funcs:
            result.add_risk("WHITELIST_FUNCTION",
                description="存在白名单功能")


# ============================================================
# TRON 扫描器
# ============================================================

class TronScanner(BaseScanner):
    """TRON 合约扫描器 - 基于 Tronscan API"""
    
    def __init__(self):
        super().__init__(chain="tron", chain_id=195)
        self.base_url = "https://apilist.tronscan.org/api"
    
    def _api_get(self, endpoint: str, params: dict = None) -> dict:
        try:
            r = self.session.get(f"{self.base_url}/{endpoint}", params=params, timeout=15)
            if r.status_code == 200:
                return r.json()
        except Exception as e:
            print(f"[TRON API Error] {endpoint}: {e}")
        return {}
    
    def scan(self, address: str) -> ScanResult:
        result = ScanResult(contract_address=address, chain="tron", chain_id=195)
        
        # 1. 账户信息
        account = self._api_get("account", {"address": address})
        if account:
            contract_map = account.get('contractMap', {})
            result.is_contract = address in contract_map or contract_map.get(address, False)
            result.contract_name = account.get('name', '')
            result.transaction_count = account.get('totalTransactionCount', 0)
            result.deployer = account.get('creator', '') or account.get('owner_address', '')
            
            # TRC20 代币信息
            for token in account.get('trc20token_balances', []):
                if token.get('tokenId', '').lower() == address.lower():
                    result.token_name = token.get('tokenName', '')
                    result.token_symbol = token.get('tokenAbbr', '')
                    result.token_decimals = token.get('decimal', 0)
                    result.total_supply = str(token.get('totalSupply', 0))
                    result.holder_count = token.get('nrOfTokenHolders', 0)
                    result.is_erc20 = True
                    break
        
        # 2. 合约代码
        code_info = self._api_get("contracts/code", {"contract": address})
        code_data = code_info.get('data', code_info) if isinstance(code_info, dict) else {}
        bytecode = code_data.get('byteCode', '')
        
        if bytecode and isinstance(bytecode, str):
            result.is_contract = True
            self._analyze_bytecode(result, bytecode)
            
            # ABI 验证状态
            abi_str = code_data.get('abi', '')
            if abi_str and isinstance(abi_str, str) and abi_str not in ('[]', '{}'):
                result.is_verified = True
                try:
                    abi = json.loads(abi_str)
                    self._analyze_abi(result, abi)
                except:
                    pass
        
        # 3. 验证状态风险
        if result.is_contract:
            if result.is_verified:
                result.add_risk("VERIFIED", description="合约源代码已验证")
            else:
                result.add_risk("UNVERIFIED_SOURCE", description="合约源代码未验证，存在黑盒风险")
        else:
            result.add_risk("NOT_A_CONTRACT", description="该地址不是智能合约")
            return result
        
        # 4. 流动性分析
        if result.transaction_count > 0:
            if result.transaction_count < 100:
                result.add_risk("EXTREMELY_LOW_VOLUME",
                    description=f"累计交易仅 {result.transaction_count} 次，流动性极差")
            elif result.transaction_count < 1000:
                result.add_risk("LOW_VOLUME",
                    description=f"累计交易 {result.transaction_count} 次，流动性偏低")
            elif result.transaction_count > 1000000:
                result.add_risk("HIGH_VOLUME",
                    description=f"累计交易 {result.transaction_count/1000000:.1f}M 次，流动性良好")
            elif result.transaction_count > 10000:
                result.add_risk("GOOD_VOLUME",
                    description=f"累计交易 {result.transaction_count/1000:.1f}K 次，有一定流动性")
        
        # 5. 持有者分析
        if result.holder_count > 0:
            if result.holder_count < 10:
                result.add_risk("EXTREME_CENTRALIZATION",
                    description=f"仅 {result.holder_count} 个持有者，筹码极度集中")
            elif result.holder_count < 100:
                result.add_risk("VERY_FEW_HOLDERS",
                    description=f"仅 {result.holder_count} 个持有者，去中心化程度低")
            elif result.holder_count < 1000:
                result.add_risk("FEW_HOLDERS",
                    description=f"{result.holder_count} 个持有者，去中心化程度较低")
            elif result.holder_count > 100000:
                result.add_risk("WIDELY_DISTRIBUTED",
                    description=f"{result.holder_count/1000:.0f}K 持有者，分布广泛")
            elif result.holder_count > 10000:
                result.add_risk("MANY_HOLDERS",
                    description=f"{result.holder_count/1000:.1f}K 持有者，用户基础较好")
            
            # 筹码集中度
            holders = self._get_holders(address)
            if holders and len(holders) > 1:
                top1 = int(holders[0].get('balance', 0))
                top2 = int(holders[1].get('balance', 0))
                if top2 > 0 and top1 / top2 > 10:
                    result.add_risk("SINGLE_WHALE",
                        description=f"第一大持有者持有量是第二名的 {top1/top2:.1f} 倍")
            
            # 零余额地址检测
            zero_count = sum(1 for h in holders if int(h.get('balance', 0)) == 0)
            if holders and zero_count > len(holders) * 0.3:
                result.add_risk("MANY_ZERO_BALANCE",
                    description=f"前{len(holders)}名持有者中 {zero_count} 个零余额，可能刷数据")
        
        return result
    
    def _get_holders(self, address: str, limit: int = 20) -> list:
        data = self._api_get("token_trc20/holders", {
            "contract_address": address, "page_size": limit, "page": 1
        })
        return data.get("data", []) if isinstance(data, dict) else []


# ============================================================
# BSC 扫描器
# ============================================================

class BscScanner(BaseScanner):
    """BSC 合约扫描器 - 基于公共RPC节点"""
    
    def __init__(self):
        super().__init__(chain="bsc", chain_id=56)
        self.rpc_url = "https://bsc.publicnode.com"
    
    def _rpc(self, method: str, params: list = None) -> Any:
        payload = {"jsonrpc": "2.0", "method": method, "params": params or [], "id": 1}
        try:
            r = self.session.post(self.rpc_url, json=payload, timeout=15)
            if r.status_code == 200:
                return r.json().get("result")
        except Exception as e:
            print(f"[BSC RPC Error] {method}: {e}")
        return None
    
    def _call(self, addr: str, sig_hex: str) -> Optional[str]:
        return self._rpc("eth_call", [{"to": addr, "data": "0x" + sig_hex}, "latest"])
    
    def _decode_string(self, hex_data: str) -> Optional[str]:
        if not hex_data or hex_data == "0x":
            return None
        try:
            h = hex_data[2:] if hex_data.startswith("0x") else hex_data
            if len(h) < 128:
                return None
            str_len = int(h[64:128], 16)
            return bytes.fromhex(h[128:128+str_len*2]).decode("utf-8")
        except:
            return None
    
    def _decode_uint(self, hex_data: str) -> Optional[int]:
        if not hex_data or hex_data == "0x":
            return None
        try:
            h = hex_data[2:] if hex_data.startswith("0x") else hex_data
            return int(h, 16)
        except:
            return None
    
    def scan(self, address: str) -> ScanResult:
        result = ScanResult(contract_address=address, chain="bsc", chain_id=56)
        
        # 1. 字节码检测
        bytecode = self._rpc("eth_getCode", [address, "latest"])
        if not bytecode or bytecode == "0x":
            result.is_contract = False
            result.add_risk("NOT_A_CONTRACT", description="该地址不是智能合约")
            return result
        
        result.is_contract = True
        bc = bytecode[2:] if bytecode.startswith("0x") else bytecode
        self._analyze_bytecode(result, bc)
        
        # 2. ERC20 接口检测
        name = self._decode_string(self._call(address, "06fdde03"))  # name()
        symbol = self._decode_string(self._call(address, "95d89b41"))  # symbol()
        decimals = self._decode_uint(self._call(address, "313ce567"))  # decimals()
        supply = self._decode_uint(self._call(address, "18160ddd"))  # totalSupply()
        balance_of = self._call(address, "70a08231" + "0" * 64)  # balanceOf(address(0))
        
        result.is_erc20 = bool(symbol or name) and balance_of is not None
        result.token_name = name or ""
        result.token_symbol = symbol or ""
        result.token_decimals = decimals or 0
        result.total_supply = str(supply or 0)
        
        # 3. 验证状态 - BSCscan API不可用，标记为无法验证
        result.is_verified = False
        result.add_risk("VERIFICATION_UNAVAILABLE",
            description="BSC区块浏览器API受限，无法验证源代码状态")
        
        # 4. 标准符合性
        if result.is_erc20:
            result.add_risk("ERC20_COMPLIANT", description="符合ERC20标准接口")
        else:
            result.add_risk("NON_STANDARD_ERC20", description="不符合标准ERC20接口")
        
        # 5. 总供应量分析
        if supply and decimals:
            supply_dec = supply / (10 ** decimals)
            if supply == 0:
                result.add_risk("ZERO_TOTAL_SUPPLY", description="总供应量为0")
            elif supply_dec < 1000:
                result.add_risk("SMALL_TOTAL_SUPPLY",
                    description=f"总供应量仅 {supply_dec:,.0f}，数量较小")
        
        # 6. 交易数（仅nonce参考，不显示给用户，只作内部数据）
        nonce = self._decode_uint(self._rpc("eth_getTransactionCount", [address, "latest"]))
        if nonce:
            result.transaction_count = nonce
        
        return result


# ============================================================
# 工厂函数 - 上层Agent只需调用这个
# ============================================================

SUPPORTED_CHAINS = {
    "tron":  TronScanner,
    "trx":   TronScanner,
    "bsc":   BscScanner,
    "bnb":   BscScanner,
    "binance": BscScanner,
}


def scan(address: str, chain: str = "tron") -> dict:
    """
    扫描单个合约 - 主入口函数
    
    Args:
        address: 合约地址
        chain: 链名称 (tron/bsc)
    
    Returns:
        结构化扫描结果字典
    """
    scanner_class = SUPPORTED_CHAINS.get(chain.lower())
    if not scanner_class:
        return {"error": f"Unsupported chain: {chain}", "supported_chains": list(SUPPORTED_CHAINS.keys())}
    
    try:
        scanner = scanner_class()
        result = scanner.scan(address)
        return result.to_dict()
    except Exception as e:
        return {"error": str(e), "address": address, "chain": chain}


def scan_batch(addresses: List[str], chain: str = "tron") -> dict:
    """批量扫描"""
    results = []
    errors = []
    
    for addr in addresses:
        r = scan(addr.strip(), chain)
        if "error" in r:
            errors.append({"address": addr, "error": r["error"]})
        else:
            results.append(r)
    
    avg_score = sum(r["security"]["overall_score"] for r in results) / len(results) if results else 0
    
    return {
        "chain": chain,
        "total": len(addresses),
        "success": len(results),
        "failed": len(errors),
        "average_score": round(avg_score, 1),
        "results": results,
        "errors": errors,
        "scan_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


# ============================================================
# CLI 入口
# ============================================================

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print(json.dumps({
            "name": "SecureScan v4.0",
            "type": "agent-first",
            "supported_chains": ["tron", "bsc"],
            "usage": {
                "single": "python scanner_v40.py <address> [--chain tron|bsc]",
                "batch": "python scanner_v40.py --batch <file> [--chain tron|bsc]",
                "human": "加 --human 参数输出人类可读格式（默认JSON）"
            }
        }, ensure_ascii=False, indent=2))
        sys.exit(0)
    
    chain = "tron"
    human_mode = "--human" in sys.argv
    
    if "--chain" in sys.argv:
        idx = sys.argv.index("--chain")
        if idx + 1 < len(sys.argv):
            chain = sys.argv[idx + 1]
    
    if sys.argv[1] == "--batch" and len(sys.argv) > 2:
        with open(sys.argv[2]) as f:
            addrs = [l.strip() for l in f if l.strip()]
        result = scan_batch(addrs, chain)
        print(json.dumps(result, ensure_ascii=False, indent=2))
    
    else:
        addr = sys.argv[1].strip()
        result = scan(addr, chain)
        
        if human_mode and "error" not in result:
            # 用人类可读格式输出
            r = result
            print(f"# {r['metadata']['token_symbol'] or r['metadata']['contract_name'] or '未知合约'}")
            print(f"链: {r['chain'].upper()} | 地址: `{r['contract_address']}`")
            print(f"安全分: {r['security']['overall_score']}/100 | 等级: {r['security']['risk_level'].upper()}")
            print()
            print("## 风险详情")
            print()
            for risk in r['security']['risks']:
                sev = risk['severity']
                emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "ℹ️"}.get(sev, "⚪")
                print(f"- {emoji} **{risk['title']}** [{risk['risk_code']}]")
                print(f"  置信度: {int(risk['confidence']*100)}%")
                print(f"  {risk['description']}")
                if risk.get('suggestion'):
                    print(f"  建议: {risk['suggestion']}")
                print()
        else:
            print(json.dumps(result, ensure_ascii=False, indent=2))
