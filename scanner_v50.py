#!/usr/bin/env python3
"""
多链智能合约安全扫描器 v5.0
================================================================
Agent-first 链上安全基础设施 - 为Agent设计，人类顺便能用

v5.0 新增：
- 蜜罐检测（Honeypot Detection）
- 合约年龄与部署者分析
- 风险画像综合评分
- 函数选择器深度分析
- 更多风险代码
================================================================
"""

import requests
import json
import time
from typing import Dict, List, Optional, Any, Tuple
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
    "HONEYPOT_SUSPECTED":      {"code": 4007, "severity": "critical", "category": "蜜罐风险"},
    "HIGH_TAX_RISK":           {"code": 4008, "severity": "high",    "category": "税费风险"},
    "BLACKLIST_DETECTED":      {"code": 4009, "severity": "high",    "category": "权限控制"},
    "WHITELIST_ONLY":          {"code": 4010, "severity": "high",    "category": "权限控制"},
    
    # 权限控制类 (5xxx)
    "BLACKLIST_FUNCTION":      {"code": 5001, "severity": "medium",  "category": "权限控制"},
    "PAUSE_FUNCTION":          {"code": 5002, "severity": "low",     "category": "权限控制"},
    "OWNER_FUNCTION":          {"code": 5003, "severity": "low",     "category": "权限控制"},
    "OWNER_WITH_TIMELOCK":     {"code": 5004, "severity": "info",    "category": "权限控制"},
    "WHITELIST_FUNCTION":      {"code": 5005, "severity": "info",    "category": "权限控制"},
    "MINTABLE_OWNER":          {"code": 5006, "severity": "high",    "category": "权限控制"},
    "FREEZE_FUNCTION":         {"code": 5007, "severity": "high",    "category": "权限控制"},
    
    # 代币经济学类 (6xxx)
    "MINT_FUNCTION_WITH_PERMISSION": {"code": 6001, "severity": "medium", "category": "代币经济学"},
    "MINT_FUNCTION_UNCONTROLLED":    {"code": 6002, "severity": "high",   "category": "代币经济学"},
    "BURN_FUNCTION":                 {"code": 6003, "severity": "info",   "category": "代币经济学"},
    "ZERO_TOTAL_SUPPLY":             {"code": 6004, "severity": "high",   "category": "代币经济学"},
    "SMALL_TOTAL_SUPPLY":            {"code": 6005, "severity": "low",    "category": "代币经济学"},
    "TAX_ON_TRANSFER":               {"code": 6006, "severity": "medium", "category": "代币经济学"},
    "DEFLATIONARY_TOKEN":            {"code": 6007, "severity": "info",   "category": "代币经济学"},
    
    # 标准符合性类 (7xxx)
    "ERC20_COMPLIANT":         {"code": 7001, "severity": "info",    "category": "标准符合性"},
    "NON_STANDARD_ERC20":      {"code": 7002, "severity": "low",     "category": "标准符合性"},
    
    # 合约年龄类 (8xxx)
    "VERY_NEW_CONTRACT":       {"code": 8001, "severity": "high",    "category": "合约年龄"},
    "NEW_CONTRACT":            {"code": 8002, "severity": "medium",  "category": "合约年龄"},
    "MATURE_CONTRACT":         {"code": 8003, "severity": "info",    "category": "合约年龄"},
    "OLD_CONTRACT":            {"code": 8004, "severity": "info",    "category": "合约年龄"},
}

# 严重程度权重
SEVERITY_WEIGHTS = {
    "critical": 100,
    "high": 50,
    "medium": 20,
    "low": 5,
    "info": 0,
}


# ============================================================
# 数据结构 - 完全结构化，Agent友好
# ============================================================

@dataclass
class RiskItem:
    code: int
    severity: str
    category: str
    description: str
    evidence: Optional[str] = None


@dataclass
class ContractInfo:
    address: str
    chain: str
    symbol: str = ""
    name: str = ""
    decimals: int = 18
    total_supply: str = "0"
    is_contract: bool = False
    code_size: int = 0
    deployer: str = ""
    deploy_timestamp: int = 0
    contract_age_days: int = 0
    is_verified: bool = False
    is_proxy: bool = False
    implementation: str = ""


@dataclass
class FunctionInfo:
    selector: str
    name: str = ""
    signature: str = ""


@dataclass
class HoneyPotResult:
    is_honeypot: bool = False
    confidence: int = 0  # 0-100
    buy_tax: float = 0.0
    sell_tax: float = 0.0
    transfer_tax: float = 0.0
    has_blacklist: bool = False
    has_whitelist: bool = False
    has_pause: bool = False
    can_freeze: bool = False
    can_mint: bool = False
    owner_centralized: bool = False
    reasons: List[str] = field(default_factory=list)


@dataclass
class ScanResult:
    contract: ContractInfo
    risks: List[RiskItem] = field(default_factory=list)
    risk_score: int = 0  # 0-100, 越高越危险
    risk_level: str = "unknown"  # safe/low/medium/high/critical
    honeypot: HoneyPotResult = field(default_factory=HoneyPotResult)
    functions: List[FunctionInfo] = field(default_factory=list)
    holders_count: int = 0
    volume_24h: float = 0.0
    raw_data: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        return {
            "contract": asdict(self.contract),
            "risks": [asdict(r) for r in self.risks],
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "honeypot": asdict(self.honeypot),
            "functions": [asdict(f) for f in self.functions],
            "holders_count": self.holders_count,
            "volume_24h": self.volume_24h,
        }


# ============================================================
# 函数选择器数据库 (常用ERC20+风险函数)
# ============================================================

# function_signature -> selector
FUNCTION_SIGNATURES = {
    # ERC20 标准
    "totalSupply()": "18160ddd",
    "balanceOf(address)": "70a08231",
    "transfer(address,uint256)": "a9059cbb",
    "transferFrom(address,address,uint256)": "23b872dd",
    "approve(address,uint256)": "095ea7b3",
    "allowance(address,address)": "dd62ed3e",
    "name()": "06fdde03",
    "symbol()": "95d89b41",
    "decimals()": "313ce567",
    
    # 常见扩展
    "mint(address,uint256)": "40c10f19",
    "mint(uint256)": "a140ae29",
    "burn(uint256)": "42966c68",
    "burnFrom(address,uint256)": "79cc6790",
    "increaseAllowance(address,uint256)": "39509351",
    "decreaseAllowance(address,uint256)": "a457c2d0",
    
    # 权限相关
    "owner()": "8da5cb5b",
    "renounceOwnership()": "715018a6",
    "transferOwnership(address)": "f2fde38b",
    "Ownable": "8da5cb5b",
    
    # 暂停功能
    "pause()": "8456cb59",
    "unpause()": "3f4ba83a",
    "paused()": "5c975abb",
    "whenPaused": "e4e6e936",
    "whenNotPaused": "d2757d3d",
    
    # 黑名单
    "blacklist(address)": "febb43a5",
    "unblacklist(address)": "a5950b0a",
    "isBlacklisted(address)": "e6b1745d",
    "addBlackList(address)": "0xec99d253",
    "removeBlackList(address)": "0x5bad3e27",
    "destroyBlackFunds(address)": "0x6a13a46c",
    
    # 白名单
    "whitelist(address)": "fd98cd0c",
    "isWhitelisted(address)": "0a65a2e5",
    "addWhitelist(address)": "b9d10645",
    "removeWhitelist(address)": "b9d10645",
    
    # 冻结/锁定
    "freeze(address)": "8e1f8633",
    "unfreeze(address)": "0d231a2e",
    "isFrozen(address)": "907d42b6",
    "freezeAccount(address)": "47a74f6a",
    "unfreezeAccount(address)": "92c3d5ef",
    
    # 代理合约
    "implementation()": "0x5c6079d5",
    "getImplementation()": "0x42404e07",
    "upgradeTo(address)": "3659c666",
    "upgradeToAndCall(address,bytes)": "4f1ef286",
    "changeAdmin(address)": "8f283970",
    "admin()": "f851a440",
    
    # 可升级代理
    "_implementation()": "0x3534e9a9",
    "_setImplementation(address)": "0x941b3235",
    "proxiableUUID()": "0x52d1902d",
    
    # 税相关
    "setBuyTaxRate(uint256)": "12198632",
    "setSellTaxRate(uint256)": "0fbe3d8e",
    "taxRate()": "034e6a31",
    "buyTaxRate()": "0ea9a887",
    "sellTaxRate()": "0e209b40",
    "totalFees()": "095ea7b3",  # 常见但可能冲突
    
    # 流动性
    "addLiquidity(uint256,uint256)": "e8e33700",
    "removeLiquidity(uint256,uint256,uint256)": "baa2ab47",
    "swapExactTokensForETHSupportingFeeOnTransferTokens": "b6f9de95",
    "swapExactTokensForTokensSupportingFeeOnTransferTokens": "0d7a318f",
}

# 反向映射
SELECTOR_TO_SIGNATURE = {v: k for k, v in FUNCTION_SIGNATURES.items()}


# ============================================================
# 基础扫描器类
# ============================================================

class BaseScanner:
    """基础扫描器，定义通用接口"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; SecureScan/5.0)"
        })
    
    def _make_request(self, method: str, url: str, **kwargs) -> Optional[dict]:
        """统一请求处理"""
        try:
            resp = self.session.request(method, url, timeout=10, **kwargs)
            if resp.status_code == 200:
                return resp.json()
            return None
        except Exception:
            return None
    
    def scan(self, address: str) -> ScanResult:
        """扫描入口，子类实现"""
        raise NotImplementedError
    
    def _analyze_bytecode(self, bytecode: str) -> Tuple[List[FunctionInfo], HoneyPotResult]:
        """分析字节码，提取函数选择器和蜜罐特征"""
        functions = []
        honeypot = HoneyPotResult()
        
        if not bytecode or bytecode == "0x":
            return functions, honeypot
        
        # 移除0x前缀
        code = bytecode[2:] if bytecode.startswith("0x") else bytecode
        
        # 1. 提取PUSH4后的选择器（近似方法，用于快速筛查）
        # 实际的函数选择器分析需要更复杂的反汇编，这里用模式匹配
        selectors = set()
        
        # 常见模式：PUSH4 selector (63 + 8 hex chars)
        i = 0
        while i < len(code) - 10:
            if code[i:i+2] == "63":  # PUSH4
                selector = code[i+2:i+10]
                if len(selector) == 8:
                    selectors.add(selector.lower())
                i += 10
            else:
                i += 2
        
        # 2. 匹配已知函数
        for sel in selectors:
            func = FunctionInfo(selector=sel)
            if sel in SELECTOR_TO_SIGNATURE:
                func.signature = SELECTOR_TO_SIGNATURE[sel]
                func.name = func.signature.split("(")[0]
            functions.append(func)
        
        # 3. 蜜罐特征分析
        reasons = []
        risk_count = 0
        
        # 检查是否有mint功能（owner可无限铸币）
        has_mint = any(f.name in ["mint"] for f in functions)
        if has_mint:
            honeypot.can_mint = True
            reasons.append("存在mint函数，owner可铸币")
            risk_count += 1
        
        # 检查黑名单功能
        has_blacklist = any("blacklist" in f.name.lower() or "black" in f.name.lower() 
                           for f in functions if f.name)
        if has_blacklist:
            honeypot.has_blacklist = True
            reasons.append("存在黑名单功能，可能封禁地址")
            risk_count += 1
        
        # 检查白名单功能（仅白名单可交易 = 蜜罐特征）
        has_whitelist = any("whitelist" in f.name.lower() or "white" in f.name.lower()
                           for f in functions if f.name)
        if has_whitelist:
            honeypot.has_whitelist = True
            reasons.append("存在白名单功能，可能限制交易")
            risk_count += 2  # 白名单风险更高
        
        # 检查暂停功能
        has_pause = any(f.name in ["pause", "unpause", "paused"] for f in functions)
        if has_pause:
            honeypot.has_pause = True
            reasons.append("存在暂停功能，可随时暂停交易")
            risk_count += 1
        
        # 检查冻结功能
        has_freeze = any("freeze" in f.name.lower() or "frozen" in f.name.lower()
                         for f in functions if f.name)
        if has_freeze:
            honeypot.can_freeze = True
            reasons.append("存在冻结功能，可冻结用户资产")
            risk_count += 2
        
        # 检查是否有owner权限
        has_owner = any(f.name in ["owner", "transferOwnership", "renounceOwnership"] 
                       for f in functions)
        if has_owner:
            honeypot.owner_centralized = True
            # 有owner + 有mint/blacklist = 高风险
            if has_mint or has_blacklist:
                reasons.append("Owner权限过大，可铸币/拉黑")
                risk_count += 1
        
        # 检查税相关函数
        has_tax = any("tax" in f.name.lower() or "fee" in f.name.lower() 
                     for f in functions if f.name)
        if has_tax:
            honeypot.transfer_tax = 5.0  # 假设5%，实际需要模拟
            reasons.append("存在交易税设置函数")
            risk_count += 1
        
        # 检查代理合约
        is_proxy = any(f.name in ["implementation", "upgradeTo", "upgradeToAndCall", 
                                  "proxiableUUID"] for f in functions)
        if is_proxy:
            reasons.append("可能是可升级代理合约，逻辑可被替换")
            risk_count += 1
        
        # 计算蜜罐置信度 - 优化版，降低误判
        # 权重：白名单=核心特征，高权重
        confidence = 0
        
        # 白名单是蜜罐核心特征
        if has_whitelist:
            confidence += 40
            if is_proxy:
                confidence += 25  # 白名单+可升级 = 高危
            if has_blacklist:
                confidence += 15  # 白+黑 = 更危险
        
        # 黑名单
        if has_blacklist and not has_whitelist:
            confidence += 15
        
        # 冻结功能
        if has_freeze:
            confidence += 20
        
        # mint功能（正常项目也可能有mint，权重低）
        if has_mint:
            confidence += 10
        
        # 可升级代理
        if is_proxy and not has_whitelist:
            confidence += 10  # 单独的代理合约不一定是蜜罐
        
        # 交易税
        if has_tax:
            confidence += 10
        
        # 有pause但没有其他风险
        if has_pause and risk_count <= 2:
            confidence = max(confidence - 5, 5)  # 只有暂停是低风险
        
        confidence = min(95, confidence)
        
        # 只有1-2个风险特征时，降低置信度
        if risk_count <= 1:
            confidence = min(confidence, 15)
        elif risk_count == 2 and not has_whitelist and not has_freeze:
            confidence = min(confidence, 25)
        
        honeypot.confidence = confidence
        honeypot.is_honeypot = confidence >= 60
        honeypot.reasons = reasons
        
        return functions, honeypot
    
    def _calc_risk_score(self, risks: List[RiskItem]) -> Tuple[int, str]:
        """计算综合风险分数"""
        total = 0
        critical_count = 0
        high_count = 0
        
        for r in risks:
            weight = SEVERITY_WEIGHTS.get(r.severity, 0)
            total += weight
            if r.severity == "critical":
                critical_count += 1
            elif r.severity == "high":
                high_count += 1
        
        # 归一化到0-100
        score = min(100, int(total / 5))  # 5个critical就满了
        
        # 风险等级 - 更合理的分级
        if critical_count >= 2 or (critical_count > 0 and score >= 50):
            level = "critical"
        elif critical_count > 0 or high_count >= 2 or score >= 60:
            level = "high"
        elif score >= 30 or high_count >= 1:
            level = "medium"
        elif score >= 10:
            level = "low"
        else:
            level = "safe"
        
        return score, level
    
    def _get_age_risk(self, age_days: int) -> RiskItem:
        """根据合约年龄生成风险项"""
        if age_days < 1:
            return RiskItem(
                code=8001, severity="high", category="合约年龄",
                description=f"合约部署不到1天，风险极高",
                evidence=f"合约年龄: {age_days}天"
            )
        elif age_days < 7:
            return RiskItem(
                code=8002, severity="medium", category="合约年龄",
                description=f"合约部署不到7天，风险较高",
                evidence=f"合约年龄: {age_days}天"
            )
        elif age_days < 30:
            return RiskItem(
                code=8003, severity="low", category="合约年龄",
                description="合约部署超过1个月，相对成熟",
                evidence=f"合约年龄: {age_days}天"
            )
        else:
            return RiskItem(
                code=8004, severity="info", category="合约年龄",
                description="合约部署超过1个月，相对成熟",
                evidence=f"合约年龄: {age_days}天"
            )


# ============================================================
# TRON 扫描器
# ============================================================

class TronScanner(BaseScanner):
    """TRON链合约扫描器"""
    
    def __init__(self):
        super().__init__()
        self.base_url = "https://apilist.tronscan.org/api"
    
    def scan(self, address: str) -> ScanResult:
        result = ScanResult(
            contract=ContractInfo(address=address, chain="tron")
        )
        
        # 1. 获取TRC20代币信息
        token_info = self._get_token_info(address)
        contract_info = self._get_contract_detail(address)
        
        if token_info:
            result.contract.symbol = token_info.get("symbol", "")
            result.contract.name = token_info.get("name", "")
            result.contract.decimals = int(token_info.get("decimals", 6))
            result.contract.total_supply = str(token_info.get("total_supply", "0"))
            result.contract.is_contract = True
            result.holders_count = int(token_info.get("holders_count", 0))
            result.volume_24h = float(token_info.get("volume24h", 0))
            
            # 合约创建时间
            date_created = token_info.get("date_created", 0)
            if date_created:
                # 秒级时间戳
                result.contract.deploy_timestamp = date_created
                now = int(time.time())
                result.contract.contract_age_days = (now - date_created) // 86400
        
        if contract_info:
            # 验证状态：0=未验证, 1=待审核, 2=已验证
            verify_status = contract_info.get("verify_status", 0)
            result.contract.is_verified = (verify_status == 2)
            result.contract.code_size = contract_info.get("code_size", 0)
            
            # 创建者
            creator = contract_info.get("creator", {})
            if creator:
                result.contract.deployer = creator.get("address", "")
            
            # 代理合约
            result.contract.is_proxy = contract_info.get("is_proxy", False)
            
            # methodMap 用于函数分析
            method_map = contract_info.get("methodMap", {})
            if method_map:
                result.functions = [
                    FunctionInfo(selector=sel, name=name)
                    for sel, name in method_map.items()
                ]
        
        # 2. 获取字节码并分析（尝试）
        bytecode = self._get_bytecode(address)
        if bytecode:
            functions, honeypot = self._analyze_bytecode(bytecode)
            # 如果已有函数信息，合并补充
            if functions and not result.functions:
                result.functions = functions
            result.honeypot = honeypot
        else:
            # 无法获取字节码时，基于已有信息做简化判断
            result.honeypot = HoneyPotResult(
                is_honeypot=False,
                confidence=0,
                reasons=["无法获取字节码进行深度分析"]
            )
            # 检查是否有transfer方法（基本ERC20标准）
            has_transfer = any(
                "transfer" in f.name.lower() 
                for f in result.functions
            )
            if not has_transfer and result.contract.is_contract:
                result.honeypot = HoneyPotResult(
                    is_honeypot=True,
                    confidence=60,
                    reasons=["合约未实现标准transfer方法，可能无法正常转账"]
                )
        
        # 3. 生成风险项
        risks = []
        
        # 基本信息风险
        if not result.contract.is_contract:
            risks.append(RiskItem(
                code=1001, severity="critical", category="基本信息",
                description="该地址不是合约",
                evidence="未检测到合约信息"
            ))
        else:
            if result.contract.is_verified:
                risks.append(RiskItem(
                    code=1004, severity="info", category="信息透明度",
                    description="合约源码已验证",
                    evidence="verify_status = 2"
                ))
            else:
                risks.append(RiskItem(
                    code=1003, severity="high", category="信息透明度",
                    description="合约源码未验证",
                    evidence="verify_status != 2"
                ))
            
            if result.contract.is_proxy:
                risks.append(RiskItem(
                    code=1005, severity="medium", category="合约类型",
                    description="代理合约，逻辑可被升级替换",
                    evidence="is_proxy = true"
                ))
        
        # 合约年龄风险
        if result.contract.contract_age_days > 0:
            risks.append(self._get_age_risk(result.contract.contract_age_days))
        
        # 流动性风险
        if result.volume_24h > 1000000:
            risks.append(RiskItem(code=2004, severity="info", category="流动性",
                                  description="24h交易量高，流动性好",
                                  evidence=f"24h交易量: ${result.volume_24h:,.0f}"))
        elif result.volume_24h > 100000:
            risks.append(RiskItem(code=2003, severity="info", category="流动性",
                                  description="24h交易量良好",
                                  evidence=f"24h交易量: ${result.volume_24h:,.0f}"))
        elif result.volume_24h > 10000:
            risks.append(RiskItem(code=2002, severity="medium", category="流动性",
                                  description="24h交易量较低",
                                  evidence=f"24h交易量: ${result.volume_24h:,.0f}"))
        elif result.volume_24h > 0:
            risks.append(RiskItem(code=2001, severity="high", category="流动性",
                                  description="24h交易量极低",
                                  evidence=f"24h交易量: ${result.volume_24h:,.0f}"))
        else:
            risks.append(RiskItem(code=2000, severity="critical", category="流动性",
                                  description="无交易量数据",
                                  evidence="volume24h = 0"))
        
        # 持有者风险
        if result.holders_count > 100000:
            risks.append(RiskItem(code=3004, severity="info", category="持有者",
                                  description="持有者数量众多",
                                  evidence=f"持有者: {result.holders_count:,}"))
        elif result.holders_count > 10000:
            risks.append(RiskItem(code=3003, severity="info", category="持有者",
                                  description="持有者数量较多",
                                  evidence=f"持有者: {result.holders_count:,}"))
        elif result.holders_count > 1000:
            risks.append(RiskItem(code=3002, severity="medium", category="持有者",
                                  description="持有者数量偏少",
                                  evidence=f"持有者: {result.holders_count:,}"))
        elif result.holders_count > 0:
            risks.append(RiskItem(code=3001, severity="high", category="持有者",
                                  description="持有者数量很少",
                                  evidence=f"持有者: {result.holders_count:,}"))
        
        # 蜜罐风险
        if result.honeypot.is_honeypot:
            severity = "critical" if result.honeypot.confidence > 70 else "high"
            risks.append(RiskItem(
                code=4001, severity=severity, category="蜜罐风险",
                description="疑似蜜罐合约",
                evidence="; ".join(result.honeypot.reasons)
            ))
        
        # 计算风险评分
        score, level = self._calc_risk_score(risks)
        result.risk_score = score
        result.risk_level = level
        result.risks = risks
        
        return result
    
    def _get_token_info(self, address: str) -> Optional[dict]:
        """获取TRC20代币信息"""
        url = f"{self.base_url}/token_trc20"
        params = {"contract": address}
        data = self._make_request("GET", url, params=params)
        
        if data:
            tokens = data.get("trc20_tokens", [])
            if tokens and len(tokens) > 0:
                t = tokens[0]
                return {
                    "symbol": t.get("symbol", ""),
                    "name": t.get("name", ""),
                    "decimals": t.get("decimals", 6),
                    "total_supply": t.get("total_supply", 0),
                    "holders_count": t.get("holders_count", 0),
                    "volume24h": t.get("volume24h", 0),
                    "date_created": t.get("date_created", 0),
                    "level": t.get("level", 0),
                    "vip": t.get("vip", False),
                }
        return None
    
    def _get_contract_detail(self, address: str) -> Optional[dict]:
        """获取合约详细信息"""
        url = f"{self.base_url}/contract"
        params = {"contract": address}
        data = self._make_request("GET", url, params=params)
        
        if data and data.get("status", {}).get("code") == 0:
            contracts = data.get("data", [])
            if contracts and len(contracts) > 0:
                c = contracts[0]
                # 只有当确实是合约时才返回（有methodMap或verify_status存在）
                if c.get("methodMap") or c.get("verify_status", 0) > 0:
                    return {
                        "verify_status": c.get("verify_status", 0),
                        "is_proxy": c.get("is_proxy", False),
                        "proxy_implementation": c.get("proxy_implementation", ""),
                        "date_created": c.get("date_created", 0),
                        "methodMap": c.get("methodMap", {}),
                        "creator": c.get("creator", {}),
                        "trxCount": c.get("trxCount", 0),
                        "code_size": len(c.get("methodMap", {})),
                    }
        return None
    
    def _get_bytecode(self, address: str) -> Optional[str]:
        """获取合约字节码"""
        # 尝试TronGrid API
        try:
            url = "https://api.trongrid.io/wallet/getcontract"
            resp = self.session.post(url, json={"address": address}, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                bytecode = data.get("bytecode", "") or data.get("byte_code", "")
                if bytecode and len(bytecode) > 10:
                    return bytecode if bytecode.startswith("0x") else "0x" + bytecode
        except Exception:
            pass
        
        # 备用：尝试其他方式
        # 注意：由于API限制，可能无法获取字节码，此时返回None
        return None
    
    def _get_holder_count(self, address: str) -> int:
        """获取持有者数量（已整合到_get_token_info，保留兼容）"""
        token_info = self._get_token_info(address)
        if token_info:
            return token_info.get("holders_count", 0)
        return 0
    
    def _get_24h_volume(self, address: str) -> float:
        """获取24h交易量（已整合到_get_token_info，保留兼容）"""
        token_info = self._get_token_info(address)
        if token_info:
            return token_info.get("volume24h", 0)
        return 0.0

class BscScanner(BaseScanner):
    """BSC链合约扫描器（基于公共RPC）"""
    
    def __init__(self):
        super().__init__()
        self.rpc_url = "https://bsc.publicnode.com"
        self.etherscan_api = ""  # BSCscan被墙，暂不可用
    
    def scan(self, address: str) -> ScanResult:
        result = ScanResult(
            contract=ContractInfo(address=address, chain="bsc")
        )
        
        # 1. 检查是否为合约并获取字节码
        bytecode = self._get_bytecode(address)
        if bytecode and len(bytecode) > 2:
            result.contract.is_contract = True
            result.contract.code_size = len(bytecode) // 2 - 1  # hex chars / 2
            
            # 2. 字节码分析
            functions, honeypot = self._analyze_bytecode(bytecode)
            result.functions = functions
            result.honeypot = honeypot
        else:
            result.contract.is_contract = False
            result.risks.append(RiskItem(
                code=1001, severity="critical", category="基本信息",
                description="该地址不是合约",
                evidence="eth_getCode 返回空"
            ))
            result.risk_score = 100
            result.risk_level = "critical"
            return result
        
        # 3. 获取ERC20基本信息（通过RPC调用）
        erc20_info = self._get_erc20_info(address)
        if erc20_info:
            result.contract.symbol = erc20_info.get("symbol", "")
            result.contract.name = erc20_info.get("name", "")
            result.contract.decimals = erc20_info.get("decimals", 18)
            result.contract.total_supply = str(erc20_info.get("totalSupply", 0))
        
        # 4. 生成风险项
        risks = []
        
        # ERC20标准符合性
        if erc20_info and erc20_info.get("is_erc20", False):
            risks.append(RiskItem(
                code=7001, severity="info", category="标准符合性",
                description="符合ERC20标准",
                evidence="实现了ERC20核心方法"
            ))
        else:
            risks.append(RiskItem(
                code=7002, severity="low", category="标准符合性",
                description="可能不符合ERC20标准",
                evidence="部分ERC20方法调用失败"
            ))
        
        # 合约大小风险
        if result.contract.code_size < 1000:
            risks.append(RiskItem(
                code=4001, severity="medium", category="异常特征",
                description="合约字节码异常小，可能是恶意合约",
                evidence=f"code_size: {result.contract.code_size} bytes"
            ))
        elif result.contract.code_size > 50000:
            risks.append(RiskItem(
                code=4002, severity="low", category="异常特征",
                description="合约字节码较大",
                evidence=f"code_size: {result.contract.code_size} bytes"
            ))
        
        # 蜜罐风险
        if result.honeypot.is_honeypot:
            risks.append(RiskItem(
                code=4007, severity="critical", category="蜜罐风险",
                description=f"高度疑似蜜罐 (置信度: {result.honeypot.confidence}%)",
                evidence="; ".join(result.honeypot.reasons)
            ))
        elif result.honeypot.confidence > 30:
            risks.append(RiskItem(
                code=4007, severity="medium", category="蜜罐风险",
                description=f"存在部分蜜罐特征 (置信度: {result.honeypot.confidence}%)",
                evidence="; ".join(result.honeypot.reasons)
            ))
        
        # 权限风险
        if result.honeypot.has_blacklist:
            risks.append(RiskItem(
                code=5001, severity="medium", category="权限控制",
                description="存在黑名单功能",
                evidence="检测到blacklist相关函数"
            ))
        
        if result.honeypot.has_pause:
            risks.append(RiskItem(
                code=5002, severity="low", category="权限控制",
                description="存在暂停功能",
                evidence="检测到pause/unpause函数"
            ))
        
        if result.honeypot.can_mint:
            risks.append(RiskItem(
                code=5006, severity="high", category="权限控制",
                description="Owner可铸币，存在通胀风险",
                evidence="检测到mint函数"
            ))
        
        if result.honeypot.can_freeze:
            risks.append(RiskItem(
                code=5007, severity="high", category="权限控制",
                description="存在冻结功能，可冻结用户资产",
                evidence="检测到freeze相关函数"
            ))
        
        # 可升级代理风险
        if result.honeypot and any("代理" in r or "proxy" in r.lower() 
                                  for r in result.honeypot.reasons):
            risks.append(RiskItem(
                code=4004, severity="medium", category="可升级性",
                description="可能是可升级代理合约，逻辑可被替换",
                evidence="检测到代理合约特征函数"
            ))
        
        result.risks = risks
        result.risk_score, result.risk_level = self._calc_risk_score(risks)
        
        return result
    
    def _get_bytecode(self, address: str) -> Optional[str]:
        """通过RPC获取字节码"""
        payload = {
            "jsonrpc": "2.0",
            "method": "eth_getCode",
            "params": [address, "latest"],
            "id": 1
        }
        try:
            resp = self.session.post(self.rpc_url, json=payload, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                return data.get("result", "")
        except Exception:
            pass
        return None
    
    def _get_erc20_info(self, address: str) -> Optional[dict]:
        """通过RPC调用获取ERC20信息"""
        info = {}
        is_erc20 = True
        
        # 调用各个ERC20方法
        methods = {
            "name": "0x06fdde03",
            "symbol": "0x95d89b41",
            "decimals": "0x313ce567",
            "totalSupply": "0x18160ddd",
            "balanceOf": "0x70a08231",  # 需要参数，只测试存在性
        }
        
        for method_name, method_sig in methods.items():
            if method_name == "balanceOf":
                continue  # 需要address参数，跳过
            
            payload = {
                "jsonrpc": "2.0",
                "method": "eth_call",
                "params": [
                    {"to": address, "data": method_sig},
                    "latest"
                ],
                "id": 1
            }
            
            try:
                resp = self.session.post(self.rpc_url, json=payload, timeout=10)
                if resp.status_code == 200:
                    data = resp.json()
                    result = data.get("result", "")
                    
                    if result and result != "0x":
                        if method_name in ["name", "symbol"]:
                            # 解码字符串
                            try:
                                hex_str = result[2:]
                                # 动态长度字符串：前32字节是偏移，接下来32字节是长度，然后是内容
                                offset = int(hex_str[:64], 16)
                                length = int(hex_str[offset*2:offset*2+64], 16)
                                content = hex_str[offset*2+64:offset*2+64+length*2]
                                info[method_name] = bytes.fromhex(content).decode("utf-8", errors="replace").strip("\x00")
                            except Exception:
                                info[method_name] = ""
                        elif method_name == "decimals":
                            try:
                                info["decimals"] = int(result, 16)
                            except ValueError:
                                info["decimals"] = 18
                        elif method_name == "totalSupply":
                            try:
                                info["totalSupply"] = int(result, 16)
                            except ValueError:
                                info["totalSupply"] = 0
                    else:
                        is_erc20 = False
                else:
                    is_erc20 = False
            except Exception:
                is_erc20 = False
        
        info["is_erc20"] = is_erc20
        return info
    
    def _simulate_transfer(self, address: str, amount: int = 1000000000000000000) -> dict:
        """模拟转账（用于检测交易税）- 仅供参考，结果可能不准确"""
        # 这是一个简化的模拟，实际需要考虑很多边界情况
        result = {"success": False, "received": 0, "tax_rate": 0}
        return result  # 暂时不可用，需要更复杂的实现


# ============================================================
# 对外接口
# ============================================================

_scanners = {}

def _get_scanner(chain: str) -> BaseScanner:
    """获取对应链的扫描器"""
    if chain not in _scanners:
        if chain == "tron":
            _scanners[chain] = TronScanner()
        elif chain == "bsc":
            _scanners[chain] = BscScanner()
        else:
            raise ValueError(f"不支持的链: {chain}")
    return _scanners[chain]


def scan(address: str, chain: str = "tron") -> dict:
    """扫描单个合约"""
    scanner = _get_scanner(chain)
    result = scanner.scan(address)
    return result.to_dict()


def scan_batch(addresses: List[str], chain: str = "tron") -> dict:
    """批量扫描合约"""
    scanner = _get_scanner(chain)
    results = {}
    
    for addr in addresses:
        try:
            result = scanner.scan(addr)
            results[addr] = result.to_dict()
        except Exception as e:
            results[addr] = {"error": str(e)}
    
    return {
        "chain": chain,
        "count": len(results),
        "results": results,
        "timestamp": int(time.time())
    }


def generate_report(scan_data: dict, format_type: str = "markdown") -> str:
    """生成人类可读的报告"""
    if format_type == "json":
        return json.dumps(scan_data, indent=2, ensure_ascii=False)
    
    # Markdown格式
    if "results" in scan_data:
        # 批量扫描结果
        md = f"# BSC 代币安全扫描报告\n\n"
        md += f"- 扫描时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        md += f"- 扫描代币数: {scan_data.get('count', 0)}\n"
        md += f"- 链: {scan_data.get('chain', 'unknown')}\n\n"
        
        results = scan_data.get("results", {})
        # 按风险排序
        sorted_results = sorted(
            results.items(),
            key=lambda x: x[1].get("risk_score", 0) if isinstance(x[1], dict) else 0,
            reverse=True
        )
        
        # 统计
        risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "safe": 0}
        for addr, data in sorted_results:
            if isinstance(data, dict):
                level = data.get("risk_level", "unknown")
                risk_counts[level] = risk_counts.get(level, 0) + 1
        
        md += "## 风险概览\n\n"
        for level in ["critical", "high", "medium", "low", "safe"]:
            md += f"- **{level}**: {risk_counts.get(level, 0)}\n"
        md += "\n---\n\n"
        
        # 详细列表
        md += "## 详细报告\n\n"
        for i, (addr, data) in enumerate(sorted_results, 1):
            if not isinstance(data, dict):
                continue
            
            contract = data.get("contract", {})
            risks = data.get("risks", [])
            honeypot = data.get("honeypot", {})
            
            md += f"### {i}. {contract.get('symbol', 'Unknown')} `{addr[:10]}...{addr[-8:]}`\n\n"
            md += f"- **风险等级**: {data.get('risk_level', 'unknown').upper()} "
            md += f"(分数: {data.get('risk_score', 0)}/100)\n"
            md += f"- **合约名称**: {contract.get('name', 'Unknown')}\n"
            md += f"- **是否验证**: {'是' if contract.get('is_verified') else '否'}\n"
            md += f"- **蜜罐风险**: {'是 ⚠️' if honeypot.get('is_honeypot') else '否'} "
            md += f"(置信度: {honeypot.get('confidence', 0)}%)\n"
            md += f"- **持有者**: {data.get('holders_count', 'N/A')}\n\n"
            
            if risks:
                md += "**主要风险项**:\n\n"
                critical_risks = [r for r in risks if r.get("severity") == "critical"]
                high_risks = [r for r in risks if r.get("severity") == "high"]
                other_risks = [r for r in risks if r.get("severity") not in ["critical", "high"]]
                
                for r in critical_risks[:3]:
                    md += f"- 🔴 **{r['category']}**: {r['description']}\n"
                for r in high_risks[:5]:
                    md += f"- 🟠 **{r['category']}**: {r['description']}\n"
                if len(other_risks) > 0:
                    md += f"- ... 还有 {len(other_risks)} 项中低风险\n"
            
            md += "\n---\n\n"
    
    else:
        # 单个扫描结果
        contract = scan_data.get("contract", {})
        md = f"# 合约安全扫描报告: {contract.get('symbol', 'Unknown')}\n\n"
        md += f"- **链**: {contract.get('chain', 'unknown')}\n"
        md += f"- **地址**: `{contract.get('address', '')}`\n"
        md += f"- **风险等级**: {scan_data.get('risk_level', 'unknown').upper()} "
        md += f"(分数: {scan_data.get('risk_score', 0)}/100)\n"
        md += f"- **蜜罐风险**: {'是 ⚠️' if scan_data.get('honeypot', {}).get('is_honeypot') else '否'}\n\n"
        
        md += "## 风险明细\n\n"
        for r in scan_data.get("risks", []):
            severity_emoji = {
                "critical": "🔴", "high": "🟠", "medium": "🟡", 
                "low": "🔵", "info": "⚪"
            }.get(r.get("severity", ""), "⚪")
            md += f"- {severity_emoji} **{r['category']}** - {r['description']}\n"
            if r.get("evidence"):
                md += f"  - 证据: {r['evidence']}\n"
    
    return md


# ============================================================
# 主程序 - 命令行调用
# ============================================================

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("用法: python scanner_v50.py <address> [chain]")
        print("示例: python scanner_v50.py TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t tron")
        sys.exit(1)
    
    address = sys.argv[1]
    chain = sys.argv[2] if len(sys.argv) > 2 else "tron"
    
    try:
        result = scan(address, chain)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    except Exception as e:
        print(f"错误: {e}")
        sys.exit(1)
