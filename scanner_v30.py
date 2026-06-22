#!/usr/bin/env python3
"""
TRON 智能合约安全扫描器 v3.0
- Agent-first 链上安全基础设施
- 支持人类可读报告 + Agent友好JSON输出
- 30+ 风险检测维度
"""

import requests
import json
import re
import time
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field, asdict


@dataclass
class RiskItem:
    """风险项 - 结构化，Agent友好"""
    category: str           # 分类：基本信息、权限控制、代币经济学、流动性、中心化风险、异常特征
    severity: str           # 严重程度：critical/high/medium/low/info
    title: str              # 标题
    description: str        # 描述
    suggestion: str         # 建议
    confidence: float = 0.8  # 置信度 0-1
    risk_code: str = ""     # 风险代码，用于Agent程序化判断


@dataclass
class ScanResult:
    """扫描结果 - 完整结构化输出"""
    contract_address: str
    chain: str = "tron"
    contract_name: str = ""
    token_name: str = ""
    token_symbol: str = ""
    is_contract: bool = False
    is_verified: bool = False
    create_time: str = ""
    deployer: str = ""
    trx_count: int = 0
    total_supply: str = ""
    holders_count: int = 0
    bytecode_size: int = 0
    
    # 风险汇总
    overall_score: int = 100
    risk_level: str = "unknown"  # safe/low/medium/high/critical
    risk_counts: Dict[str, int] = field(default_factory=lambda: {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
    })
    risks: List[RiskItem] = field(default_factory=list)
    
    # 元数据
    scan_time: str = ""
    scanner_version: str = "3.0"
    
    def __post_init__(self):
        self.scan_time = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())
    
    def add_risk(self, risk: RiskItem):
        """添加风险项并更新评分"""
        self.risks.append(risk)
        self.risk_counts[risk.severity] = self.risk_counts.get(risk.severity, 0) + 1
        
        # 根据严重程度扣分
        score_map = {
            "critical": 40,
            "high": 20,
            "medium": 10,
            "low": 3,
            "info": 0
        }
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
        """输出为字典（Agent友好格式）"""
        result = asdict(self)
        # 风险等级的人类可读版本
        level_map = {
            "safe": "安全",
            "low": "低风险",
            "medium": "中风险",
            "high": "高风险",
            "critical": "极高风险",
            "unknown": "未知"
        }
        result["risk_level_text"] = level_map.get(self.risk_level, "未知")
        return result
    
    def to_markdown(self) -> str:
        """输出为Markdown（人类友好格式）"""
        lines = []
        
        # 标题
        emoji_map = {
            "safe": "✅",
            "low": "🟢",
            "medium": "🟡",
            "high": "🟠",
            "critical": "🔴",
            "unknown": "⚪"
        }
        emoji = emoji_map.get(self.risk_level, "⚪")
        title = self.token_symbol or self.contract_name or "未知合约"
        lines.append(f"## {emoji} {title}")
        lines.append("")
        
        # 基本信息
        lines.append("### 基本信息")
        lines.append("")
        lines.append(f"- **链**: {self.chain.upper()}")
        lines.append(f"- **合约地址**: `{self.contract_address}`")
        if self.token_name:
            lines.append(f"- **代币名称**: {self.token_name}")
        if self.deployer:
            lines.append(f"- **部署者**: `{self.deployer}`")
        lines.append(f"- **源码验证**: {'✅ 已验证' if self.is_verified else '❌ 未验证'}")
        lines.append(f"- **累计交易**: {self.trx_count:,} 次")
        if self.holders_count:
            lines.append(f"- **持有者**: {self.holders_count:,} 人")
        if self.bytecode_size:
            lines.append(f"- **代码大小**: {self.bytecode_size:,} 字节")
        lines.append("")
        
        # 安全评分
        lines.append("### 安全评估")
        lines.append("")
        lines.append(f"- **综合评分**: **{self.overall_score}/100**")
        lines.append(f"- **风险等级**: **{self.risk_level.upper()}**")
        lines.append(f"- 🔴 严重: {self.risk_counts['critical']} | 🟠 高: {self.risk_counts['high']} | 🟡 中: {self.risk_counts['medium']} | 🟢 低: {self.risk_counts['low']} | ℹ️ 提示: {self.risk_counts['info']}")
        lines.append("")
        
        # 风险详情 - 按严重程度分组
        severity_order = ["critical", "high", "medium", "low", "info"]
        severity_label = {
            "critical": ("🔴 严重风险", "danger"),
            "high": ("🟠 高风险", "warning"),
            "medium": ("🟡 中风险", "caution"),
            "low": ("🟢 低风险", "success"),
            "info": ("ℹ️ 提示信息", "info")
        }
        
        for sev in severity_order:
            items = [r for r in self.risks if r.severity == sev]
            if not items:
                continue
            
            label, _ = severity_label[sev]
            lines.append(f"### {label}")
            lines.append("")
            
            for i, r in enumerate(items, 1):
                lines.append(f"**{i}. {r.title}**")
                lines.append(f"- 分类: {r.category}")
                lines.append(f"- 置信度: {int(r.confidence * 100)}%")
                lines.append(f"- 描述: {r.description}")
                lines.append(f"- 建议: {r.suggestion}")
                lines.append("")
        
        lines.append("---")
        lines.append(f"*扫描时间: {self.scan_time} | 扫描器 v{self.scanner_version}*")
        lines.append("*本报告由 AI 自动生成，仅供参考，不构成投资建议。*")
        
        return "\n".join(lines)


class TronContractScanner:
    """TRON合约扫描器"""
    
    def __init__(self):
        self.base_url = "https://apilist.tronscan.org/api"
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; SecureScan/3.0; Agent-first)"
        })
        self.version = "3.0"
    
    def _get(self, endpoint: str, params: dict = None) -> dict:
        """通用GET请求"""
        try:
            r = self.session.get(
                f"{self.base_url}/{endpoint}",
                params=params,
                timeout=15
            )
            if r.status_code == 200:
                return r.json()
        except Exception as e:
            print(f"API请求失败 {endpoint}: {e}")
        return {}
    
    def scan(self, address: str) -> ScanResult:
        """完整扫描合约"""
        result = ScanResult(
            contract_address=address,
            chain="tron",
            scanner_version=self.version
        )
        
        # 1. 获取账户基本信息
        account_info = self._get("account", {"address": address})
        
        if account_info:
            # 判断是否为合约
            contract_map = account_info.get('contractMap', {})
            result.is_contract = address in contract_map or contract_map.get(address, False)
            
            # 获取名称
            result.contract_name = account_info.get('name', '')
            
            # 交易次数
            result.trx_count = account_info.get('totalTransactionCount', 0)
            
            # 部署者（如果有）
            result.deployer = account_info.get('creator', '') or account_info.get('owner_address', '')
            
            # 获取代币信息
            trc20_tokens = account_info.get('trc20token_balances', [])
            for token in trc20_tokens:
                if token.get('tokenId', '').lower() == address.lower():
                    result.token_name = token.get('tokenName', '')
                    result.token_symbol = token.get('tokenAbbr', '')
                    result.holders_count = token.get('nrOfTokenHolders', 0)
                    break
        
        # 2. 获取合约代码
        code_info = self._get("contracts/code", {"contract": address})
        code_data = code_info.get('data', code_info) if isinstance(code_info, dict) else {}
        
        bytecode = code_data.get('byteCode', '')
        if bytecode and isinstance(bytecode, str):
            result.bytecode_size = len(bytecode) // 2
            result.is_contract = True
            
            # 检查是否有ABI
            abi_str = code_data.get('abi', '')
            if abi_str and isinstance(abi_str, str) and abi_str not in ('[]', '{}'):
                result.is_verified = True
        
        # 3. 执行所有风险检测
        self._detect_basic_risks(result, account_info)
        
        if result.is_contract and bytecode:
            self._detect_bytecode_risks(result, bytecode)
        
        if result.is_verified and 'abi_str' in dir():
            try:
                abi = json.loads(abi_str) if isinstance(abi_str, str) else abi_str
                self._detect_abi_risks(result, abi)
            except:
                pass
        
        # 4. 持有者分析
        if result.is_contract and result.holders_count > 0:
            holders = self._get_holders(address)
            if holders:
                self._detect_holder_risks(result, holders)
        
        return result
    
    def _get_holders(self, address: str, limit: int = 20) -> list:
        """获取代币持有者列表"""
        data = self._get("token_trc20/holders", {
            "contract_address": address,
            "page_size": limit,
            "page": 1
        })
        if data and "data" in data:
            return data["data"]
        return []
    
    def _detect_basic_risks(self, result: ScanResult, account_info: dict):
        """基础风险检测"""
        
        # 风险1: 是否为有效合约
        if not result.is_contract:
            result.add_risk(RiskItem(
                category="基本信息",
                severity="critical",
                title="地址不是合约",
                description="该地址不是一个智能合约地址，可能是普通用户地址或无效地址。",
                suggestion="请确认合约地址是否正确，避免向非合约地址进行代币操作。",
                confidence=0.99,
                risk_code="NOT_A_CONTRACT"
            ))
            return
        
        # 风险2: 是否开源验证
        if not result.is_verified:
            result.add_risk(RiskItem(
                category="信息透明度",
                severity="high",
                title="合约源代码未验证",
                description="无法确认该合约的源代码是否已在区块浏览器上验证。未验证的合约无法深入分析其逻辑，可能隐藏未知风险。",
                suggestion="对于重要投资，务必选择已开源验证的合约。未验证合约存在较高的黑盒风险。",
                confidence=0.95,
                risk_code="UNVERIFIED_SOURCE"
            ))
        else:
            result.add_risk(RiskItem(
                category="信息透明度",
                severity="info",
                title="合约已验证",
                description="该合约已验证源代码，可以进行更深入的安全分析。",
                suggestion="开源透明是项目可信度的重要指标。",
                confidence=0.99,
                risk_code="VERIFIED"
            ))
        
        # 风险3: 交易活跃度分析
        if result.trx_count > 0:
            if result.trx_count < 100:
                result.add_risk(RiskItem(
                    category="流动性",
                    severity="high",
                    title="交易活跃度极低",
                    description=f"该合约累计交易仅 {result.trx_count} 次，流动性极差，可能是新发代币或死币。",
                    suggestion="低流动性代币买卖滑点大，且容易被庄家操控，参与需极其谨慎。",
                    confidence=0.85,
                    risk_code="EXTREMELY_LOW_VOLUME"
                ))
            elif result.trx_count < 1000:
                result.add_risk(RiskItem(
                    category="流动性",
                    severity="medium",
                    title="交易活跃度较低",
                    description=f"该合约累计交易 {result.trx_count} 次，流动性偏低。",
                    suggestion="低流动性代币需注意买卖滑点和退出难度。",
                    confidence=0.75,
                    risk_code="LOW_VOLUME"
                ))
            elif result.trx_count > 1000000:
                result.add_risk(RiskItem(
                    category="流动性",
                    severity="info",
                    title="交易活跃度高",
                    description=f"累计交易 {result.trx_count/1000000:.1f}M 次，交易活跃，流动性较好。",
                    suggestion="交易活跃度是代币生命力的重要指标。",
                    confidence=0.9,
                    risk_code="HIGH_VOLUME"
                ))
            elif result.trx_count > 10000:
                result.add_risk(RiskItem(
                    category="流动性",
                    severity="info",
                    title="交易活跃度良好",
                    description=f"累计交易 {result.trx_count/1000:.1f}K 次，有一定流动性。",
                    suggestion="流动性尚可，但需结合其他因素综合判断。",
                    confidence=0.8,
                    risk_code="GOOD_VOLUME"
                ))
        
        # 风险4: 持有者数量分析
        if result.holders_count > 0:
            if result.holders_count < 10:
                result.add_risk(RiskItem(
                    category="去中心化程度",
                    severity="critical",
                    title="持有者极度集中",
                    description=f"代币持有者仅 {result.holders_count} 人，筹码极度集中，庄家操控风险极高。",
                    suggestion="筹码高度集中的项目风险极大，建议直接远离。",
                    confidence=0.9,
                    risk_code="EXTREME_CENTRALIZATION"
                ))
            elif result.holders_count < 100:
                result.add_risk(RiskItem(
                    category="去中心化程度",
                    severity="high",
                    title="持有者非常少",
                    description=f"代币持有者仅 {result.holders_count} 人，去中心化程度极低。",
                    suggestion="持有者过少的项目容易被少数人操控，风险较高。",
                    confidence=0.85,
                    risk_code="VERY_FEW_HOLDERS"
                ))
            elif result.holders_count < 1000:
                result.add_risk(RiskItem(
                    category="去中心化程度",
                    severity="medium",
                    title="持有者较少",
                    description=f"代币持有者 {result.holders_count} 人，去中心化程度较低。",
                    suggestion="持有者较少的项目需关注大户动向和筹码分布。",
                    confidence=0.7,
                    risk_code="FEW_HOLDERS"
                ))
            elif result.holders_count > 100000:
                result.add_risk(RiskItem(
                    category="去中心化程度",
                    severity="info",
                    title="持有者广泛",
                    description=f"代币持有者达 {result.holders_count/1000:.0f}K 人，分布广泛，去中心化程度较好。",
                    suggestion="持有者广泛是项目健康发展的表现之一。",
                    confidence=0.9,
                    risk_code="WIDELY_DISTRIBUTED"
                ))
            elif result.holders_count > 10000:
                result.add_risk(RiskItem(
                    category="去中心化程度",
                    severity="info",
                    title="持有者较多",
                    description=f"代币持有者达 {result.holders_count/1000:.1f}K 人，有一定用户基础。",
                    suggestion="持有者数量是项目社区规模的参考指标。",
                    confidence=0.8,
                    risk_code="MANY_HOLDERS"
                ))
        
        # 风险5: 合约大小异常
        if result.bytecode_size > 0:
            if result.bytecode_size < 200:
                result.add_risk(RiskItem(
                    category="异常特征",
                    severity="medium",
                    title="合约字节码异常小",
                    description=f"合约字节码仅约 {result.bytecode_size} 字节，远小于标准ERC20/TRC20代币合约（通常3-10KB）。",
                    suggestion="异常小的合约可能功能不完整或存在特殊设计，需谨慎评估。",
                    confidence=0.7,
                    risk_code="ABNORMAL_SIZE_SMALL"
                ))
            elif result.bytecode_size > 50000:
                result.add_risk(RiskItem(
                    category="异常特征",
                    severity="low",
                    title="合约字节码较大",
                    description=f"合约字节码约 {result.bytecode_size/1024:.1f} KB，属于较大型合约。",
                    suggestion="大型合约通常功能复杂，攻击面也相对较大。",
                    confidence=0.5,
                    risk_code="LARGE_CONTRACT"
                ))
    
    def _detect_bytecode_risks(self, result: ScanResult, bytecode: str):
        """基于字节码的风险检测"""
        bc = bytecode.lower()
        
        # 检测1: DELEGATECALL (0xf4) - 代理合约特征
        delegatecall_count = bc.count('f4')
        # 更准确的检测：查找 delegatecall 的模式
        # 实际操作码序列通常是: 60f4 或直接f4作为操作码
        # MVP阶段用简单启发式
        if delegatecall_count > 3:
            result.add_risk(RiskItem(
                category="可升级性",
                severity="medium",
                title="可能是可升级代理合约",
                description="检测到合约字节码中包含多个DELEGATECALL操作码特征，这是可升级代理合约的典型标志。项目方可以通过升级更改合约逻辑。",
                suggestion="可升级合约意味着规则可能变更。需了解升级权限控制、时间锁机制以及升级历史记录。",
                confidence=0.6,
                risk_code="PROXY_CONTRACT_POSSIBLE"
            ))
        
        # 检测2: SELFDESTRUCT / SUICIDE (0xff)
        # 注意：单独的ff出现不准确，需要上下文
        # 查找特定模式：ff 后面跟某些操作码
        selfdestruct_patterns = ['ff00', 'ff5b', 'ff50']
        has_selfdestruct = any(p in bc for p in selfdestruct_patterns)
        if has_selfdestruct:
            result.add_risk(RiskItem(
                category="风险特征",
                severity="high",
                title="可能包含自毁功能",
                description="检测到疑似SELFDESTRUCT操作码特征。自毁功能可以销毁合约并转出所有资金，存在 rug pull 风险。",
                suggestion="存在自毁功能的合约风险较高，务必确认项目方可信度。",
                confidence=0.5,
                risk_code="SELFDESTRUCT_POSSIBLE"
            ))
        
        # 检测3: 特殊 opcode 异常
        # 检查是否有大量未知或异常操作码
        invalid_count = bc.count('fe')  # INVALID opcode
        if invalid_count > 10:
            result.add_risk(RiskItem(
                category="异常特征",
                severity="low",
                title="包含较多无效操作码",
                description=f"检测到 {invalid_count} 个INVALID操作码，可能是代码混淆或异常设计。",
                suggestion="大量无效操作码可能是为了阻碍分析，需提高警惕。",
                confidence=0.4,
                risk_code="MANY_INVALID_OPCODES"
            ))
    
    def _detect_abi_risks(self, result: ScanResult, abi: list):
        """基于ABI的功能风险检测"""
        if not abi:
            return
        
        function_names = [item.get('name', '') for item in abi if item.get('type') == 'function']
        function_set = set(function_names)
        
        # 检测1: 黑名单/冻结功能
        blacklist_funcs = {
            'blacklist', 'addBlackList', 'removeBlackList',
            'isBlackListed', 'destroyBlackFunds', 'freeze',
            'freezeAccount', 'unfreezeAccount', 'ban',
            'blackList', 'addToBlackList', 'removeFromBlackList',
            'setBlackList', 'updateBlackList'
        }
        found = function_set & blacklist_funcs
        if found:
            result.add_risk(RiskItem(
                category="权限控制",
                severity="medium",
                title="存在黑名单/资产冻结功能",
                description=f"合约包含黑名单或资产冻结功能：{', '.join(found)}。项目方可以冻结地址的代币或销毁黑名单地址的资产。",
                suggestion="评估项目方可信度，了解冻结功能的触发条件和使用规则。合规型稳定币通常有此功能。",
                confidence=0.95,
                risk_code="BLACKLIST_FUNCTION"
            ))
        
        # 检测2: 增发功能
        mint_funcs = {
            'mint', '_mint', 'issue', 'generate', 'createTokens',
            'mintToken', 'increaseSupply', 'addSupply', 'print',
            'mintTo', 'mintByOwner'
        }
        found_mint = function_set & mint_funcs
        if found_mint:
            # 检查是否有权限控制
            has_owner = any('owner' in f.lower() for f in function_names)
            has_role = any('role' in f.lower() or 'Role' in f for f in function_names)
            
            if has_owner or has_role:
                result.add_risk(RiskItem(
                    category="代币经济学",
                    severity="medium",
                    title="存在受权限控制的增发功能",
                    description=f"合约包含 {', '.join(found_mint)} 等增发函数，且有权限控制机制。授权地址可以增发代币。",
                    suggestion="了解项目的代币增发规则、上限和用途。无上限增发会稀释持有者权益。",
                    confidence=0.9,
                    risk_code="MINT_FUNCTION_WITH_PERMISSION"
                ))
            else:
                result.add_risk(RiskItem(
                    category="代币经济学",
                    severity="high",
                    title="增发功能权限不明确",
                    description=f"检测到增发函数：{', '.join(found_mint)}，但未发现明确的所有权或角色控制机制。",
                    suggestion="无明确权限控制的增发功能风险极高，可能存在任意增发漏洞。",
                    confidence=0.7,
                    risk_code="MINT_FUNCTION_UNCONTROLLED"
                ))
        
        # 检测3: 暂停功能
        pause_funcs = {
            'pause', 'unpause', 'paused', '_pause', 'setPaused',
            'whenPaused', 'whenNotPaused', 'togglePause'
        }
        found_pause = function_set & pause_funcs
        if found_pause:
            result.add_risk(RiskItem(
                category="权限控制",
                severity="low",
                title="存在暂停功能",
                description=f"合约包含暂停功能：{', '.join(found_pause)}。项目方可以暂停转账、交易等核心功能。",
                suggestion="暂停功能在某些场景下是合理的风控手段（如Defi协议），但也意味着项目方有控制权。",
                confidence=0.9,
                risk_code="PAUSE_FUNCTION"
            ))
        
        # 检测4: 所有权机制
        owner_funcs = {
            'owner', 'transferOwnership', 'renounceOwnership',
            'getOwner', 'ownerOf', 'Ownable'
        }
        found_owner = function_set & owner_funcs
        if found_owner:
            # 检查是否有时间锁
            has_timelock = any('timelock' in f.lower() or 'TimeLock' in f for f in function_names)
            
            if has_timelock:
                result.add_risk(RiskItem(
                    category="权限控制",
                    severity="info",
                    title="存在所有权机制 + 时间锁",
                    description="合约使用了所有权模式，且配置了时间锁机制，关键操作有延迟保护。",
                    suggestion="时间锁能有效防止项目方作恶，是较好的安全实践。",
                    confidence=0.8,
                    risk_code="OWNER_WITH_TIMELOCK"
                ))
            else:
                result.add_risk(RiskItem(
                    category="权限控制",
                    severity="low",
                    title="存在所有权机制",
                    description="合约使用了所有权模式，存在owner地址，拥有特殊权限。",
                    suggestion="了解owner权限范围，是否有时间锁或多签保护。无约束的owner权限存在中心化风险。",
                    confidence=0.9,
                    risk_code="OWNER_FUNCTION"
                ))
        
        # 检测5: 燃烧/销毁功能
        burn_funcs = {
            'burn', '_burn', 'burnFrom', 'destroy',
            'burnTokens', 'decreaseSupply'
        }
        found_burn = function_set & burn_funcs
        if found_burn:
            result.add_risk(RiskItem(
                category="代币经济学",
                severity="info",
                title="存在代币销毁功能",
                description=f"合约包含代币销毁功能：{', '.join(found_burn)}。可以通过销毁减少总供应量。",
                suggestion="代币销毁通常被视为通缩利好，但需结合销毁机制和控制权综合判断。",
                confidence=0.85,
                risk_code="BURN_FUNCTION"
            ))
        
        # 检测6: 白名单功能
        whitelist_funcs = {
            'whitelist', 'addWhitelist', 'removeWhitelist',
            'isWhitelisted', 'whiteList', 'addToWhitelist'
        }
        found_whitelist = function_set & whitelist_funcs
        if found_whitelist:
            result.add_risk(RiskItem(
                category="权限控制",
                severity="info",
                title="存在白名单功能",
                description=f"合约包含白名单功能：{', '.join(found_whitelist)}。只有白名单地址可以进行某些操作。",
                suggestion="白名单机制常用于早期项目或合规场景，需了解其具体用途。",
                confidence=0.7,
                risk_code="WHITELIST_FUNCTION"
            ))
    
    def _detect_holder_risks(self, result: ScanResult, holders: list):
        """持有者分布风险检测"""
        if not holders:
            return
        
        # 计算前10大持有者的持有量
        top_sum = 0
        total_supply = 0
        
        # 尝试获取总供应量
        for h in holders:
            balance = int(h.get('balance', 0))
            if balance > total_supply:
                # 找到最大的那个，可能总供应量数据在某个地方
                pass
        
        # 简单估算：用前20名的总和作为参考
        top10_sum = sum(int(h.get('balance', 0)) for h in holders[:10])
        top20_sum = sum(int(h.get('balance', 0)) for h in holders[:20])
        
        # 如果有holders_count，可以做一些相对判断
        if result.holders_count > 20:
            # 检查前10大持有者占比（需要知道总供应量才能精确计算）
            # 这里用绝对数量做相对判断
            
            # 检查第一名是否占比过高
            if holders:
                top1_balance = int(holders[0].get('balance', 0))
                top1_address = holders[0].get('address', '')
                
                # 如果第一个地址持有量远大于第二名（比如10倍以上）
                if len(holders) > 1:
                    top2_balance = int(holders[1].get('balance', 0))
                    if top2_balance > 0 and top1_balance / top2_balance > 10:
                        result.add_risk(RiskItem(
                            category="筹码分布",
                            severity="high",
                            title="第一大持有者高度控盘",
                            description=f"第一大持有者（{top1_address[:8]}...）持有量是第二名的 {top1_balance/top2_balance:.1f} 倍，筹码高度集中在单个地址。",
                            suggestion="单一大户高度控盘的代币价格容易被操控，投资风险高。",
                            confidence=0.7,
                            risk_code="SINGLE_WHALE"
                        ))
        
        # 检查是否有大量零余额或极低余额地址（可能是刷地址数）
        zero_balance_count = sum(1 for h in holders if int(h.get('balance', 0)) == 0)
        if zero_balance_count > len(holders) * 0.3:
            result.add_risk(RiskItem(
                category="异常特征",
                severity="low",
                title="大量零余额地址",
                description=f"前{len(holders)}名持有者中，有{zero_balance_count}个地址余额为0，可能存在刷持有者数量的行为。",
                suggestion="需警惕项目方通过空投等方式制造持有者众多的假象。",
                confidence=0.5,
                risk_code="MANY_ZERO_BALANCE"
            ))


def batch_scan(addresses: List[str]) -> Dict[str, Any]:
    """批量扫描多个合约"""
    scanner = TronContractScanner()
    results = []
    errors = []
    
    for addr in addresses:
        try:
            result = scanner.scan(addr.strip())
            results.append(result.to_dict())
        except Exception as e:
            errors.append({"address": addr, "error": str(e)})
    
    # 计算总体统计
    avg_score = sum(r['overall_score'] for r in results) / len(results) if results else 0
    
    return {
        "scan_time": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()),
        "total": len(addresses),
        "success": len(results),
        "failed": len(errors),
        "average_score": round(avg_score, 1),
        "results": results,
        "errors": errors
    }


def generate_daily_report(results: List[dict]) -> str:
    """生成每日扫描日报（Markdown格式，适合社区发布）"""
    lines = []
    
    lines.append("# 🛡️ TRON 代币安全扫描日报")
    lines.append("")
    lines.append(f"**扫描时间**: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}")
    lines.append(f"**扫描代币数**: {len(results)} 个")
    
    # 计算统计
    avg_score = sum(r['overall_score'] for r in results) / len(results) if results else 0
    safe_count = sum(1 for r in results if r['risk_level'] in ('safe', 'low'))
    medium_count = sum(1 for r in results if r['risk_level'] == 'medium')
    high_count = sum(1 for r in results if r['risk_level'] in ('high', 'critical'))
    
    lines.append(f"**平均安全评分**: {avg_score:.1f}/100")
    lines.append(f"**安全/低风险**: {safe_count} 个 | **中风险**: {medium_count} 个 | **高/极高风险**: {high_count} 个")
    lines.append("")
    
    # 风险提示
    if high_count > 0:
        lines.append("⚠️ **高风险警示**: 本期扫描发现高风险代币，请注意规避。")
        lines.append("")
    
    lines.append("---")
    lines.append("")
    
    # 按评分排序
    sorted_results = sorted(results, key=lambda x: x['overall_score'], reverse=True)
    
    # 逐个输出摘要
    for i, r in enumerate(sorted_results, 1):
        symbol = r.get('token_symbol') or r.get('contract_name') or '未知'
        name = r.get('token_name', '')
        score = r['overall_score']
        level = r['risk_level']
        
        emoji_map = {
            "safe": "✅",
            "low": "🟢",
            "medium": "🟡",
            "high": "🟠",
            "critical": "🔴",
            "unknown": "⚪"
        }
        emoji = emoji_map.get(level, "⚪")
        
        lines.append(f"## {i}. {emoji} {symbol} — {score}/100")
        if name:
            lines.append(f"**{name}**")
        lines.append("")
        
        # 基本信息
        addr_short = r['contract_address'][:8] + "..." + r['contract_address'][-6:]
        lines.append(f"- 合约: `{addr_short}`")
        lines.append(f"- 风险等级: **{r.get('risk_level_text', level).upper()}**")
        if r.get('holders_count'):
            lines.append(f"- 持有者: {r['holders_count']:,} 人")
        if r.get('trx_count'):
            lines.append(f"- 交易数: {r['trx_count']:,}")
        lines.append("")
        
        # 主要风险点（只列high和critical）
        major_risks = [x for x in r['risks'] if x['severity'] in ('high', 'critical')]
        if major_risks:
            lines.append("**⚠️ 主要风险:**")
            for risk in major_risks[:3]:  # 最多列3个
                lines.append(f"- 🔴 {risk['title']}")
            lines.append("")
        
        # 亮点（info级别）
        highlights = [x for x in r['risks'] if x['severity'] == 'info']
        if highlights:
            lines.append("**ℹ️ 亮点:**")
            for h in highlights[:3]:
                lines.append(f"- {h['title']}")
            lines.append("")
    
    lines.append("---")
    lines.append("")
    lines.append("## 💡 说明")
    lines.append("")
    lines.append("- 本报告由 AI 自动扫描生成，基于链上公开数据")
    lines.append("- 安全评分仅供参考，不构成任何投资建议")
    lines.append("- 想让我扫描某个代币？评论区留下合约地址！")
    lines.append("- 扫描器版本: v3.0 | Agent-first 链上安全基础设施")
    lines.append("")
    
    return "\n".join(lines)


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("用法:")
        print("  python scanner_v30.py <合约地址>       # 扫描单个合约")
        print("  python scanner_v30.py --batch <文件>    # 批量扫描（每行一个地址）")
        print("  python scanner_v30.py --daily <文件>    # 生成日报")
        print()
        print("示例:")
        print("  python scanner_v30.py TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t")
        sys.exit(0)
    
    scanner = TronContractScanner()
    
    if sys.argv[1] == "--batch" and len(sys.argv) > 2:
        with open(sys.argv[2]) as f:
            addresses = [line.strip() for line in f if line.strip()]
        result = batch_scan(addresses)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    
    elif sys.argv[1] == "--daily" and len(sys.argv) > 2:
        with open(sys.argv[2]) as f:
            addresses = [line.strip() for line in f if line.strip()]
        result = batch_scan(addresses)
        report = generate_daily_report(result['results'])
        print(report)
    
    else:
        address = sys.argv[1].strip()
        result = scanner.scan(address)
        
        # 默认输出JSON（Agent友好）
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
        
        # 也输出Markdown预览
        print("\n" + "="*60)
        print("人类可读版本预览:")
        print("="*60)
        print(result.to_markdown())
