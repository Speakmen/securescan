#!/usr/bin/env python3
"""
TRON 智能合约安全扫描器 v2.0
- 基于链上数据和bytecode分析，无需源码
- 支持10+项风险检测
- 输出结构化风险报告
"""

import requests
import json
import re
import time
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field


@dataclass
class RiskItem:
    """风险项"""
    category: str  # 风险类别
    severity: str  # 严重程度: high/medium/low/info
    title: str     # 风险标题
    description: str  # 详细描述
    suggestion: str   # 修复建议


@dataclass
class ScanResult:
    """扫描结果"""
    contract_address: str
    contract_name: str = ""
    compiler_version: str = ""
    is_verified: bool = False
    create_time: str = ""
    trx_count: int = 0
    creator_address: str = ""
    token_name: str = ""
    token_symbol: str = ""
    total_supply: str = ""
    holders_count: int = 0
    risks: List[RiskItem] = field(default_factory=list)
    overall_score: int = 100  # 安全分数，100满分

    @property
    def risk_level(self) -> str:
        if self.overall_score >= 80:
            return "低风险 ✅"
        elif self.overall_score >= 60:
            return "中风险 ⚠️"
        elif self.overall_score >= 40:
            return "高风险 🚨"
        else:
            return "极高风险 💀"

    def add_risk(self, risk: RiskItem):
        self.risks.append(risk)
        score_map = {"high": 20, "medium": 10, "low": 3, "info": 0}
        self.overall_score -= score_map.get(risk.severity, 0)
        if self.overall_score < 0:
            self.overall_score = 0


class TronContractScanner:
    """TRON合约扫描器"""

    def __init__(self):
        self.base_url = "https://apilist.tronscan.org/api"
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; TRON-Scanner/2.0)"
        })

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

    def get_contract_info(self, address: str) -> dict:
        """获取合约基本信息"""
        data = self._get("contracts", {"contract": address})
        if data and "data" in data and data["data"]:
            # 精确匹配地址
            for item in data["data"]:
                if item.get('address', '').lower() == address.lower():
                    return item
            # 没有精确匹配时返回第一个
            return data["data"][0]
        return {}

    def get_contract_code(self, address: str) -> dict:
        """获取合约字节码和ABI"""
        data = self._get("contracts/code", {"contract": address})
        if data and "data" in data:
            return data["data"]
        return {}

    def get_account_info(self, address: str) -> dict:
        """获取账户信息"""
        return self._get("account", {"address": address})

    def get_holders_info(self, address: str) -> dict:
        """获取代币持有者信息"""
        data = self._get("token_trc20/holders", {
            "contract_address": address,
            "page_size": 10,
            "page": 1
        })
        return data

    def scan(self, address: str) -> ScanResult:
        """完整扫描合约"""
        result = ScanResult(contract_address=address)

        # 1. 获取基本信息
        contract_info = self.get_contract_info(address)
        if contract_info:
            result.contract_name = contract_info.get('name', 'Unknown')
            result.compiler_version = contract_info.get('compile_version', 'Unknown')
            result.is_verified = contract_info.get('verify_status', 0) in (1, 2)
            result.trx_count = contract_info.get('trxCount', 0)
            result.creator_address = contract_info.get('creator', {}).get('address', '')
            
            # 创建时间
            date_created = contract_info.get('date_created', 0)
            if date_created:
                result.create_time = time.strftime(
                    '%Y-%m-%d %H:%M:%S',
                    time.localtime(date_created / 1000)
                )

            # 代币信息
            token_info = contract_info.get('trc20token', {})
            if token_info:
                result.token_name = token_info.get('name', '')
                result.token_symbol = token_info.get('symbol', '')
                result.total_supply = token_info.get('total_supply', '')
                result.holders_count = int(token_info.get('holders_count', 0))

        # 2. 基础风险检测
        self._scan_basic_risks(result, contract_info)

        # 3. 获取字节码，做深度检测
        code_info = self.get_contract_code(address)
        bytecode = code_info.get('byteCode', '')
        abi_str = code_info.get('abi', '')
        
        if bytecode:
            self._scan_bytecode_risks(result, bytecode)
        
        if abi_str:
            try:
                abi = json.loads(abi_str) if isinstance(abi_str, str) else abi_str
                self._scan_abi_risks(result, abi)
            except:
                pass

        # 4. 持有者分析
        if result.holders_count > 0:
            self._scan_holders_risks(result, address)

        return result

    def _scan_basic_risks(self, result: ScanResult, contract_info: dict):
        """基础风险检测"""

        # 风险1: 合约是否开源验证
        if not result.is_verified:
            result.add_risk(RiskItem(
                category="信息透明度",
                severity="high",
                title="合约源代码未验证",
                description="该合约未在Tronscan上验证源代码，无法确认合约逻辑是否安全。未验证的合约可能隐藏恶意代码（如蜜罐、后门等）。",
                suggestion="投资前务必确认合约已开源并验证，或要求项目方提供源码进行审计。"
            ))
        else:
            result.add_risk(RiskItem(
                category="信息透明度",
                severity="info",
                title="合约已验证源代码",
                description="该合约已在Tronscan上验证源代码，可进行深度安全分析。",
                suggestion="继续保持开源透明，建议定期进行安全审计。"
            ))

        # 风险2: 合约年龄
        if result.create_time:
            try:
                create_ts = time.mktime(time.strptime(result.create_time, '%Y-%m-%d %H:%M:%S'))
                age_days = (time.time() - create_ts) / 86400
                if age_days < 1:
                    result.add_risk(RiskItem(
                        category="项目成熟度",
                        severity="high",
                        title="合约创建不足24小时",
                        description=f"该合约仅创建了约 {age_days:.1f} 小时，属于非常新的合约。新合约跑路风险极高。",
                        suggestion="谨慎参与新发行代币，建议至少观察7天以上，确认项目方有实际行动后再考虑。"
                    ))
                elif age_days < 7:
                    result.add_risk(RiskItem(
                        category="项目成熟度",
                        severity="medium",
                        title="合约创建不足7天",
                        description=f"该合约创建仅 {age_days:.0f} 天，项目尚处于早期阶段，存在较高不确定性。",
                        suggestion="建议继续观察，确认项目运营稳定后再考虑投资。"
                    ))
                elif age_days > 365:
                    result.add_risk(RiskItem(
                        category="项目成熟度",
                        severity="info",
                        title="合约运行超过1年",
                        description=f"该合约已运行 {age_days/365:.1f} 年，经过了较长时间的市场检验。",
                        suggestion="相对成熟的项目，但仍需关注其他风险因素。"
                    ))
            except:
                pass

        # 风险3: 交易活跃度
        if result.trx_count > 0:
            if result.trx_count < 100:
                result.add_risk(RiskItem(
                    category="流动性",
                    severity="medium",
                    title="交易活跃度极低",
                    description=f"该合约累计交易次数仅 {result.trx_count} 次，流动性极差，可能存在无法卖出的风险。",
                    suggestion="低流动性代币买卖滑点极大，建议远离。"
                ))
            elif result.trx_count > 1000000:
                result.add_risk(RiskItem(
                    category="流动性",
                    severity="info",
                    title="交易活跃度高",
                    description=f"该合约累计交易次数达 {result.trx_count/1000000:.1f}M 次，交易活跃，流动性较好。",
                    suggestion="交易活跃度是代币生命力的重要指标。"
                ))

        # 风险4: 持有者数量
        if result.holders_count > 0:
            if result.holders_count < 10:
                result.add_risk(RiskItem(
                    category="去中心化程度",
                    severity="high",
                    title="持有者极度集中",
                    description=f"该代币持有者仅 {result.holders_count} 人，筹码极度集中，存在庄家操控风险。",
                    suggestion="筹码高度集中的项目风险极大，建议远离。"
                ))
            elif result.holders_count < 100:
                result.add_risk(RiskItem(
                    category="去中心化程度",
                    severity="medium",
                    title="持有者较少",
                    description=f"该代币持有者仅 {result.holders_count} 人，去中心化程度较低。",
                    suggestion="建议关注持有者分布情况，避免大户砸盘风险。"
                ))

    def _scan_bytecode_risks(self, result: ScanResult, bytecode: str):
        """基于字节码的风险检测"""

        # 检测1: 自毁函数 (SELFDESTRUCT / SUICIDE)
        # 0xff = SELFDESTRUCT 操作码
        if 'ff' in bytecode.lower() and len(bytecode) > 100:
            # 更精确的检测：查找SELFDESTRUCT模式
            if re.search(r'ff.{0,4}?$', bytecode.lower()) or \
               bytecode.lower().count('ff') > 5:  # 粗略判断
                result.add_risk(RiskItem(
                    category="安全漏洞",
                    severity="medium",
                    title="可能包含自毁函数",
                    description="检测到合约字节码中可能包含SELFDESTRUCT（自毁）操作码。如果存在自毁函数且权限控制不当，可能导致合约资金被盗或合约被销毁。",
                    suggestion="如果有源码，请详细检查自毁函数的调用条件和权限控制。"
                ))

        # 检测2: 代理模式 (DELEGATECALL)
        # 0xf4 = DELEGATECALL 操作码
        delegatecall_count = bytecode.lower().count('f4')
        if delegatecall_count > 0:
            result.add_risk(RiskItem(
                category="可升级性",
                severity="medium",
                title="可能是可升级合约（代理模式）",
                description=f"检测到合约包含 DELEGATECALL 操作码（出现{delegatecall_count}次），该合约可能是可升级的代理合约。这意味着项目方可以随时更改合约逻辑，投资者权益可能发生变化。",
                suggestion="确认升级机制，是否有时间锁（Timelock）保护，升级权限归谁所有。"
            ))

        # 检测3: 合约大小异常
        code_size = len(bytecode) // 2  # 字节数
        if code_size < 200:
            result.add_risk(RiskItem(
                category="异常特征",
                severity="low",
                title="合约字节码偏小",
                description=f"合约字节码仅约 {code_size} 字节，远小于标准ERC20代币合约大小。可能是极简合约或存在异常。",
                suggestion="结合其他风险因素综合判断。"
            ))

    def _scan_abi_risks(self, result: ScanResult, abi: list):
        """基于ABI的功能检测"""

        function_names = [item.get('name', '') for item in abi if item.get('type') == 'function']
        function_set = set(function_names)

        # 检测1: 黑名单功能
        blacklist_funcs = {'blacklist', 'addBlackList', 'removeBlackList', 
                          'isBlackListed', 'destroyBlackFunds', 'freeze', 'ban'}
        found_blacklist = function_set & blacklist_funcs
        if found_blacklist:
            result.add_risk(RiskItem(
                category="权限控制",
                severity="medium",
                title="存在黑名单/冻结功能",
                description=f"合约包含黑名单或资产冻结功能：{', '.join(found_blacklist)}。项目方可以冻结任意地址的代币，影响资金流动性和自主控制权。",
                suggestion="评估项目方可信度，了解冻结功能的使用规则和限制。对于去中心化理念的项目，这是一个减分项。"
            ))

        # 检测2: 增发功能
        mint_funcs = {'mint', '_mint', 'issue', 'generate', 'createTokens'}
        found_mint = function_set & mint_funcs
        if found_mint:
            # 检查是否有权限控制
            has_owner = any('owner' in f.lower() or 'Ownable' in f for f in function_names)
            
            if has_owner:
                result.add_risk(RiskItem(
                    category="代币经济学",
                    severity="medium",
                    title="存在增发功能",
                    description=f"合约包含 {', '.join(found_mint)} 等增发函数，且存在所有者权限控制。所有者可以随时增发代币，可能导致通胀和币价下跌。",
                    suggestion="了解项目的代币经济学，确认增发是否有上限和用途，是否有时间锁保护。"
                ))
            else:
                result.add_risk(RiskItem(
                    category="代币经济学",
                    severity="high",
                    title="增发功能可能无权限限制",
                    description=f"检测到增发函数：{', '.join(found_mint)}，但未发现明确的所有权控制机制。如果任何人都可以调用增发，存在无限增发风险。",
                    suggestion="高度危险！无权限控制的增发函数是典型的骗局特征，建议立即远离。"
                ))

        # 检测3: 暂停功能
        pause_funcs = {'pause', 'unpause', 'paused', '_pause'}
        found_pause = function_set & pause_funcs
        if found_pause:
            result.add_risk(RiskItem(
                category="权限控制",
                severity="low",
                title="存在暂停功能",
                description=f"合约包含暂停功能：{', '.join(found_pause)}。项目方可以暂停合约的转账等功能。",
                suggestion="暂停功能在某些场景下是合理的（如防止黑客攻击），但也意味着项目方有绝对控制权。"
            ))

        # 检测4: 所有权相关
        owner_funcs = {'owner', 'transferOwnership', 'renounceOwnership', 'getOwner'}
        found_owner = function_set & owner_funcs
        if found_owner:
            result.add_risk(RiskItem(
                category="权限控制",
                severity="info",
                title="存在所有权机制",
                description=f"合约使用了所有权模式：{', '.join(found_owner)}。存在owner地址，拥有特殊权限。",
                suggestion="检查owner是否为多签或时间锁合约，以及owner具体拥有哪些权限。"
            ))

        # 检测5: 标准ERC20符合性
        erc20_standard = {'transfer', 'transferFrom', 'approve', 'allowance', 
                         'balanceOf', 'totalSupply', 'Transfer', 'Approval'}
        standard_count = len(function_set & erc20_standard)
        if standard_count < 5:
            result.add_risk(RiskItem(
                category="标准符合性",
                severity="low",
                title="可能不符合标准ERC20/TRC20",
                description=f"该合约仅包含 {standard_count} 个标准代币方法，可能不完全符合TRC20标准。这可能导致在某些钱包或DEX中无法正常使用。",
                suggestion="确认代币在主流钱包和交易所中是否正常工作。"
            ))

    def _scan_holders_risks(self, result: ScanResult, address: str):
        """持有者分布风险检测"""
        holders_data = self.get_holders_info(address)
        
        if not holders_data or 'data' not in holders_data:
            return

        holders = holders_data.get('data', [])
        if not holders:
            return

        # 计算前10大持有者占比
        total_supply = 0
        top10_amount = 0
        
        try:
            total_supply = int(result.total_supply) if result.total_supply.isdigit() else 0
        except:
            pass

        if total_supply > 0:
            for h in holders[:10]:
                top10_amount += int(h.get('balance', 0))
            
            top10_percent = (top10_amount / total_supply) * 100
            
            if top10_percent > 90:
                result.add_risk(RiskItem(
                    category="筹码分布",
                    severity="high",
                    title="筹码高度集中",
                    description=f"前10大持有者持有 {top10_percent:.1f}% 的代币供应量，筹码极度集中。庄家可以轻易操控价格。",
                    suggestion="筹码高度集中的项目风险极大，建议远离。"
                ))
            elif top10_percent > 70:
                result.add_risk(RiskItem(
                    category="筹码分布",
                    severity="medium",
                    title="筹码较为集中",
                    description=f"前10大持有者持有 {top10_percent:.1f}% 的代币供应量，筹码相对集中。",
                    suggestion="关注大户动向，注意砸盘风险。"
                ))
            elif top10_percent < 30:
                result.add_risk(RiskItem(
                    category="筹码分布",
                    severity="info",
                    title="筹码分布较为分散",
                    description=f"前10大持有者仅持有 {top10_percent:.1f}% 的代币供应量，去中心化程度较好。",
                    suggestion="筹码分散有助于价格稳定，是积极信号。"
                ))

        # 检查是否有黑洞地址销毁
        burn_addresses = {'T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb',  # 常见黑洞
                         'TQn9Y2khEsLJW1ChVWFMSMeRDow5KcbLSE'}  # 另一个常见黑洞
        
        for h in holders[:20]:
            if h.get('address') in burn_addresses:
                amount = int(h.get('balance', 0))
                if total_supply > 0:
                    percent = (amount / total_supply) * 100
                    result.add_risk(RiskItem(
                        category="代币经济学",
                        severity="info",
                        title="存在代币销毁",
                        description=f"检测到黑洞地址持有 {percent:.1f}% 的代币，说明项目方已进行代币销毁。",
                        suggestion="销毁代币通常被视为积极的通缩行为。"
                    ))
                break


def format_report(result: ScanResult) -> str:
    """格式化扫描报告为文本"""
    lines = []
    lines.append("=" * 60)
    lines.append("  🛡️  TRON 智能合约安全扫描报告")
    lines.append("=" * 60)
    lines.append("")
    
    # 基本信息
    lines.append("📋 基本信息")
    lines.append("-" * 40)
    lines.append(f"  合约地址: {result.contract_address}")
    lines.append(f"  合约名称: {result.contract_name or '未知'}")
    lines.append(f"  编译器: {result.compiler_version or '未知'}")
    lines.append(f"  源码验证: {'✅ 已验证' if result.is_verified else '❌ 未验证'}")
    lines.append(f"  创建时间: {result.create_time or '未知'}")
    lines.append(f"  累计交易: {result.trx_count:,} 次")
    
    if result.token_symbol:
        lines.append(f"  代币名称: {result.token_name} ({result.token_symbol})")
        lines.append(f"  持有者: {result.holders_count:,} 人")
    
    lines.append("")
    
    # 风险评分
    lines.append("📊 安全评分")
    lines.append("-" * 40)
    lines.append(f"  综合评分: {result.overall_score}/100")
    lines.append(f"  风险等级: {result.risk_level}")
    lines.append(f"  检测项数: {len(result.risks)} 项")
    lines.append("")

    # 风险详情 - 按严重程度分组
    high_risks = [r for r in result.risks if r.severity == 'high']
    medium_risks = [r for r in result.risks if r.severity == 'medium']
    low_risks = [r for r in result.risks if r.severity == 'low']
    info_risks = [r for r in result.risks if r.severity == 'info']

    if high_risks:
        lines.append("🚨 高风险项")
        lines.append("-" * 40)
        for i, r in enumerate(high_risks, 1):
            lines.append(f"  {i}. [{r.category}] {r.title}")
            lines.append(f"     {r.description}")
            lines.append(f"     💡 建议: {r.suggestion}")
            lines.append("")

    if medium_risks:
        lines.append("⚠️  中风险项")
        lines.append("-" * 40)
        for i, r in enumerate(medium_risks, 1):
            lines.append(f"  {i}. [{r.category}] {r.title}")
            lines.append(f"     {r.description}")
            lines.append(f"     💡 建议: {r.suggestion}")
            lines.append("")

    if low_risks:
        lines.append("📝 低风险项")
        lines.append("-" * 40)
        for i, r in enumerate(low_risks, 1):
            lines.append(f"  {i}. [{r.category}] {r.title}")
            lines.append(f"     {r.description}")
            lines.append(f"     💡 建议: {r.suggestion}")
            lines.append("")

    if info_risks:
        lines.append("ℹ️  提示信息")
        lines.append("-" * 40)
        for i, r in enumerate(info_risks, 1):
            lines.append(f"  {i}. [{r.category}] {r.title}")
            lines.append(f"     {r.description}")
            lines.append(f"     💡 建议: {r.suggestion}")
            lines.append("")

    lines.append("=" * 60)
    lines.append("  ⚠️  免责声明")
    lines.append("  本报告仅供参考，不构成任何投资建议。")
    lines.append("  扫描基于公开链上数据和自动化分析，")
    lines.append("  可能存在误报或漏报，投资请自行判断。")
    lines.append("=" * 60)

    return "\n".join(lines)


def main():
    import sys
    if len(sys.argv) < 2:
        print("用法: python scanner.py <合约地址>")
        print("示例: python scanner.py TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t")
        return

    address = sys.argv[1].strip()
    scanner = TronContractScanner()

    print(f"🔍 正在扫描合约: {address}...")
    print()

    result = scanner.scan(address)
    report = format_report(result)
    print(report)


if __name__ == "__main__":
    main()
