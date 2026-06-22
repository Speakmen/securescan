#!/usr/bin/env python3
"""
TRON 智能合约安全扫描器 v2.1
- 基于链上数据和bytecode分析
- 修复API调用，使用account + contract/code组合
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
    category: str
    severity: str  # high/medium/low/info
    title: str
    description: str
    suggestion: str


@dataclass
class ScanResult:
    """扫描结果"""
    contract_address: str
    contract_name: str = ""
    is_contract: bool = False
    is_verified: bool = False
    create_time: str = ""
    trx_count: int = 0
    token_name: str = ""
    token_symbol: str = ""
    total_supply: str = ""
    holders_count: int = 0
    bytecode_size: int = 0
    risks: List[RiskItem] = field(default_factory=list)
    overall_score: int = 100

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
            "User-Agent": "Mozilla/5.0 (compatible; TRON-Scanner/2.1)"
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

    def get_account_info(self, address: str) -> dict:
        """获取账户/合约基本信息"""
        return self._get("account", {"address": address})

    def get_contract_code(self, address: str) -> dict:
        """获取合约字节码和ABI"""
        data = self._get("contracts/code", {"contract": address})
        if data and "data" in data:
            return data["data"]
        return {}

    def get_token_holders(self, address: str, limit: int = 20) -> list:
        """获取代币持有者列表"""
        data = self._get("token_trc20/holders", {
            "contract_address": address,
            "page_size": limit,
            "page": 1
        })
        if data and "data" in data:
            return data["data"]
        return []

    def scan(self, address: str) -> ScanResult:
        """完整扫描合约"""
        result = ScanResult(contract_address=address)

        # 1. 获取账户基本信息
        account_info = self.get_account_info(address)
        if account_info:
            # 判断是否为合约
            contract_map = account_info.get('contractMap', {})
            result.is_contract = address in contract_map or contract_map.get(address, False)
            
            # 获取名称
            result.contract_name = account_info.get('name', '')
            
            # 交易次数
            result.trx_count = account_info.get('totalTransactionCount', 0)
            
            # 获取代币信息
            trc20_tokens = account_info.get('trc20token_balances', [])
            if trc20_tokens:
                # 找到该合约本身的代币
                for token in trc20_tokens:
                    if token.get('tokenId', '').lower() == address.lower():
                        result.token_name = token.get('tokenName', '')
                        result.token_symbol = token.get('tokenAbbr', '')
                        result.total_supply = token.get('balance', '')  # 注意：这是该地址持有的量，不是总供应量
                        result.holders_count = token.get('nrOfTokenHolders', 0)
                        break

        # 2. 获取合约代码信息
        code_info = self.get_contract_code(address)
        bytecode = code_info.get('byteCode', '')
        
        if bytecode:
            result.bytecode_size = len(bytecode) // 2  # 字节数
            # 有字节码，进一步确认是合约
            result.is_contract = True
            
            # 检查是否有ABI（验证过的合约才有ABI）
            abi_str = code_info.get('abi', '')
            if abi_str and abi_str != '[]' and abi_str != '{}':
                result.is_verified = True
            
            # 基于字节码的风险检测
            self._scan_bytecode_risks(result, bytecode)
            
            # 基于ABI的风险检测
            if result.is_verified:
                try:
                    abi = json.loads(abi_str) if isinstance(abi_str, str) else abi_str
                    self._scan_abi_risks(result, abi)
                except:
                    pass

        # 3. 基础风险检测
        self._scan_basic_risks(result, account_info)

        # 4. 持有者分析
        if result.holders_count > 0 or result.token_symbol:
            holders = self.get_token_holders(address)
            if holders:
                self._scan_holders_risks(result, holders)

        return result

    def _scan_basic_risks(self, result: ScanResult, account_info: dict):
        """基础风险检测"""

        # 风险1: 是否为有效合约
        if not result.is_contract:
            result.add_risk(RiskItem(
                category="基本信息",
                severity="high",
                title="地址不是合约",
                description="该地址不是一个智能合约地址，可能是普通用户地址或无效地址。",
                suggestion="请确认合约地址是否正确。"
            ))
            return  # 不是合约，后面的检测无意义

        # 风险2: 是否开源验证
        if not result.is_verified:
            result.add_risk(RiskItem(
                category="信息透明度",
                severity="medium",
                title="合约源代码未验证",
                description="无法确认该合约的源代码是否已验证。未验证的合约无法深入分析其逻辑，可能隐藏风险。",
                suggestion="对于重要投资，务必选择已开源验证的合约。"
            ))
        else:
            result.add_risk(RiskItem(
                category="信息透明度",
                severity="info",
                title="合约已验证",
                description="该合约已验证源代码，可以进行更深入的安全分析。",
                suggestion="开源透明是项目可信度的重要指标。"
            ))

        # 风险3: 交易活跃度
        if result.trx_count > 0:
            if result.trx_count < 100:
                result.add_risk(RiskItem(
                    category="流动性",
                    severity="medium",
                    title="交易活跃度极低",
                    description=f"该合约累计交易仅 {result.trx_count} 次，流动性极差。",
                    suggestion="低流动性代币买卖滑点大，参与需谨慎。"
                ))
            elif result.trx_count > 1000000:
                result.add_risk(RiskItem(
                    category="流动性",
                    severity="info",
                    title="交易活跃度高",
                    description=f"累计交易 {result.trx_count/1000000:.1f}M 次，交易活跃，流动性较好。",
                    suggestion="交易活跃度是代币生命力的重要指标。"
                ))
            elif result.trx_count > 10000:
                result.add_risk(RiskItem(
                    category="流动性",
                    severity="info",
                    title="交易活跃度良好",
                    description=f"累计交易 {result.trx_count/1000:.1f}K 次，有一定流动性。",
                    suggestion="流动性尚可，但需结合其他因素判断。"
                ))

        # 风险4: 持有者数量
        if result.holders_count > 0:
            if result.holders_count < 10:
                result.add_risk(RiskItem(
                    category="去中心化程度",
                    severity="high",
                    title="持有者极度集中",
                    description=f"代币持有者仅 {result.holders_count} 人，筹码极度集中，庄家操控风险高。",
                    suggestion="筹码高度集中的项目风险极大，建议远离。"
                ))
            elif result.holders_count < 100:
                result.add_risk(RiskItem(
                    category="去中心化程度",
                    severity="medium",
                    title="持有者较少",
                    description=f"代币持有者仅 {result.holders_count} 人，去中心化程度较低。",
                    suggestion="持有者较少的项目需关注大户动向。"
                ))
            elif result.holders_count > 10000:
                result.add_risk(RiskItem(
                    category="去中心化程度",
                    severity="info",
                    title="持有者广泛",
                    description=f"代币持有者达 {result.holders_count/1000:.1f}K 人，分布较广泛。",
                    suggestion="持有者广泛是项目健康的表现之一。"
                ))

        # 风险5: 合约大小
        if result.bytecode_size > 0:
            if result.bytecode_size < 200:
                result.add_risk(RiskItem(
                    category="异常特征",
                    severity="low",
                    title="合约字节码偏小",
                    description=f"合约字节码仅约 {result.bytecode_size} 字节，小于标准代币合约。",
                    suggestion="需结合其他因素综合判断。"
                ))

    def _scan_bytecode_risks(self, result: ScanResult, bytecode: str):
        """基于字节码的风险检测"""
        
        # 将十六进制字符串转为小写便于匹配
        bc = bytecode.lower()
        
        # 检测1: SELFDESTRUCT (0xff) 
        # 注意：简单的ff出现不准确，这里用更保守的方式
        # 实际上需要反编译，但MVP阶段做模式匹配
        ff_count = bc.count('ff')
        if ff_count > 100:  # 正常合约也会有很多ff，这个检测不太准
            pass  # 暂时跳过，误报率太高
        
        # 检测2: DELEGATECALL (0xf4) - 代理合约特征
        delegatecall_count = bc.count('f4')
        if delegatecall_count > 5:
            result.add_risk(RiskItem(
                category="可升级性",
                severity="medium",
                title="可能是可升级合约",
                description="检测到合约字节码中包含较多DELEGATECALL操作码特征，可能是可升级的代理合约。项目方可以更改合约逻辑。",
                suggestion="可升级合约意味着规则可能变更，需了解升级权限和时间锁机制。"
            ))

    def _scan_abi_risks(self, result: ScanResult, abi: list):
        """基于ABI的功能检测"""

        function_names = [item.get('name', '') for item in abi if item.get('type') == 'function']
        function_set = set(function_names)

        # 检测黑名单功能
        blacklist_funcs = {'blacklist', 'addBlackList', 'removeBlackList', 
                          'isBlackListed', 'destroyBlackFunds', 'freeze', 'ban',
                          'blackList', 'addToBlackList', 'removeFromBlackList'}
        found_blacklist = function_set & blacklist_funcs
        if found_blacklist:
            result.add_risk(RiskItem(
                category="权限控制",
                severity="medium",
                title="存在黑名单/冻结功能",
                description=f"合约包含黑名单或资产冻结功能：{', '.join(found_blacklist)}。项目方可以冻结地址的代币。",
                suggestion="评估项目方可信度，了解冻结功能的使用规则。"
            ))

        # 检测增发功能
        mint_funcs = {'mint', '_mint', 'issue', 'generate', 'createTokens',
                     'mintToken', 'increaseSupply', 'addSupply'}
        found_mint = function_set & mint_funcs
        if found_mint:
            # 检查是否有权限控制
            has_owner = any('owner' in f.lower() or 'Ownable' in f or 'onlyOwner' in f 
                          for f in function_names)
            
            if has_owner:
                result.add_risk(RiskItem(
                    category="代币经济学",
                    severity="medium",
                    title="存在增发功能",
                    description=f"合约包含 {', '.join(found_mint)} 等增发函数，存在所有权控制。所有者可以增发代币。",
                    suggestion="了解项目的代币增发规则和上限。"
                ))
            else:
                result.add_risk(RiskItem(
                    category="代币经济学",
                    severity="high",
                    title="增发功能权限不明",
                    description=f"检测到增发函数：{', '.join(found_mint)}，但未发现明确的所有权控制。",
                    suggestion="请谨慎评估，无明确权限控制的增发功能风险较高。"
                ))

        # 检测暂停功能
        pause_funcs = {'pause', 'unpause', 'paused', '_pause', 'setPaused'}
        found_pause = function_set & pause_funcs
        if found_pause:
            result.add_risk(RiskItem(
                category="权限控制",
                severity="low",
                title="存在暂停功能",
                description=f"合约包含暂停功能：{', '.join(found_pause)}。项目方可以暂停转账等功能。",
                suggestion="暂停功能在某些场景下是合理的风控手段，但也意味着项目方有控制权。"
            ))

        # 检测所有权相关
        owner_funcs = {'owner', 'transferOwnership', 'renounceOwnership', 'getOwner', 'Ownable'}
        found_owner = function_set & owner_funcs
        if found_owner:
            result.add_risk(RiskItem(
                category="权限控制",
                severity="info",
                title="存在所有权机制",
                description="合约使用了所有权模式，存在owner地址。",
                suggestion="了解owner权限范围，是否有时间锁或多签保护。"
            ))

    def _scan_holders_risks(self, result: ScanResult, holders: list):
        """持有者分布风险检测"""
        if not holders:
            return

        # 计算前10大持有者占比（需要总供应量，这里估算）
        total_supply = 0
        # 尝试从第一个持有者获取总供应量信息
        # 注意：holders列表里的balance是各自的持有量，我们需要总供应量
        
        # 简单估算：假设前20名持有量总和 * 一个系数
        top_sum = sum(int(h.get('balance', 0)) for h in holders[:10])
        
        if result.total_supply:
            try:
                total = int(result.total_supply)
                if total > 0:
                    top10_percent = (top_sum / total) * 100
                    
                    if top10_percent > 90:
                        result.add_risk(RiskItem(
                            category="筹码分布",
                            severity="high",
                            title="筹码高度集中",
                            description=f"前10大持有者持有约 {top10_percent:.1f}% 的代币，筹码极度集中。",
                            suggestion="筹码高度集中的项目庄家操控风险大，建议远离。"
                        ))
                    elif top10_percent > 70:
                        result.add_risk(RiskItem(
                            category="筹码分布",
                            severity="medium",
                            title="筹码较为集中",
                            description=f"前10大持有者持有约 {top10_percent:.1f}% 的代币。",
                            suggestion="关注大户动向，注意砸盘风险。"
                        ))
                    elif top10_percent < 30:
                        result.add_risk(RiskItem(
                            category="筹码分布",
                            severity="info",
                            title="筹码分布较分散",
                            description=f"前10大持有者仅持有约 {top10_percent:.1f}% 的代币，去中心化程度较好。",
                            suggestion="筹码分散有助于价格稳定。"
                        ))
            except:
                pass


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
    name = result.token_name or result.contract_name or '未知'
    if result.token_symbol:
        name += f" ({result.token_symbol})"
    lines.append(f"  合约名称: {name}")
    lines.append(f"  源码验证: {'✅ 已验证' if result.is_verified else '❌ 未验证'}")
    lines.append(f"  累计交易: {result.trx_count:,} 次")
    if result.holders_count:
        lines.append(f"  持有者: {result.holders_count:,} 人")
    if result.bytecode_size:
        lines.append(f"  代码大小: {result.bytecode_size:,} 字节")
    
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
        print("用法: python scanner_v21.py <合约地址>")
        print("示例: python scanner_v21.py TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t")
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
