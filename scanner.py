#!/usr/bin/env python3
"""
TRON 智能合约安全扫描工具 MVP
"""

import requests
import json
import re
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
    source_code: str = ""
    bytecode: str = ""
    risks: List[RiskItem] = field(default_factory=list)
    overall_score: int = 100  # 安全分数，100满分

    @property
    def risk_level(self) -> str:
        if self.overall_score >= 80:
            return "低风险"
        elif self.overall_score >= 60:
            return "中风险"
        elif self.overall_score >= 40:
            return "高风险"
        else:
            return "极高风险"

    def add_risk(self, risk: RiskItem):
        self.risks.append(risk)
        # 根据严重程度扣分
        score_map = {"high": 15, "medium": 8, "low": 3, "info": 0}
        self.overall_score -= score_map.get(risk.severity, 0)
        if self.overall_score < 0:
            self.overall_score = 0


class TronContractScanner:
    """TRON合约扫描器"""

    def __init__(self):
        self.base_url = "https://apilist.tronscan.org/api"

    def get_contract_info(self, address: str) -> dict:
        """获取合约信息"""
        try:
            r = requests.get(
                f"{self.base_url}/contract",
                params={"contract": address},
                timeout=10
            )
            if r.status_code == 200:
                return r.json()
        except Exception as e:
            print(f"获取合约信息失败: {e}")
        return {}

    def get_contract_source(self, address: str) -> Optional[str]:
        """获取合约源代码（如果已验证）"""
        try:
            r = requests.get(
                f"{self.base_url}/contract/code",
                params={"contract": address},
                timeout=10
            )
            if r.status_code == 200:
                data = r.json()
                # 尝试从不同字段获取源码
                if isinstance(data, dict):
                    for key in ['source_code', 'SourceCode', 'source', 'code']:
                        if key in data and data[key]:
                            return str(data[key])
                    # 如果有多个合约文件
                    if 'data' in data and isinstance(data['data'], list):
                        sources = []
                        for item in data['data']:
                            if 'source_code' in item:
                                sources.append(item['source_code'])
                            elif 'SourceCode' in item:
                                sources.append(item['SourceCode'])
                        if sources:
                            return "\n\n".join(sources)
        except Exception as e:
            print(f"获取合约源码失败: {e}")
        return None

    def get_account_info(self, address: str) -> dict:
        """获取账户信息"""
        try:
            r = requests.get(
                f"{self.base_url}/account",
                params={"address": address},
                timeout=10
            )
            if r.status_code == 200:
                return r.json()
        except Exception as e:
            print(f"获取账户信息失败: {e}")
        return {}

    def scan(self, address: str) -> ScanResult:
        """扫描合约"""
        result = ScanResult(contract_address=address)

        # 获取合约信息
        contract_info = self.get_contract_info(address)
        if contract_info:
            result.contract_name = contract_info.get('name', 'Unknown')
            result.compiler_version = contract_info.get('compiler_version', 'Unknown')

        # 获取源码
        source_code = self.get_contract_source(address)
        if source_code:
            result.source_code = source_code
            # 有源码，做深度扫描
            self._scan_source_code(result, source_code)
        else:
            # 没有源码，只能做基础检测
            result.add_risk(RiskItem(
                category="信息缺失",
                severity="medium",
                title="合约源代码未验证",
                description="该合约未在Tronscan上验证源代码，无法进行深度安全分析。未验证的合约可能隐藏恶意代码。",
                suggestion="投资前务必确认合约已开源并验证，或要求项目方提供源码进行审计。"
            ))

        # 获取账户信息做辅助检测
        account_info = self.get_account_info(address)
        if account_info:
            self._scan_account_info(result, account_info)

        # 如果检测项太少，加一个info级别的提示
        if len(result.risks) < 3:
            result.add_risk(RiskItem(
                category="提示",
                severity="info",
                title="仅完成基础检测",
                description="由于数据源限制，本次仅完成基础安全检测。对于重要投资，建议进行专业的合约审计。",
                suggestion="考虑进行专业智能合约安全审计，或使用更全面的安全分析工具。"
            ))

        return result

    def _scan_source_code(self, result: ScanResult, source_code: str):
        """基于源码的安全检测"""

        # 1. 检查是否有所有权控制（owner权限）
        if re.search(r'(owner|Ownable|onlyOwner|Ownable2Step)', source_code, re.IGNORECASE):
            has_renounce = 'renounceOwnership' in source_code
            if not has_renounce:
                result.add_risk(RiskItem(
                    category="权限控制",
                    severity="medium",
                    title="存在所有者权限但无法确认是否可放弃",
                    description="合约使用了Ownable模式，存在owner地址。如果owner权限过大且不可撤销，项目方可能拥有无限控制权。",
                    suggestion="检查owner具体权限，确认是否有时间锁或多签机制。"
                ))

        # 2. 检查是否有增发（mint）功能
        if re.search(r'(function\s+mint|_mint\s*\()', source_code):
            # 检查mint是否有权限控制
            mint_lines = re.findall(r'function\s+mint[^}]*{[^}]*}', source_code, re.IGNORECASE | re.DOTALL)
            has_access_control = any(
                re.search(r'(onlyOwner|require.*owner|modifier|auth|access)', line, re.IGNORECASE)
                for line in mint_lines
            )
            if not has_access_control:
                result.add_risk(RiskItem(
                    category="代币经济学",
                    severity="high",
                    title="增发功能可能无权限限制",
                    description="检测到mint（增发）函数，但未发现明确的访问控制。任何人都可能调用增发函数，存在无限增发风险。",
                    suggestion="立即远离该代币。无权限控制的增发函数是典型的骗局特征。"
                ))
            else:
                result.add_risk(RiskItem(
                    category="代币经济学",
                    severity="medium",
                    title="存在增发功能",
                    description="合约包含mint（增发）函数，受权限控制。所有者可以随时增发代币，可能导致通胀和币价下跌。",
                    suggestion="了解项目的代币经济学，确认增发是否有上限和用途。"
                ))

        # 3. 检查是否有黑名单/冻结功能
        if re.search(r'(blacklist|freeze|seize|ban|block.*account)', source_code, re.IGNORECASE):
            result.add_risk(RiskItem(
                category="权限控制",
                severity="medium",
                title="存在黑名单/冻结功能",
                description="合约包含黑名单或资产冻结功能。项目方可以冻结任意地址的代币，影响资金流动性。",
                suggestion="评估项目方可信度，了解冻结功能的使用规则和限制。"
            ))

        # 4. 检查是否有高额税费
        if re.search(r'(tax|fee|_tFee|_fee|taxRate|feeRate)', source_code, re.IGNORECASE):
            # 尝试找出税率数值
            tax_values = re.findall(r'(?:tax|fee)[_\w]*\s*[=:]\s*(\d+)', source_code, re.IGNORECASE)
            tax_info = ""
            if tax_values:
                rates = [f"{v}%" for v in tax_values[:3] if int(v) > 0 and int(v) < 100]
                if rates:
                    tax_info = f"检测到的税率值: {', '.join(rates)}。"
            result.add_risk(RiskItem(
                category="代币经济学",
                severity="low",
                title="存在交易税费",
                description=f"合约包含交易税/手续费机制。{tax_info}高税率可能影响交易利润，特别是对于短线交易者。",
                suggestion="了解具体税率和税费用途（如分红、回购、流动性添加等）。"
            ))

        # 5. 检查是否有自毁函数
        if re.search(r'(selfdestruct|suicide|SELFDESTRUCT)', source_code):
            result.add_risk(RiskItem(
                category="安全风险",
                severity="high",
                title="存在自毁函数",
                description="合约包含selfdestruct（自毁）函数。如果被恶意调用，可能销毁合约中的所有资金。",
                suggestion="检查自毁函数的调用权限和条件。如果可以被任意调用，极度危险。"
            ))

        # 6. 检查代理模式（可升级合约）
        if re.search(r'(delegatecall|proxy|upgrade|TransparentProxy|UUPS|_implementation)', source_code, re.IGNORECASE):
            result.add_risk(RiskItem(
                category="可升级性",
                severity="medium",
                title="可能是可升级合约",
                description="检测到delegatecall或代理模式特征，合约可能是可升级的。这意味着合约逻辑可以被更改，投资者权益可能发生变化。",
                suggestion="确认升级机制，是否有时间锁（Timelock）保护，升级权限归谁所有。"
            ))

        # 7. 检查重入风险
        if re.search(r'(call\.value|send|transfer|\.call\{)', source_code) and \
           not re.search(r'(ReentrancyGuard|nonReentrant|Checks-Effects-Interactions)', source_code, re.IGNORECASE):
            result.add_risk(RiskItem(
                category="安全漏洞",
                severity="medium",
                title="潜在重入风险",
                description="合约向外部地址转账，但未检测到重入防护（如ReentrancyGuard）。存在重入攻击的潜在风险。",
                suggestion="确认转账逻辑是否遵循Checks-Effects-Interactions模式，或使用了重入锁。"
            ))

        # 8. 检查是否有反机器人机制
        if re.search(r'(maxTxn|maxWallet|maxTransaction|_maxTx|MaxTx)', source_code, re.IGNORECASE):
            result.add_risk(RiskItem(
                category="交易限制",
                severity="info",
                title="存在交易限额",
                description="合约包含最大交易金额或最大持仓量限制。这通常是反机器人机制的一部分，可以防止巨鲸砸盘。",
                suggestion="了解具体限额数值，确认是否适合你的投资金额。"
            ))

        # 9. 检查流动性锁定相关代码
        if re.search(r'(lock|LiquidityLock|LPLock|unlock|_lockLiquidity)', source_code, re.IGNORECASE):
            result.add_risk(RiskItem(
                category="流动性",
                severity="info",
                title="包含流动性锁定逻辑",
                description="合约代码中包含流动性锁定相关逻辑。这是一个积极信号，说明项目方可能计划锁定流动性。",
                suggestion="在链上核实流动性是否实际锁定，以及锁定时间和比例。"
            ))

        # 10. 蜜罐检测 - 检查是否有只进不出的逻辑
        if re.search(r'(function\s+transfer[^}]*require[^}]*block|function\s+transfer[^}]*revert)', source_code, re.IGNORECASE):
            result.add_risk(RiskItem(
                category="欺诈风险",
                severity="high",
                title="可能存在转账限制（蜜罐风险）",
                description="transfer函数中包含复杂的条件判断，可能存在阻止用户卖出的蜜罐机制。",
                suggestion="高度警惕！蜜罐合约只允许买入不允许卖出，是常见的诈骗手段。"
            ))

        # 11. 检查是否有隐藏的铸币权限（后门）
        if re.search(r'(function\s+.*mint|_mint|_safeMint)', source_code, re.IGNORECASE):
            # 检查是否有隐藏的铸币后门
            hidden_mint_patterns = [
                r'(address.*=.*tx\.origin)',
                r'(require.*block\.timestamp.*<.*_mint)',
                r'(secret.*mint|hidden.*mint|backdoor)',
            ]
            for pattern in hidden_mint_patterns:
                if re.search(pattern, source_code, re.IGNORECASE):
                    result.add_risk(RiskItem(
                        category="欺诈风险",
                        severity="high",
                        title="疑似隐藏铸币后门",
                        description=f"检测到可疑模式: {pattern}。可能存在隐藏的铸币后门，项目方可以秘密增发代币。",
                        suggestion="极度危险！不要投资该代币。"
                    ))
                    break

    def _scan_account_info(self, result: ScanResult, account_info: dict):
        """基于账户信息的检测"""
        # 检查合约余额
        balance = account_info.get('balance', 0)
        if isinstance(balance, str):
            balance = int(balance) / 1e6

        # 检查是否为合约
        is_contract = account_info.get('type') == 'Contract' or 'tokenName' in account_info
        if not is_contract:
            result.add_risk(RiskItem(
                category="基本信息",
                severity="info",
                title="地址类型验证",
                description="该地址似乎不是标准合约账户，请确认地址是否正确。",
                suggestion="核实合约地址，避免向错误地址转账。"
            ))

        # 检查TRC20代币信息
        trc20_tokens = account_info.get('trc20token_balances', [])
        if trc20_tokens:
            # 有多种代币，可能是DEX合约或其他
            result.add_risk(RiskItem(
                category="基本信息",
                severity="info",
                title="合约持有多种代币",
                description=f"该合约地址持有 {len(trc20_tokens)} 种TRC20代币，可能是流动性池或DeFi合约。",
                suggestion="如果是流动性池，注意无常损失风险。"
            ))


def format_report(result: ScanResult) -> str:
    """格式化扫描报告"""
    lines = []
    lines.append("=" * 60)
    lines.append("  TRON 智能合约安全扫描报告")
    lines.append("=" * 60)
    lines.append("")
    lines.append(f"合约地址: {result.contract_address}")
    lines.append(f"合约名称: {result.contract_name}")
    lines.append(f"编译器版本: {result.compiler_version}")
    lines.append(f"安全评分: {result.overall_score}/100")
    lines.append(f"风险等级: {result.risk_level}")
    lines.append(f"检测到风险项: {len(result.risks)} 个")
    lines.append("")

    # 按严重程度分组
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
            lines.append(f"     建议: {r.suggestion}")
            lines.append("")

    if medium_risks:
        lines.append("⚠️  中风险项")
        lines.append("-" * 40)
        for i, r in enumerate(medium_risks, 1):
            lines.append(f"  {i}. [{r.category}] {r.title}")
            lines.append(f"     {r.description}")
            lines.append(f"     建议: {r.suggestion}")
            lines.append("")

    if low_risks:
        lines.append("📝 低风险项")
        lines.append("-" * 40)
        for i, r in enumerate(low_risks, 1):
            lines.append(f"  {i}. [{r.category}] {r.title}")
            lines.append(f"     {r.description}")
            lines.append(f"     建议: {r.suggestion}")
            lines.append("")

    if info_risks:
        lines.append("ℹ️  提示信息")
        lines.append("-" * 40)
        for i, r in enumerate(info_risks, 1):
            lines.append(f"  {i}. [{r.category}] {r.title}")
            lines.append(f"     {r.description}")
            lines.append(f"     建议: {r.suggestion}")
            lines.append("")

    lines.append("=" * 60)
    lines.append("  免责声明：本报告仅供参考，不构成投资建议。")
    lines.append("  扫描基于公开数据和自动化分析，可能存在误报或漏报。")
    lines.append("  投资有风险，请谨慎决策。")
    lines.append("=" * 60)

    return "\n".join(lines)


def main():
    import sys
    if len(sys.argv) < 2:
        print("用法: python scanner.py <合约地址>")
        print("示例: python scanner.py TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t")
        return

    address = sys.argv[1]
    scanner = TronContractScanner()

    print(f"正在扫描合约: {address}...")
    print()

    result = scanner.scan(address)
    report = format_report(result)
    print(report)


if __name__ == "__main__":
    main()
