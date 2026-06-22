#!/usr/bin/env python3
"""
TRON合约扫描器 - API封装
支持批量扫描、JSON输出、风险等级判断
"""

import json
from scanner_v2 import TronContractScanner, ScanResult, format_report


def scan_to_dict(address: str) -> dict:
    """扫描并返回字典格式"""
    scanner = TronContractScanner()
    result = scanner.scan(address)
    
    return {
        "contract_address": result.contract_address,
        "contract_name": result.contract_name,
        "compiler_version": result.compiler_version,
        "is_verified": result.is_verified,
        "create_time": result.create_time,
        "trx_count": result.trx_count,
        "creator_address": result.creator_address,
        "token_name": result.token_name,
        "token_symbol": result.token_symbol,
        "total_supply": result.total_supply,
        "holders_count": result.holders_count,
        "overall_score": result.overall_score,
        "risk_level": result.risk_level,
        "risks": [
            {
                "category": r.category,
                "severity": r.severity,
                "title": r.title,
                "description": r.description,
                "suggestion": r.suggestion
            }
            for r in result.risks
        ]
    }


def batch_scan(addresses: list) -> list:
    """批量扫描多个合约"""
    results = []
    for addr in addresses:
        try:
            results.append(scan_to_dict(addr))
        except Exception as e:
            results.append({
                "contract_address": addr,
                "error": str(e)
            })
    return results


def get_risk_summary(result_dict: dict) -> str:
    """获取一句话风险总结"""
    score = result_dict.get('overall_score', 0)
    symbol = result_dict.get('token_symbol', '未知代币')
    
    high_count = sum(1 for r in result_dict.get('risks', []) if r['severity'] == 'high')
    medium_count = sum(1 for r in result_dict.get('risks', []) if r['severity'] == 'medium')
    
    if score >= 80:
        verdict = f"✅ {symbol} 安全评分 {score}/100，风险较低，可以考虑。"
    elif score >= 60:
        verdict = f"⚠️  {symbol} 安全评分 {score}/100，存在一定风险，需谨慎。"
    elif score >= 40:
        verdict = f"🚨 {symbol} 安全评分 {score}/100，风险较高，建议远离。"
    else:
        verdict = f"💀 {symbol} 安全评分 {score}/100，极高风险，绝对不要碰！"
    
    details = f"检测到 {high_count} 项高风险、{medium_count} 项中风险。"
    return f"{verdict} {details}"


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("用法:")
        print("  python scanner_api.py <合约地址>          # 单个扫描，输出JSON")
        print("  python scanner_api.py --text <地址>       # 单个扫描，输出文本报告")
        print("  python scanner_api.py --batch 地址1 地址2 # 批量扫描")
        print("  python scanner_api.py --summary <地址>    # 一句话总结")
        sys.exit(1)
    
    if sys.argv[1] == '--text':
        scanner = TronContractScanner()
        result = scanner.scan(sys.argv[2])
        print(format_report(result))
    elif sys.argv[1] == '--batch':
        results = batch_scan(sys.argv[2:])
        print(json.dumps(results, ensure_ascii=False, indent=2))
    elif sys.argv[1] == '--summary':
        result = scan_to_dict(sys.argv[2])
        print(get_risk_summary(result))
    else:
        result = scan_to_dict(sys.argv[1])
        print(json.dumps(result, ensure_ascii=False, indent=2))
