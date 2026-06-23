#!/usr/bin/env python3
"""
批量扫描脚本 - 扫描地址列表并生成报告
"""

import json
import sys
import os
import time
from datetime import datetime

# 添加当前目录到路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 导入扫描器
import importlib.util
spec = importlib.util.spec_from_file_location("scanner_v50", os.path.join(os.path.dirname(os.path.abspath(__file__)), "scanner_v50.py"))
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)


def load_addresses(filepath):
    """加载地址列表，支持 地址|符号 格式"""
    addresses = []
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '|' in line:
                addr, symbol = line.split('|', 1)
                addresses.append((addr.strip(), symbol.strip()))
            else:
                addresses.append((line.strip(), ''))
    return addresses


def batch_scan(addresses, chain, delay=0.5):
    """批量扫描"""
    results = []
    total = len(addresses)
    for i, (addr, symbol) in enumerate(addresses):
        print(f"[{i+1}/{total}] 扫描 {addr} ({symbol})...", flush=True)
        try:
            result = scanner.scan(addr, chain)
            # 确保有symbol
            if symbol and not result.get('contract', {}).get('symbol'):
                result['contract']['symbol'] = symbol
            results.append(result)
        except Exception as e:
            print(f"  错误: {e}")
            results.append({
                "contract": {"address": addr, "chain": chain, "symbol": symbol},
                "error": str(e),
                "risk_score": 0,
                "risk_level": "error"
            })
        time.sleep(delay)
    return results


def generate_report(results, chain):
    """生成Markdown报告"""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    chain_name = "TRON" if chain == "tron" else "BSC"
    
    # 统计风险分布
    stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "safe": 0, "error": 0}
    for r in results:
        level = r.get('risk_level', 'safe')
        if level in stats:
            stats[level] += 1
        else:
            stats["safe"] += 1
    
    # 计算平均分
    scores = [r.get('risk_score', 0) for r in results if r.get('risk_level') != 'error']
    avg_score = sum(scores) / len(scores) if scores else 0
    
    # 按风险等级排序
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "safe": 4, "error": 5}
    results_sorted = sorted(results, key=lambda x: severity_order.get(x.get('risk_level', 'safe'), 99))
    
    # 生成报告
    report = []
    report.append(f"# {chain_name} 代币安全扫描日报")
    report.append("")
    report.append(f"- **扫描时间**: {now}")
    report.append(f"- **扫描代币数**: {len(results)}")
    report.append(f"- **链**: {chain_name}")
    report.append(f"- **平均安全分**: {avg_score:.1f}/100")
    report.append("")
    report.append("## 风险概览")
    report.append("")
    report.append(f"- 🔴 **critical**: {stats['critical']}")
    report.append(f"- 🟠 **high**: {stats['high']}")
    report.append(f"- 🟡 **medium**: {stats['medium']}")
    report.append(f"- 🟢 **low**: {stats['low']}")
    report.append(f"- ✅ **safe**: {stats['safe']}")
    if stats['error'] > 0:
        report.append(f"- ❌ **error**: {stats['error']}")
    report.append("")
    report.append("---")
    report.append("")
    report.append("## 详细报告")
    report.append("")
    
    for i, r in enumerate(results_sorted):
        contract = r.get('contract', {})
        symbol = contract.get('symbol', '')
        name = contract.get('name', '')
        addr = contract.get('address', 'unknown')
        addr_short = addr[:10] + '...' + addr[-8:] if len(addr) > 18 else addr
        score = r.get('risk_score', 0)
        level = r.get('risk_level', 'unknown').upper()
        is_verified = contract.get('is_verified', False)
        holders = r.get('holders_count', 0)
        honeypot = r.get('honeypot', {})
        is_honeypot = honeypot.get('is_honeypot', False)
        hp_confidence = honeypot.get('confidence', 0)
        risks = r.get('risks', [])
        
        title = f"### {i+1}. {symbol} `{addr_short}`" if symbol else f"### {i+1}. `{addr_short}`"
        report.append(title)
        report.append("")
        report.append(f"- **风险等级**: {level} (分数: {score}/100)")
        if name:
            report.append(f"- **合约名称**: {name}")
        report.append(f"- **是否验证**: {'是' if is_verified else '否'}")
        report.append(f"- **蜜罐风险**: {'是' if is_honeypot else '否'} (置信度: {hp_confidence}%)")
        report.append(f"- **持有者**: {holders}")
        report.append("")
        report.append("**主要风险项**:")
        report.append("")
        
        # 显示前3个风险项
        displayed = 0
        for risk in risks:
            sev = risk.get('severity', '')
            if sev in ('critical', 'high', 'medium'):
                icon = '🔴' if sev == 'critical' else ('🟠' if sev == 'high' else '🟡')
                cat = risk.get('category', '')
                desc = risk.get('description', '')
                report.append(f"- {icon} **{cat}**: {desc}")
                displayed += 1
                if displayed >= 3:
                    break
        
        remaining = len([x for x in risks if x.get('severity') in ('critical', 'high', 'medium')]) - displayed
        if remaining > 0:
            report.append(f"- ... 还有 {remaining} 项中高风险")
        
        low_count = len([x for x in risks if x.get('severity') in ('low', 'info')])
        if low_count > 0 and displayed == 0:
            report.append("- 无显著风险项")
        
        report.append("")
        report.append("---")
        report.append("")
    
    report.append("")
    report.append("*由 SecureScan v5.0 自动生成 | Agent-first 链上安全基础设施*")
    
    return "\n".join(report)


def main():
    if len(sys.argv) < 3:
        print("用法: python3 batch_scan.py <地址文件> <链名> [输出前缀]")
        print("示例: python3 batch_scan.py addresses_tron.txt tron daily_scan_tron")
        sys.exit(1)
    
    addr_file = sys.argv[1]
    chain = sys.argv[2]
    prefix = sys.argv[3] if len(sys.argv) > 3 else f"scan_{chain}"
    
    # 日期
    today = datetime.now().strftime("%Y%m%d")
    
    # 加载地址
    addresses = load_addresses(addr_file)
    print(f"加载了 {len(addresses)} 个地址，链: {chain}")
    
    # 批量扫描
    results = batch_scan(addresses, chain, delay=0.3)
    
    # 保存JSON
    json_file = f"{prefix}_{today}.json"
    with open(json_file, 'w') as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print(f"JSON结果已保存到: {json_file}")
    
    # 生成报告
    report = generate_report(results, chain)
    md_file = f"{prefix}_{today}.md"
    with open(md_file, 'w') as f:
        f.write(report)
    print(f"Markdown报告已保存到: {md_file}")
    
    # 同时保存一个 latest 版本
    with open(f"{prefix}_latest.md", 'w') as f:
        f.write(report)
    with open(f"{prefix}_latest.json", 'w') as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    
    print("完成！")


if __name__ == "__main__":
    main()
