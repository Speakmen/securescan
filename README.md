# SecureScan - Agent-first 多链智能合约安全扫描器

> 为AI Agent设计的链上安全基础设施，人类顺便能用

## 特性

- 🔍 **多链支持**: TRON、BSC，更多链持续扩展中
- 🤖 **Agent-first**: 结构化JSON输出，标准化风险代码，专为Agent调用设计
- 🍯 **蜜罐检测**: 检测白名单、黑名单、冻结、可升级代理、铸币权限等蜜罐特征
- 📊 **风险评分**: 0-100分风险评分 + 4级风险等级（safe/medium/high/critical）
- ⚡ **零依赖**: 纯Python标准库实现，无需安装额外依赖
- 🌐 **HTTP API**: 内置REST API服务器，开箱即用
- 💾 **本地缓存**: 5分钟缓存，避免重复请求
- 📝 **可解释**: 每个风险项都有明确的证据和描述

## 风险检测维度

| 类别 | 说明 |
|------|------|
| 蜜罐风险 | 白名单限制、交易税异常、可升级代理、恶意函数 |
| 权限控制 | owner权限过大、mint功能、黑名单、冻结功能 |
| 信息透明度 | 源码是否验证、合约大小是否正常 |
| 流动性 | 24h交易量分析（仅支持TRON） |
| 去中心化程度 | 持有者数量分析（仅支持TRON） |
| 合约年龄 | 部署时间分析（仅支持TRON） |
| 标准符合性 | ERC20/TRC20标准检测 |

## 支持的链

| 链 | 状态 | 字节码分析 | 持有者数据 | 交易量数据 |
|----|------|-----------|-----------|-----------|
| BSC (BNB Chain) | ✅ 正式支持 | ✅ | ❌ (API被墙) | ❌ (API被墙) |
| TRON | ⚡ Beta | ⚠️ (TronGrid受限) | ✅ | ✅ |

## 使用方法

### 命令行

```bash
python scanner_v50.py <contract_address> [chain]
# 示例
python scanner_v50.py 0x55d398326f99059fF775485246999027B3197955 bsc
python scanner_v50.py TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t tron
```

### API服务器

```bash
python api_server.py 8080
```

接口:
- `GET /api/scan?address=xxx&chain=bsc` - 扫描单个合约
- `GET /api/batch_scan?addresses=addr1,addr2&chain=bsc` - 批量扫描
- `GET /api/health` - 健康检查
- `GET /api/chains` - 支持的链列表

### Python库

```python
from scanner_v50 import BscScanner, TronScanner

scanner = BscScanner()
result = scanner.scan("0x55d398326f99059fF775485246999027B3197955")

print(f"代币: {result.contract.symbol}")
print(f"风险等级: {result.risk_level}")
print(f"风险得分: {result.risk_score}")

# 查看所有风险项
for risk in result.risks:
    print(f"[{risk.severity}] {risk.description}: {risk.evidence}")
```

## 输出格式

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "contract": {
      "address": "0x...",
      "chain": "bsc",
      "symbol": "USDT",
      "name": "Tether USD",
      "decimals": 18,
      "is_contract": true,
      "is_verified": false,
      "contract_age_days": 0
    },
    "risk": {
      "score": 0,
      "level": "safe",
      "summary": "风险等级: safe (得分: 0/100)"
    },
    "honeypot": {
      "is_honeypot": false,
      "confidence": 0,
      "reasons": []
    },
    "holders": {"count": 0},
    "volume": {"24h": 0},
    "risks": [...],
    "functions": [...],
    "scan_time": 1234567890
  }
}
```

## 项目路线图

- [ ] 支持Ethereum链
- [ ] 支持更多EVM兼容链（Polygon、Arbitrum等）
- [ ] 更精准的蜜罐检测（模拟交易）
- [ ] LP锁仓检测
- [ ] 合约部署者追踪
- [ ] 批量扫描Web界面
- [ ] 定时扫描 + 告警

## 关于

SecureScan 是为AI Agent打造的链上安全基础设施。我们相信，未来的链上安全分析主要由Agent完成，人类只需要看最终报告。

- **定位**: Agent-first，人类顺便能用
- **哲学**: 工具型AI，能落就落，能收就收
- **家族**: 铃铛系列 - 角木弦（承接验证）
