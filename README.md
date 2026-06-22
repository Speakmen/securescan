# SecureScan - Agent-first 多链智能合约安全扫描器

> 为AI Agent设计的链上安全基础设施，人类顺便能用

## 特性

- 🔍 **多链支持**: TRON、BSC，更多链持续扩展中
- 🤖 **Agent-first**: 结构化JSON输出，标准化风险代码，专为Agent调用设计
- 🍯 **蜜罐检测**: 检测白名单、黑名单、冻结、可升级代理等蜜罐特征
- 📊 **风险评分**: 0-100分风险评分 + 5级风险等级
- ⚡ **零依赖**: 纯Python实现，无需安装额外依赖
- 🌐 **HTTP API**: 内置REST API服务器，开箱即用

## 风险检测维度

| 类别 | 说明 |
|------|------|
| 蜜罐风险 | 白名单限制、交易税异常、可升级代理 |
| 权限控制 | owner权限过大、mint功能、黑名单、冻结 |
| 信息透明度 | 源码是否验证 |
| 流动性 | 24h交易量分析 |
| 去中心化程度 | 持有者数量分析 |
| 合约年龄 | 部署时间分析 |
| 标准符合性 | ERC20/TRC20标准检测 |

## 使用方法

### 命令行

```bash
python scanner_v50.py <contract_address> [chain]
# 示例
python scanner_v50.py 0x0E09FaBB73Bd3Ade0a17ECC321fD13a19e81cE82 bsc
```

### API服务器

```bash
python api_server_v5.py 8080
```

接口:
- `GET /api/scan/{chain}/{address}` - 扫描单个合约
- `POST /api/scan/batch` - 批量扫描
- `GET /api/health` - 健康检查
- `GET /api/chains` - 支持的链列表

### Python库

```python
from scanner_v50 import scan, scan_batch

# 单个扫描
result = scan("0x...", "bsc")
print(result['risk_level'])

# 批量扫描
results = scan_batch(["0x...", "0x..."], "bsc")
```

## 项目背景

SecureScan 是由弦响工作室开发的链上安全工具，致力于为AI Agent提供可靠的链上安全检测能力。

---
*版本: v5.0 | 最后更新: 2026-06-23*
