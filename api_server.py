#!/usr/bin/env python3
"""
SecureScan API Server
链上合约安全扫描器 - HTTP API 服务
使用Python标准库实现，无需额外依赖
"""

import json
import time
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# 导入扫描器
sys.path.insert(0, '/app/data/所有对话/主对话/contract_scanner')
from scanner_v50 import BscScanner, TronScanner, ScanResult

# 初始化扫描器
bsc_scanner = BscScanner()
tron_scanner = TronScanner()

# 简单缓存（5分钟过期）
cache = {}
CACHE_TTL = 300  # 5分钟

def get_scanner(chain: str):
    """根据链名获取扫描器"""
    chain = chain.lower()
    if chain in ("bsc", "bnb"):
        return bsc_scanner
    elif chain in ("tron", "trx"):
        return tron_scanner
    else:
        return None

def result_to_dict(result: ScanResult) -> dict:
    """将扫描结果转为字典"""
    return {
        "contract": {
            "address": result.contract.address,
            "chain": result.contract.chain,
            "symbol": result.contract.symbol,
            "name": result.contract.name,
            "decimals": result.contract.decimals,
            "total_supply": str(result.contract.total_supply),
            "is_contract": result.contract.is_contract,
            "is_verified": result.contract.is_verified,
            "is_proxy": result.contract.is_proxy,
            "deployer": result.contract.deployer,
            "deploy_timestamp": result.contract.deploy_timestamp,
            "contract_age_days": result.contract.contract_age_days,
            "code_size": result.contract.code_size,
        },
        "risk": {
            "score": result.risk_score,
            "level": result.risk_level,
            "summary": f"风险等级: {result.risk_level} (得分: {result.risk_score}/100)",
        },
        "honeypot": {
            "is_honeypot": result.honeypot.is_honeypot if result.honeypot else False,
            "confidence": result.honeypot.confidence if result.honeypot else 0,
            "reasons": result.honeypot.reasons if result.honeypot else [],
        },
        "holders": {
            "count": result.holders_count,
        },
        "volume": {
            "24h": result.volume_24h,
        },
        "functions": [
            {"selector": f.selector, "name": f.name}
            for f in result.functions
        ] if result.functions else [],
        "risks": [
            {
                "code": r.code,
                "severity": r.severity,
                "category": r.category,
                "description": r.description,
                "evidence": r.evidence,
            }
            for r in result.risks
        ],
        "scan_time": int(time.time()),
    }

class ScanHandler(BaseHTTPRequestHandler):
    """HTTP请求处理器"""
    
    def _send_json(self, data, status=200):
        """发送JSON响应"""
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(body)
    
    def do_GET(self):
        """处理GET请求"""
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)
        
        # 健康检查
        if path == '/api/health' or path == '/health':
            self._send_json({
                "status": "ok",
                "timestamp": int(time.time()),
                "version": "5.0.0",
            })
            return
        
        # 支持的链
        elif path == '/api/chains':
            self._send_json({
                "code": 0,
                "data": [
                    {"id": "bsc", "name": "BNB Chain", "status": "active"},
                    {"id": "tron", "name": "TRON", "status": "beta"},
                ]
            })
            return
        
        # 单个合约扫描
        elif path == '/api/scan':
            address = params.get('address', [''])[0].strip()
            chain = params.get('chain', ['bsc'])[0].strip()
            
            if not address:
                self._send_json({"error": "缺少address参数"}, 400)
                return
            
            scanner = get_scanner(chain)
            if not scanner:
                self._send_json({"error": f"不支持的链: {chain}"}, 400)
                return
            
            # 检查缓存
            cache_key = f"{chain}:{address}"
            now = int(time.time())
            if cache_key in cache and now - cache[cache_key]["time"] < CACHE_TTL:
                self._send_json({
                    "code": 0,
                    "message": "success (cached)",
                    "data": cache[cache_key]["data"]
                })
                return
            
            try:
                result = scanner.scan(address)
                data = result_to_dict(result)
                cache[cache_key] = {"time": now, "data": data}
                
                self._send_json({
                    "code": 0,
                    "message": "success",
                    "data": data
                })
            except Exception as e:
                self._send_json({"error": f"扫描失败: {str(e)}"}, 500)
            return
        
        # 批量扫描
        elif path == '/api/batch_scan':
            addresses_str = params.get('addresses', [''])[0].strip()
            chain = params.get('chain', ['bsc'])[0].strip()
            
            if not addresses_str:
                self._send_json({"error": "缺少addresses参数"}, 400)
                return
            
            addresses = [a.strip() for a in addresses_str.split(",") if a.strip()]
            if len(addresses) > 20:
                self._send_json({"error": "最多支持20个地址批量扫描"}, 400)
                return
            
            scanner = get_scanner(chain)
            if not scanner:
                self._send_json({"error": f"不支持的链: {chain}"}, 400)
                return
            
            results = []
            for addr in addresses:
                try:
                    result = scanner.scan(addr)
                    results.append(result_to_dict(result))
                except Exception as e:
                    results.append({"address": addr, "error": str(e)})
                time.sleep(0.1)
            
            self._send_json({
                "code": 0,
                "message": "success",
                "count": len(results),
                "data": results
            })
            return
        
        # 首页
        elif path == '/' or path == '':
            self._send_json({
                "name": "SecureScan API",
                "version": "5.0.0",
                "description": "链上合约安全扫描器 - Agent-first",
                "endpoints": [
                    {"path": "/api/scan", "method": "GET", "params": "address, chain"},
                    {"path": "/api/batch_scan", "method": "GET", "params": "addresses, chain"},
                    {"path": "/api/chains", "method": "GET", "params": ""},
                    {"path": "/api/health", "method": "GET", "params": ""},
                ]
            })
            return
        
        else:
            self._send_json({"error": "Not Found"}, 404)
    
    def log_message(self, format, *args):
        """简化日志输出"""
        pass  # 静默模式，不输出访问日志

def run_server(host='0.0.0.0', port=8080):
    """启动服务器"""
    print(f"🚀 SecureScan API Server v5.0 启动中...")
    print(f"📡 监听地址: http://{host}:{port}")
    print(f"🔗 支持链: BSC, TRON")
    
    server = HTTPServer((host, port), ScanHandler)
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n👋 服务器已停止")
        server.shutdown()

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    run_server(port=port)
