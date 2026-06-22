#!/usr/bin/env python3
"""
SecureScan HTTP API - Agent-first 合约安全扫描服务
纯标准库实现，无外部依赖，可直接部署
"""

import json
import sys
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# 导入扫描器
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from scanner_v40 import scan, scan_batch, SUPPORTED_CHAINS


class ScanAPIHandler(BaseHTTPRequestHandler):
    """API 请求处理器"""
    
    def _send_json(self, data: dict, status: int = 200):
        """发送 JSON 响应"""
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Scanner-Version", "4.0")
        self.send_header("X-Scanner-Type", "agent-first")
        self.end_headers()
        self.wfile.write(body)
    
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)
        
        # 健康检查
        if path == "/health" or path == "/api/health":
            self._send_json({
                "status": "ok",
                "service": "securescan",
                "version": "4.0",
                "type": "agent-first",
                "supported_chains": list(set(
                    "tron" if c in ("tron", "trx") else "bsc"
                    for c in SUPPORTED_CHAINS.keys()
                ))
            })
            return
        
        # 支持的链
        elif path == "/api/chains":
            self._send_json({
                "chains": [
                    {"name": "tron", "chain_id": 195, "status": "available"},
                    {"name": "bsc", "chain_id": 56, "status": "available"},
                ]
            })
            return
        
        # 单个扫描
        elif path == "/api/scan" or path == "/scan":
            address = params.get("address", [""])[0]
            chain = params.get("chain", ["tron"])[0]
            
            if not address:
                self._send_json({
                    "error": "address parameter is required",
                    "usage": "GET /api/scan?address=CONTRACT_ADDRESS&chain=tron"
                }, status=400)
                return
            
            result = scan(address, chain)
            if "error" in result:
                self._send_json(result, status=400)
            else:
                self._send_json(result)
            return
        
        # 404
        else:
            self._send_json({
                "error": "not found",
                "available_endpoints": [
                    "GET /api/health",
                    "GET /api/chains",
                    "GET /api/scan?address=&chain=",
                    "POST /api/scan/batch",
                ]
            }, status=404)
    
    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        
        # 批量扫描
        if path == "/api/scan/batch":
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length == 0:
                self._send_json({
                    "error": "request body is required",
                    "format": {"addresses": ["addr1", "addr2"], "chain": "tron"}
                }, status=400)
                return
            
            try:
                body = json.loads(self.rfile.read(content_length))
            except json.JSONDecodeError:
                self._send_json({"error": "invalid JSON"}, status=400)
                return
            
            addresses = body.get("addresses", [])
            chain = body.get("chain", "tron")
            
            if not addresses:
                self._send_json({"error": "addresses list is required"}, status=400)
                return
            
            result = scan_batch(addresses, chain)
            self._send_json(result)
            return
        
        else:
            self._send_json({"error": "not found"}, status=404)
    
    def log_message(self, format, *args):
        """精简日志 - Agent不需要看人类日志"""
        pass  # 生产环境可注释掉减少输出


def main():
    host = "0.0.0.0"
    port = int(os.environ.get("PORT", 8080))
    
    print(f"[SecureScan v4.0] Agent-first 合约安全扫描服务启动")
    print(f"监听地址: {host}:{port}")
    print(f"支持链: {', '.join(set('tron' if c in ('tron', 'trx') else 'bsc' for c in SUPPORTED_CHAINS.keys()))}")
    print()
    print("API 端点:")
    print("  GET  /api/health              - 健康检查")
    print("  GET  /api/chains              - 支持的链列表")
    print("  GET  /api/scan?address=&chain= - 扫描单个合约")
    print("  POST /api/scan/batch          - 批量扫描")
    print()
    
    server = HTTPServer((host, port), ScanAPIHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n服务已停止")
        server.server_close()


if __name__ == "__main__":
    main()
