#!/usr/bin/env python3
"""
SecureScan v5.0 API 服务器
Agent-first 多链智能合约安全扫描器

使用方法:
    python api_server_v5.py [端口]

API接口:
    GET  /api/scan/<chain>/<address>   扫描单个合约
    POST /api/scan/batch                批量扫描
    GET  /api/health                   健康检查
    GET  /api/chains                   支持的链列表
"""

import json
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

from scanner_v50 import scan, scan_batch, generate_report


class ScanAPIHandler(BaseHTTPRequestHandler):
    """API请求处理器"""
    
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        
        if path == "/api/health":
            self._json_response({
                "status": "ok",
                "version": "5.0",
                "timestamp": int(time.time())
            })
        elif path == "/api/chains":
            self._json_response({
                "chains": [
                    {"id": "bsc", "name": "BSC (Binance Smart Chain)", "status": "online"},
                    {"id": "tron", "name": "TRON", "status": "degraded"},
                ]
            })
        elif path.startswith("/api/scan/"):
            # /api/scan/{chain}/{address}
            parts = path.split("/")
            if len(parts) >= 5:
                chain = parts[3]
                address = parts[4]
                
                if chain not in ["tron", "bsc"]:
                    self._json_response({"error": f"不支持的链: {chain}"}, 400)
                    return
                
                try:
                    result = scan(address, chain)
                    # 支持 ?format=markdown 返回人类可读格式
                    if "markdown" in parsed.query or "format=md" in parsed.query:
                        self._text_response(generate_report(result, "markdown"))
                    else:
                        self._json_response(result)
                except Exception as e:
                    self._json_response({"error": str(e)}, 500)
            else:
                self._json_response({"error": "参数错误，格式: /api/scan/{chain}/{address}"}, 400)
        else:
            self._json_response({"error": "Not Found"}, 404)
    
    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        
        if path == "/api/scan/batch":
            try:
                content_len = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(content_len)
                data = json.loads(body)
                
                addresses = data.get("addresses", [])
                chain = data.get("chain", "tron")
                
                if not addresses:
                    self._json_response({"error": "addresses 参数不能为空"}, 400)
                    return
                
                if chain not in ["tron", "bsc"]:
                    self._json_response({"error": f"不支持的链: {chain}"}, 400)
                    return
                
                results = scan_batch(addresses, chain)
                
                if data.get("format") == "markdown":
                    self._text_response(generate_report(results, "markdown"))
                else:
                    self._json_response(results)
            except Exception as e:
                self._json_response({"error": str(e)}, 500)
        else:
            self._json_response({"error": "Not Found"}, 404)
    
    def _json_response(self, data: dict, status: int = 200):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2, ensure_ascii=False).encode('utf-8'))
    
    def _text_response(self, text: str, status: int = 200):
        self.send_response(status)
        self.send_header('Content-Type', 'text/markdown; charset=utf-8')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(text.encode('utf-8'))
    
    def log_message(self, format, *args):
        """重写日志，避免输出太多"""
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {args[0]}")


def run_server(port: int = 8080):
    """启动服务器"""
    server = HTTPServer(('0.0.0.0', port), ScanAPIHandler)
    print(f"SecureScan v5.0 API 服务器已启动")
    print(f"监听端口: {port}")
    print(f"API文档:")
    print(f"  GET  /api/health              健康检查")
    print(f"  GET  /api/chains              支持的链")
    print(f"  GET  /api/scan/{{chain}}/{{address}}  扫描单个合约")
    print(f"  POST /api/scan/batch          批量扫描")
    print(f"  示例: /api/scan/bsc/0x0E09FaBB73Bd3Ade0a17ECC321fD13a19e81cE82")
    print()
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n服务器已停止")
        server.server_close()


if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    run_server(port)
