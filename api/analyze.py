"""Vercel serverless function: POST /api/analyze  {"text": "..."} -> JSON risk report.
Pure Python (stdlib only): rule engine + ML model loaded from _model.json."""
import json, os, sys
from http.server import BaseHTTPRequestHandler

sys.path.insert(0, os.path.dirname(__file__))
from _core import full_analysis

with open(os.path.join(os.path.dirname(__file__), "_model.json")) as f:
    MODEL = json.load(f)

class handler(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        self._send(200, {"status": "ok", "model_classes": MODEL["classes"]})

    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
            text = json.loads(self.rfile.read(n) or b"{}").get("text", "")[:2000].strip()
            if not text:
                return self._send(400, {"error": "No text supplied"})
            self._send(200, full_analysis(text, MODEL))
        except Exception as e:
            self._send(500, {"error": str(e)})
