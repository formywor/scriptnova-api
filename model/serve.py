"""Private inference service for NEBULA_MODEL_URL. Host separately from Vercel."""
import argparse
import hmac
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from nebula import load
from rules import with_owner_rules

def make_server(model, key, host='127.0.0.1', port=8001):
    if len(key) < 32: raise ValueError('NEBULA_MODEL_KEY must have at least 32 characters')
    gate = threading.Lock()
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def send_json(self, status, data):
            body = json.dumps(data).encode(); self.send_response(status); self.send_header('Content-Type', 'application/json'); self.send_header('Cache-Control', 'no-store'); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
        def do_GET(self): self.send_json(200 if self.path == '/health' else 404, {'status': 'ready', 'experimental': True} if self.path == '/health' else {'code': 'NOT_FOUND'})
        def do_POST(self):
            if self.path != '/chat': return self.send_json(404, {'code': 'NOT_FOUND'})
            try: length = int(self.headers.get('Content-Length', '0'))
            except ValueError: return self.send_json(400, {'code': 'INVALID_INPUT'})
            if length < 1 or length > 500000: return self.send_json(413, {'code': 'INVALID_INPUT'})
            raw = self.rfile.read(length)
            if not hmac.compare_digest(self.headers.get('Authorization', ''), 'Bearer ' + key): return self.send_json(401, {'code': 'UNAUTHORIZED'})
            if not gate.acquire(blocking=False): return self.send_json(503, {'code': 'BUSY'})
            try:
                if not self.headers.get('Content-Type', '').startswith('application/json'): return self.send_json(415, {'code': 'INVALID_INPUT'})
                body = json.loads(raw)
                if not isinstance(body, dict): raise ValueError()
                messages = body.get('messages')
                if not isinstance(messages, list) or not 1 <= len(messages) <= 201: raise ValueError()
                if any(not isinstance(m, dict) or m.get('role') not in ['system', 'user', 'assistant'] or not isinstance(m.get('content'), str) or len(m['content']) > 100000 for m in messages): raise ValueError()
                if messages[-1]['role'] != 'user': raise ValueError()
                text = model.reply(with_owner_rules(messages))
                if not text: return self.send_json(503, {'code': 'NO_REPLY'})
                self.send_json(200, {'reply': text, 'experimental': True})
            except (ValueError, KeyError, TypeError): self.send_json(400, {'code': 'INVALID_INPUT'})
            except Exception: self.send_json(503, {'code': 'UNAVAILABLE'})
            finally: gate.release()
    server = ThreadingHTTPServer((host, port), Handler); server.daemon_threads = True
    # Prevent slow clients holding request threads forever.
    old = server.get_request
    def get_request():
        sock, address = old(); sock.settimeout(80); return sock, address
    server.get_request = get_request
    return server

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Private experimental Nebula model server. Put behind HTTPS for remote API access.')
    parser.add_argument('--checkpoint', required=True); parser.add_argument('--host', default='127.0.0.1'); parser.add_argument('--port', type=int, default=8001); parser.add_argument('--threads', type=int, default=2)
    args = parser.parse_args()
    import torch
    torch.set_num_threads(max(1, args.threads))
    model, metadata = load(args.checkpoint)
    print(json.dumps({'status': 'experimental model loaded', 'parameters': sum(p.numel() for p in model.parameters()), 'qualityApproved': metadata.get('qualityApproved', False)}), flush=True)
    make_server(model, os.environ.get('NEBULA_MODEL_KEY', ''), args.host, args.port).serve_forever()
