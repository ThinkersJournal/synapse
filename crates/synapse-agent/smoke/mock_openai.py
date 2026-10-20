# SPDX-License-Identifier: MIT OR Apache-2.0
"""Stand-in for an OpenAI-compatible chat endpoint: always answers PONG. Stdlib only.
Usage: python mock_openai.py <port>   (serves http://127.0.0.1:<port>/v1/chat/completions)"""
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


class H(BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("content-length", 0)))
        out = json.dumps({
            "id": "x", "object": "chat.completion", "created": 0, "model": "mock",
            "choices": [{"index": 0, "finish_reason": "stop",
                         "message": {"role": "assistant", "content": "PONG"}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        }).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
