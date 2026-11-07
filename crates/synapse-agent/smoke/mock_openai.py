# SPDX-License-Identifier: MIT OR Apache-2.0
"""Stand-in for an OpenAI-compatible chat endpoint. Stdlib only.

Usage: python mock_openai.py <port>   (serves http://127.0.0.1:<port>/v1/chat/completions)

Answers PONG. When the request offers tools and carries no tool result yet, it instead calls
send_message(to="ops", body="TOOLOK"); once a tool result is in the conversation it answers DONE.
That is the whole of what the tool-use smoke needs from a model."""
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


def reply_for(request):
    messages = request.get("messages", [])
    if any(m.get("role") == "tool" for m in messages):
        return {"role": "assistant", "content": "DONE"}, "stop"
    if request.get("tools"):
        call = {"id": "call_1", "type": "function", "function": {
            "name": "send_message",
            "arguments": json.dumps({"to": "ops", "body": "TOOLOK"})}}
        return {"role": "assistant", "content": None, "tool_calls": [call]}, "tool_calls"
    return {"role": "assistant", "content": "PONG"}, "stop"


class H(BaseHTTPRequestHandler):
    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("content-length", 0)))
        try:
            request = json.loads(raw)
        except ValueError:
            request = {}
        message, finish = reply_for(request)
        out = json.dumps({
            "id": "x", "object": "chat.completion", "created": 0, "model": "mock",
            "choices": [{"index": 0, "finish_reason": finish, "message": message}],
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
