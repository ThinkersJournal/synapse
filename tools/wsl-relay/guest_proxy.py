"""Linux side of the WSL pilot link: per-lane Unix socket -> host over AF_VSOCK (CID 2).

Run OUTSIDE the sandbox as the proxy user; bind-mount the socket into the sandbox, where a
second instance of this script (--tcp) serves the sandbox-private 127.0.0.1:7920 for the
unchanged client. Spike code.
usage: guest_proxy.py unix <path> <vsock-port>     # outside the sandbox
       guest_proxy.py tcp  <unix-path>             # inside, listens on 127.0.0.1:7920
"""
import os, socket, sys, threading

def pipe(a, b):
    try:
        while (d := a.recv(65536)):
            b.sendall(d)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

def serve(srv, dial):
    srv.listen(8)
    while True:
        c, _ = srv.accept()
        try:
            u = dial()
        except OSError as e:
            print("dial failed:", e, flush=True)
            c.close()
            continue
        threading.Thread(target=pipe, args=(c, u), daemon=True).start()
        threading.Thread(target=pipe, args=(u, c), daemon=True).start()

mode = sys.argv[1]
if mode == "unix":
    path, port = sys.argv[2], int(sys.argv[3], 0)
    if os.path.exists(path):
        os.unlink(path)
    s = socket.socket(socket.AF_UNIX)
    s.bind(path)
    os.chmod(path, 0o600)
    def dial():
        v = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        v.connect((socket.VMADDR_CID_HOST, port))
        return v
    serve(s, dial)
else:
    path = sys.argv[2]
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 7920))
    def dial():
        u = socket.socket(socket.AF_UNIX)
        u.connect(path)
        return u
    serve(s, dial)
