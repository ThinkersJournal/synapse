"""Windows side of the WSL pilot link: Hyper-V socket -> the daemon's 127.0.0.1 port.

Listens on AF_HYPERV (no TCP listener) for ONE service GUID and pipes each connection to
SYNAPSE_ADDR (default 127.0.0.1:7920). One relay process per lane GUID. Spike code.
usage: python relay_win.py <port-int, e.g. 0x53590001>
"""
import socket, sys, threading, os

WILDCARD = "00000000-0000-0000-0000-000000000000"
TARGET = os.environ.get("SYNAPSE_ADDR", "127.0.0.1:7920")


def service_guid(port: int) -> str:
    # WSL2 maps a guest AF_VSOCK port to this service GUID template.
    return f"{port:08x}-facb-11e6-bd58-64006a7986d3"


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


def main():
    port = int(sys.argv[1], 0)
    host, _, p = TARGET.rpartition(":")
    if host != "127.0.0.1":
        sys.exit("refusing a non-loopback target")
    srv = socket.socket(socket.AF_HYPERV, socket.SOCK_STREAM, socket.HV_PROTOCOL_RAW)
    srv.bind((WILDCARD, service_guid(port)))
    srv.listen(8)
    print("relay listening on", service_guid(port), "->", TARGET, flush=True)
    while True:
        c, _ = srv.accept()
        u = socket.create_connection((host, int(p)), timeout=5)
        u.settimeout(None)
        threading.Thread(target=pipe, args=(c, u), daemon=True).start()
        threading.Thread(target=pipe, args=(u, c), daemon=True).start()


main()
