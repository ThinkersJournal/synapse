"""Windows side of the WSL pilot link: Hyper-V socket -> the daemon's 127.0.0.1 port.

Listens on AF_HYPERV (no TCP listener) for ONE service GUID and pipes each connection to
SYNAPSE_ADDR (default 127.0.0.1:7920). One relay process per lane GUID. Spike code.

The WSL VM id changes on every WSL boot and a wildcard bind is NOT accepted by the guest's
connect, so the relay finds the running WSL VM itself (`hcsdiag list`) and rebinds when the id
changes. SYNAPSE_RELAY_VMID pins it instead.
usage: python relay_win.py <port-int, e.g. 0x53590001>
"""
import os, re, socket, subprocess, sys, threading, time

TARGET = os.environ.get("SYNAPSE_ADDR", "127.0.0.1:7920")


def service_guid(port: int) -> str:
    # WSL2 maps a guest AF_VSOCK port to this service GUID template.
    return f"{port:08x}-facb-11e6-bd58-64006a7986d3"


def wsl_vm_id():
    pinned = os.environ.get("SYNAPSE_RELAY_VMID")
    if pinned:
        return pinned
    out = subprocess.run(["hcsdiag", "list"], capture_output=True, text=True).stdout
    m = re.search(r"VM,\s*Running,\s*([0-9A-Fa-f-]{36}),\s*WSL\b", out)
    return m.group(1) if m else None


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


def serve(srv, host, port):
    while True:
        try:
            c, _ = srv.accept()
        except OSError:
            return  # closed: the VM id changed
        try:
            u = socket.create_connection((host, port), timeout=5)
        except OSError as e:
            print("daemon unreachable:", e, flush=True)
            c.close()
            continue
        u.settimeout(None)
        threading.Thread(target=pipe, args=(c, u), daemon=True).start()
        threading.Thread(target=pipe, args=(u, c), daemon=True).start()


def main():
    guid = service_guid(int(sys.argv[1], 0))
    host, _, p = TARGET.rpartition(":")
    if host != "127.0.0.1":
        sys.exit("refusing a non-loopback target")
    bound, srv = None, None
    while True:
        vm = wsl_vm_id()
        if vm != bound:
            if srv:
                srv.close()
                srv = None
            bound = vm
            if vm:
                try:
                    srv = socket.socket(socket.AF_HYPERV, socket.SOCK_STREAM, socket.HV_PROTOCOL_RAW)
                    srv.bind((vm, guid))
                    srv.listen(8)
                    threading.Thread(target=serve, args=(srv, host, int(p)), daemon=True).start()
                    print("relay listening: vm", vm, "service", guid, "->", TARGET, flush=True)
                except OSError as e:
                    print("bind failed:", e, flush=True)
                    srv, bound = None, None
            else:
                print("no running WSL VM; waiting", flush=True)
        time.sleep(5)


main()
