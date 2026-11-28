# SPDX-License-Identifier: MIT OR Apache-2.0
# Smoke driver for 2026-11-28-rc271-adapter-swap-steps.md section 6: python -I <this> <channel.exe> <home> <role>
import subprocess,sys,json,threading,time,os,queue
exe=sys.argv[1]; home=sys.argv[2]; role=sys.argv[3]
env=dict(os.environ,SYNAPSE_NO_AUTOSTART="1",SYNAPSE_HOME=home,SYNAPSE_ADDR="127.0.0.1:7961")
p=subprocess.Popen([exe,"--role",role,"--home",home],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,text=True)
q=queue.Queue()
threading.Thread(target=lambda:[q.put(l) for l in p.stdout],daemon=True).start()
threading.Thread(target=lambda:[print("STDERR",l.strip()) for l in p.stderr],daemon=True).start()
def send(o): p.stdin.write(json.dumps(o)+"\n"); p.stdin.flush()
def drain(sec,label):
    t=time.time()+sec; n=[]
    while time.time()<t:
        try: l=q.get(timeout=0.5)
        except queue.Empty: continue
        o=json.loads(l)
        if "method" in o and "channel" in o["method"]:
            n.append(o); print(f"[{label}] NOTIFY",o["method"],json.dumps(o["params"])[:200])
        else: print(f"[{label}] OTHER",l.strip()[:200])
    print(f"[{label}] notifications: {len(n)}"); return n
send({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{"experimental":{"claude/channel":{}}},"clientInfo":{"name":"smoke","version":"0"}}})
time.sleep(1); send({"jsonrpc":"2.0","method":"notifications/initialized"})
first=drain(3,"after-start")
req=os.path.join(home,f"redeliver-{role}.request")
print("request exists before:",os.path.exists(req)); open(req,"w").close(); print("created request #1")
n=drain(4,"after-request-1")
print("request exists after #1:",os.path.exists(req))
mid=first[0]["params"]["meta"]["message_id"]
send({"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"ack","arguments":{"message_id":mid}}})
drain(1,"ack")
open(req,"w").close(); print("created request #2 after acking",mid)
drain(4,"after-request-2")
p.kill()
