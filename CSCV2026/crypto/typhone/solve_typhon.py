import sys, pathlib, json, hashlib, math, re, ast
ROOT = pathlib.Path(__file__).resolve().parent
from Crypto.Cipher import AES
from sympy import integer_nthroot, factorint, discrete_log
from sympy.ntheory.modular import crt

src = ast.parse((ROOT / 'challenge_typhon.py').read_text())
safe = []
for node in src.body:
    if isinstance(node, ast.FunctionDef) and node.name in ['_add','_mul','_sc','sp','sha_ext']:
        safe.append(node)
    elif isinstance(node, ast.Assign) and all(isinstance(t, ast.Name) and t.id in ['EP','EN','EGx','EGy','SK','rr'] for t in node.targets):
        safe.append(node)
import struct
exec(compile(ast.Module(body=safe, type_ignores=[]), '<crypto helpers>', 'exec'))
out = json.loads((ROOT / 'output_typhon.txt').read_text())
def h(b): return hashlib.sha256(b).digest()[:16]
def dec(key, obj):
    return AES.new(key, AES.MODE_GCM, nonce=bytes.fromhex(obj['N'])).decrypt_and_verify(bytes.fromhex(obj['C']), bytes.fromhex(obj['T']))
def layer(name, key, js=True):
    b = dec(key, out[name]['Φ'])
    print('Verified layer', name, flush=True)
    (ROOT / ('layer_' + name + '.txt')).write_bytes(b)
    return json.loads(b) if js else b

M=out['α']['M']; xs=out['α']['out']
a=(xs[2]-xs[1])*pow(xs[1]-xs[0],-1,M)%M
c=(xs[1]-a*xs[0])%M
assert all((a*x+c)%M==y for x,y in zip(xs,xs[1:]))
k0=h(((a*xs[-1]+c)%M).to_bytes(16,'big'))
b=layer('α',k0,False)
ns=[int.from_bytes(b[i:i+16],'big') for i in range(0,48,16)]
cs=[int.from_bytes(b[i:i+16],'big') for i in range(48,96,16)]
s1,exact=integer_nthroot(int(crt(ns,cs)[0]),3); assert exact
gd=layer('γ',h(int(s1).to_bytes(15,'big')))
# GCM nonce reuse reveals the first 64 LFSR output bits directly.
lf=bytes(x^y^z for x,y,z in zip(bytes.fromhex(gd['c1']),bytes.fromhex(gd['c2']),bytes.fromhex(gd['p1'])))[:8]
bits=[(v>>i)&1 for v in lf for i in range(7,-1,-1)]
state=sum(bits[i]<<i for i in range(32))
def lb():
    global state
    b=state&1
    fb=((state>>31)^(state>>29)^(state>>25)^(state>>23))&1
    state=(state>>1)|(fb<<31)
    return b
assert [lb() for _ in range(64)] == bits
kL=int(''.join(str(lb()) for _ in range(128)),2).to_bytes(16,'big')
pd=layer('δ',kL)
p,g,y=(pd[k] for k in ['ph_p','ph_g','ph_h'])
print('Factoring group order',flush=True)
fac=factorint(p-1); print('p-1 =',fac,flush=True)
mods=[]; residues=[]
for q,e in fac.items():
    m=int(q**e)
    residues.append(int(discrete_log(p,pow(y,(p-1)//m,p),pow(g,(p-1)//m,p),order=m)))
    mods.append(m)
x=int(crt(mods,residues)[0]); assert pow(g,x,p)==y
kP=x.to_bytes(16,'big')
zd=layer('ζ',h(kP))
kS=sha_ext(zd['sha_mac'],zd['secret_len'],bytes.fromhex(zd['sha_msg']),b'::uid=root::op=exec')[:16]
cc=layer('η',h(kS),False).decode()
hosts=['alpha','bravo','charlie','delta','echo','foxtrot','golf','hotel','india','juliet','kilo','lima','mike','november','oscar','papa']
beacons={host:int(b) for b,host in re.findall(r'BEACON #(\d+) ws-(\w+)',cc)}
key_cc=bytes(beacons[host] for host in hosts)
rat=layer('θ',h(key_cc))
names=['keylogger','screencap','filegrab','shellexec','clipboard','browser_stealer','credential_dump','network_scan','lateral_move','persistence','exfil','c2_rotate','av_evasion','process_inject','memory_scan','log_wipe']
modules={m['name']:m['interval'] for m in rat['modules']}
key_rat=bytes(modules[n] for n in names)
tx=layer('ι',h(key_rat))
tb=dec(kS,dict(N=tx['tx_nonce'],C=tx['tx_ct'],T=tx['tx_tag']))
TX=[tuple(int.from_bytes(tb[i+j:i+j+32],'big') for j in (0,32,64)) for i in range(0,len(tb),96)]
# Hidden-number problem: k_i = u_i + t_i*d (mod n), with 0 <= k_i < 2^128.
# The embedding below balances n*k_i against 2^128*d, then LLL exposes d.
from flint import fmpz_mat
B=1<<128; n=EN; m=len(TX)
t=[r*pow(s,-1,n)%n for r,s,z in TX]
u=[z*pow(s,-1,n)%n for r,s,z in TX]
rows=[]
for i in range(m):
    row=[0]*(m+2); row[i]=n*n; rows.append(row)
rows.append([n*v for v in t]+[B,0])
rows.append([n*v for v in u]+[0,n*B])
print('Running LLL on ECDSA nonce lattice',flush=True)
L=fmpz_mat(rows).lll(delta=0.99)
de=None
for row in L.tolist():
    if abs(row[-1])==n*B and row[m]%B==0:
        sign=1 if row[-1]>0 else -1
        cand=(sign*row[m]//B)%n
        if _mul(cand,(EGx,EGy))==(out['pub']['Qx'],out['pub']['Qy']): de=int(cand); break
assert de is not None, 'ECDSA lattice did not yield private key'
print('Recovered ECDSA private key',flush=True)
kd=layer('κ',h(de.to_bytes(32,'big')))
(ROOT/'checkpoint.json').write_text(json.dumps(dict(kL=kL.hex(),kP=kP.hex(),kS=kS.hex(),key_cc=key_cc.hex(),key_rat=key_rat.hex(),de=hex(de),bd=kd)))
