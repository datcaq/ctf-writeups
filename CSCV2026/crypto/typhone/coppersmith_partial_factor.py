"""Factor λ's RSA modulus from the published upper half of p."""
import json, pathlib, math, hashlib
from flint import fmpz_mat
from sympy import symbols, Poly, factor_list
from Crypto.Cipher import AES
R=pathlib.Path(__file__).resolve().parent
bd=json.loads((R/'checkpoint.json').read_text())['bd']; n,e,c=map(int,(bd[k] for k in ('n','e','c')))
recovered=json.loads((R/'bd_result.json').read_text())
assert (recovered['n'], recovered['e']) == (n,e), 'RSA result belongs to another instance'
db=pow(c, recovered['d'], n)
key_bd=hashlib.sha256(db.to_bytes(16,'big')).digest()[:16]
out=json.loads((R/'output_typhon.txt').read_text()); o=out['λ']['Φ']
ld=json.loads(AES.new(key_bd,AES.MODE_GCM,nonce=bytes.fromhex(o['N'])).decrypt_and_verify(bytes.fromhex(o['C']),bytes.fromhex(o['T'])))
N=int(ld['n']); base=int(ld['p_top'])<<128
# Guess eight missing high bits, leaving a root below N^(1/4).
X=1<<120; m=t=16; dim=m+t; x=symbols('x')
for guess in range(256):
    a=base+(guess<<120); rows=[]
    for i in range(m):
        rows.append([N**(m-i)*math.comb(i,j)*a**(i-j)*X**j if j<=i else 0 for j in range(dim)])
    fm=[math.comb(m,j)*a**(m-j) for j in range(m+1)]
    for sh in range(t):
        rows.append([fm[j-sh]*X**j if sh<=j<=m+sh else 0 for j in range(dim)])
    L=fmpz_mat(rows).lll(delta=.999)
    for row in L.tolist()[:4]:
        poly=Poly(sum(int(v)//X**j*x**j for j,v in enumerate(row) if v),x,domain='ZZ')
        for fac,_ in factor_list(poly.as_expr())[1]:
            q=Poly(fac,x)
            if q.degree()==1:
                cc=q.all_coeffs(); num=-int(cc[1]); den=int(cc[0])
                if num % den: continue
                low=num//den; p=a+low
                if 0 <= low < X and N%p==0:
                    print('FOUND',p,flush=True)
                    key_cop=hashlib.sha256(p.to_bytes(32,'big')).digest()[:16]
                    state=json.loads((R/'checkpoint.json').read_text())
                    master=hashlib.sha256(
                        bytes.fromhex(state['kL'])+bytes.fromhex(state['kP'])+
                        bytes.fromhex(state['kS'])+bytes.fromhex(state['key_cc'])+
                        bytes.fromhex(state['key_rat'])+key_bd+key_cop
                    ).digest()
                    omega=out['Ω']; flag=AES.new(master,AES.MODE_GCM,nonce=bytes.fromhex(omega['N'])).decrypt_and_verify(bytes.fromhex(omega['C']),bytes.fromhex(omega['T']))
                    print('FLAG',flag.decode(),flush=True)
                    raise SystemExit
    if guess%16==0: print('guess',guess,flush=True)
raise RuntimeError('Coppersmith did not find a valid factor with these parameters')
