"""Small-d RSA attack for the deliberately weak κ layer."""
import sys, json, pathlib, math
from collections import defaultdict
from flint import fmpz_mat
from sympy import symbols, Poly, resultant, factor_list
R=pathlib.Path(__file__).resolve().parent
d=json.loads((R/'checkpoint.json').read_text())['bd']; n,e,c=map(int,(d[k] for k in ('n','e','c')))

def mul(a,b):
 o=defaultdict(int)
 for (i,j),v in a.items():
  for (k,l),w in b.items(): o[i+k,j+l]+=v*w
 return dict(o)
def power(a,k):
 o={(0,0):1}
 for _ in range(k):o=mul(o,a)
 return o
def shift(a,i,j,scale): return {(x+i,y+j):v*scale for (x,y),v in a.items()}

# e*d-k*phi=1.  Set x=2k, y=-(p+q)/2, A=(n+1)/2:
# 1+x(A+y) == 0 (mod e).
A=(n+1)//2; f={(0,0):1,(1,0):A,(1,1):1}
delta=.27; m=6; t=2
X=2*int(n**delta); Y=2*int(n**.5)
shifts=[]
for k in range(m+1):
 for i in range(m-k+1): shifts.append(shift(power(f,k),i,0,e**(m-k)))
for k in range(1,m+1):
 for j in range(1,t+1): shifts.append(shift(power(f,k),0,j,e**(m-k)))
mons=sorted(set().union(*[set(s) for s in shifts]))
print('LLL lattice',len(shifts),'x',len(mons),flush=True)
L=fmpz_mat([[s.get(q,0)*X**q[0]*Y**q[1] for q in mons] for s in shifts]).lll(delta=.999)
x,y=symbols('x y')
polys=[]
for row in L.tolist()[:12]:
 expr=sum(int(v)//(X**q[0]*Y**q[1])*x**q[0]*y**q[1] for v,q in zip(row,mons) if v)
 polys.append(Poly(expr,x,y,domain='ZZ'))
print('Extracting common small root',flush=True)
for i in range(len(polys)):
 for j in range(i+1,len(polys)):
  if polys[i].total_degree()<1 or polys[j].total_degree()<1:continue
  res=Poly(resultant(polys[i].as_expr(),polys[j].as_expr(),y),x,domain='ZZ')
  if res.is_zero:continue
  try: fs=factor_list(res.as_expr())[1]
  except Exception: continue
  for fac,ex in fs:
   if Poly(fac,x).degree()!=1:continue
   co=Poly(fac,x).all_coeffs(); num=-int(co[1]); den=int(co[0])
   if num%den:continue
   xx=num//den
   # derive y from the first polynomial by checking its integer roots in y
   for p in (polys[i],polys[j]):
    py=Poly(p.as_expr().subs(x,xx),y,domain='ZZ')
    for fy,_ in factor_list(py.as_expr())[1]:
     q=Poly(fy,y)
     if q.degree()==1:
      cc=q.all_coeffs()
      if -int(cc[1]) % int(cc[0]):continue
      yy=-int(cc[1])//int(cc[0])
      phi=2*(A+yy)
      if phi>0 and (n-phi+1)>0:
       S=n-phi+1; disc=S*S-4*n
       if disc<0:continue
       rt=math.isqrt(disc)
       if rt*rt==disc and (S+rt)%2==0:
        p0=(S+rt)//2
        if n%p0==0:
         private_d=pow(e,-1,phi)
         (R/'bd_result.json').write_text(json.dumps({'n':n,'e':e,'d':private_d,'p':p0}))
         print('FOUND',p0,flush=True); print('D',private_d);sys.exit()
raise RuntimeError('Boneh-Durfee did not find a valid factor with these parameters')
