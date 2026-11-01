import json,pathlib,sys
b=pathlib.Path(__file__).resolve().parent;r=b.parent/'merge-latest-1153-1160/integration';sys.path.insert(0,str(r/'tools'));import node94_weak_pidfd as m
x=m.produce();(b/'weak-pidfd-fresh.json').write_text(json.dumps(x,indent=2)+'\n');old=json.loads((r/m.OUT/'evidence.json').read_text())
diffs=[]
def walk(a,z,p=''):
 if type(a)!=type(z):diffs.append(p+':type');return
 if isinstance(a,dict):
  for k in set(a)|set(z):
   if k not in a or k not in z:diffs.append(p+'/'+k+':missing')
   else:walk(a[k],z[k],p+'/'+k)
 elif isinstance(a,list):
  if len(a)!=len(z):diffs.append(p+':length')
  else:
   for i,(aa,zz)in enumerate(zip(a,z)):walk(aa,zz,p+'/'+str(i))
 elif a!=z:diffs.append(p)
walk(old,x);(b/'weak-pidfd-differences.json').write_text(json.dumps(diffs,indent=2)+'\n');print('differences',len(diffs));print('\n'.join(diffs[:70]))
