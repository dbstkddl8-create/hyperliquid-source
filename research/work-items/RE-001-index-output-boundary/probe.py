#!/usr/bin/env python3
"""Real pinned node94 CLI probe in disposable private copies; no target execution."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[3]
TARGET=ROOT/'artifacts/node/94/hl-node'
SHA='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SIZE=91774280
COUNT=121299
SOURCES=('elf_index.py','fde_extents.py','artifacts.py')


def sha(raw):return hashlib.sha256(raw).hexdigest()


def probe(revision):
    revision=subprocess.check_output(['git','rev-parse',revision+'^{commit}'],cwd=ROOT,text=True).strip()
    data=TARGET.read_bytes()
    if len(data)!=SIZE or sha(data)!=SHA:raise ValueError('expected complete pinned node94')
    sources={n:subprocess.check_output(['git','show',revision+':tools/'+n],cwd=ROOT) for n in SOURCES}
    # An executable .text byte is changed in a private copy, leaving all ELF/FDE
    # metadata parseable. Never alter or hardlink the imported capture.
    import struct
    shoff=struct.unpack_from('<Q',data,40)[0];width=struct.unpack_from('<H',data,58)[0]
    headers=[struct.unpack_from('<IIQQQQIIQQ',data,shoff+i*width) for i in range(struct.unpack_from('<H',data,60)[0])]
    section=next(s for s in headers if s[1]==1 and s[2]&4 and s[5]>1000000)
    changed_offset=section[4]
    cases=[]
    for tool,prefix,suffixes,field in [('elf_index','node-94-unwind',('.json','.tsv'),'unwind_entries'),('fde_extents','node-94-fde',('.json','.tsv','-gaps.tsv'),'unwind_table_entries')]:
        for case in ['matching','count_without_output','count_existing_output','replaced_after_check']:
            with tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);(root/'tools').mkdir()
                for n,raw in sources.items():(root/'tools'/n).write_bytes(raw)
                rel='artifacts/node/94/hl-node';binary=root/rel;binary.parent.mkdir(parents=True);binary.write_bytes(data)
                (root/'provenance').mkdir()
                (root/'provenance/artifacts.json').write_text(json.dumps({'files':[{'path':rel,'size':SIZE,'sha256':SHA}]}))
                inv=root/'research/imported/hl-node-94.inventory.json';inv.parent.mkdir(parents=True)
                inv.write_text(json.dumps({'fde_count_eh_frame_hdr':COUNT+(1 if case.startswith('count_') else 0)}))
                out=root/'out';before={}
                if case=='count_existing_output':
                    out.mkdir()
                    for suffix in suffixes:
                        p=out/(prefix+suffix);p.write_bytes(b'existing packet sentinel; preserve on rejection\n');before[p.name]=sha(p.read_bytes())
                if case=='replaced_after_check':
                    with (root/'tools/artifacts.py').open('a') as handle:
                        handle.write('\n_original_check = check\ndef check(path, item):\n    _original_check(path, item)\n    data=bytearray(Path(path).read_bytes())\n    Path(path).with_name("checker-accepted.txt").write_text(__import__("hashlib").sha256(data).hexdigest())\n    data['+str(changed_offset)+'] ^= 1\n    Path(path).write_bytes(data)\n')
                result=subprocess.run([sys.executable,'-B',str(root/'tools'/(tool+'.py')),'--release','94','--output-dir',str(out)],capture_output=True,text=True)
                after={p.name:sha(p.read_bytes()) for p in sorted(out.iterdir())} if out.exists() else {}
                summary=json.loads(result.stdout) if result.returncode==0 else None
                row={'tool':tool,'case':case,'returncode':result.returncode,'stdout':result.stdout,'stderr':result.stderr.replace(str(root),'<fixture>'),'output_directory_exists':out.exists(),'before_sha256':before,'after_sha256':after,'prior_outputs_unchanged':before==after if before else None}
                if summary is not None:row.update(reported_count=summary[field],reported_sha256=summary['binary_sha256'])
                if case=='replaced_after_check':
                    row['checker_accepted_sha256']=binary.with_name('checker-accepted.txt').read_text()
                    row['private_replacement_sha256']=sha(binary.read_bytes())
                cases.append(row)
    return {'source_revision':revision,'source_sha256':{n:sha(raw) for n,raw in sources.items()},'target_sha256':SHA,'target_size':SIZE,'retained_correct_count':COUNT,'private_changed_file_offset':changed_offset,'captured_instructions_executed':False,'cases':cases}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--revision',required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();r=probe(a.revision);a.output.write_text(json.dumps(r,indent=2)+'\n')
    print(json.dumps({'cases':len(r['cases']),'revision':a.revision}))
