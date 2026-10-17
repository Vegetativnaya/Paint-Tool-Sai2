"""Rebuild public-key-free Windows verifier templates using MinGW-w64."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

here=Path(__file__).resolve().parent
parser=argparse.ArgumentParser()
parser.add_argument('--compiler-dir',type=Path)
args=parser.parse_args()
for bits,prefix in [(32,'i686'),(64,'x86_64')]:
    compiler=f'{prefix}-w64-mingw32-gcc-posix'
    if args.compiler_dir:compiler=str(args.compiler_dir/compiler)
    output=here/'bin'/f'gate{bits}.dll'
    subprocess.run([compiler,'-Os','-s','-shared','-static-libgcc','-Wl,--no-insert-timestamp',
                    '-o',str(output),str(here/'native'/'gate.c'),str(here/'native'/'gate.def'),
                    '-ladvapi32','-luser32'],check=True)
manifest={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (here/'bin').glob('*.dll')}
(here/'bin'/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
print(json.dumps(manifest,indent=2))
