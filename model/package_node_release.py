"""Package an exported owned model into bounded upload files; publish manifest last."""
import argparse
import hashlib
import json
from pathlib import Path
import re

def package(artifact,output,version,correct,cases,source_revision='',source_path=''):
    if not re.fullmatch(r'[a-z0-9-]{1,60}',version):raise ValueError('Invalid release version')
    if not 0<=correct<=cases or cases<1:raise ValueError('Invalid diagnostic counts')
    raw=Path(artifact).read_bytes();model=json.loads(raw)
    if not 0<len(raw)<=64*1024*1024 or model.get('format')!=1:raise ValueError('Invalid model export')
    output=Path(output);output.mkdir(parents=True,exist_ok=True);stem='nebula-'+version;shards=[]
    for index,offset in enumerate(range(0,len(raw),8*1024*1024),1):
        name=f'{stem}-{index:02d}.part';path=output/name;temporary=path.with_suffix('.tmp')
        temporary.write_bytes(raw[offset:offset+8*1024*1024]);temporary.replace(path);shards.append(name)
    release={'version':version,'asset':stem+'.json','shards':shards,'bytes':len(raw),
        'sha256':hashlib.sha256(raw).hexdigest(),'parameters':model['metadata']['parameters'],
        'experimental':True,'sourceRevision':source_revision,'sourcePath':source_path,
        'diagnosticCorrect':correct,'diagnosticCases':cases,'automaticPromotion':False}
    temporary=output/'release.tmp';temporary.write_text(json.dumps(release,indent=2),encoding='utf-8');temporary.replace(output/'release.json')
    return release

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifact',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--version',required=True);parser.add_argument('--correct',type=int,required=True);parser.add_argument('--cases',type=int,required=True)
    parser.add_argument('--source-revision',default='');parser.add_argument('--source-path',default='')
    args=parser.parse_args();release=package(args.artifact,args.output,args.version,args.correct,args.cases,args.source_revision,args.source_path)
    print(json.dumps({'version':release['version'],'shards':len(release['shards']),'bytes':release['bytes']}))
