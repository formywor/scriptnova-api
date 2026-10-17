"""Download a bounded, cached public training sample; never call teacher APIs."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import time
from urllib.parse import urlencode
from urllib.request import Request, urlopen

SOURCES = {
    'everyday': {'dataset':'HuggingFaceTB/everyday-conversations-llama3.1-2k','config':'default','split':'train_sft','license':'apache-2.0','author':'Hugging Face'},
    'magpie': {'dataset':'HuggingFaceTB/smoltalk','config':'smol-magpie-ultra','split':'train','license':'apache-2.0','author':'HuggingFaceTB'},
}

def fetch_page(source, offset, length, cache, transport=None):
    path = cache / f'{offset}-{length}.json'
    if path.exists(): return json.loads(path.read_text(encoding='utf-8'))
    query = urlencode({k:source[k] for k in ['dataset','config','split']} | {'offset':offset,'length':length})
    url = 'https://datasets-server.huggingface.co/rows?' + query
    if transport: value = transport(url)
    else:
        for attempt in range(3):
            try:
                with urlopen(Request(url,headers={'User-Agent':'Nebula-Public-Data/1.0'}),timeout=45) as response:
                    raw = response.read(12000001)
                    if len(raw)>12000000: raise ValueError('Dataset page too large')
                    value = json.loads(raw)
                break
            except Exception:
                if attempt == 2: raise
                time.sleep(2 ** attempt)
    if not isinstance(value.get('rows'),list): raise ValueError('Invalid dataset page')
    cache.mkdir(parents=True,exist_ok=True)
    temporary=path.with_suffix('.tmp'); temporary.write_text(json.dumps(value),encoding='utf-8'); temporary.replace(path)
    return value

def convert(item, source, index):
    messages = item.get('messages')
    if not isinstance(messages,list) or not 2<=len(messages)<=12 or len(messages)%2: return None
    if any(not isinstance(m,dict) or m.get('role')!=('user' if i%2==0 else 'assistant') or not isinstance(m.get('content'),str) or not m['content'].strip() or len(m['content'])>16000 for i,m in enumerate(messages)): return None
    # Identity boilerplate from a teacher is unsuitable as Nebula's identity training.
    text=' '.join(m['content'].lower() for m in messages if m['role']=='assistant')
    if any(phrase in text for phrase in ['i am chatgpt','i\'m chatgpt','i am llama','i\'m llama','i am gemini','i\'m gemini']): return None
    from dataflow import redact
    messages=[{'role':m['role'],'content':redact(m['content'])} for m in messages]
    identifier=hashlib.sha256(json.dumps(messages,sort_keys=True).encode()).hexdigest()
    return {'id':identifier,'reviewStatus':'approved','approvalMethod':'public-dataset-structural-filter-unverified','messages':messages,'source':{'kind':'public','dataset':source['dataset'],'subset':source['config'],'license':source['license'],'recordId':identifier,'rowIndex':index,'url':'https://huggingface.co/datasets/'+source['dataset']}}

def download(output, everyday=2260, magpie=5000, transport=None):
    from dataflow import write_jsonl
    if not 0<=everyday<=2260 or not 0<=magpie<=20000: raise ValueError('Bounded download requires 0-2260 everyday and 0-20000 magpie rows')
    output=Path(output); output.mkdir(parents=True,exist_ok=True)
    rows=[]; seen=set(); counts={}
    for name,limit in [('everyday',everyday),('magpie',magpie)]:
        source=SOURCES[name]; offset=0; accepted=0
        while offset<limit:
            page=fetch_page(source,offset,min(100,limit-offset),output/'public-cache'/name,transport)
            entries=page['rows']
            if not entries: break
            for entry in entries:
                # Dataset viewer may truncate large cells; never train their partial text.
                if entry.get('truncated_cells'): continue
                row=convert(entry.get('row',{}),source,entry.get('row_idx',offset))
                if row and row['id'] not in seen: seen.add(row['id']); rows.append(row); accepted+=1
            offset+=len(entries)
            print(json.dumps({'publicDataset':name,'scanned':offset,'accepted':accepted}),flush=True)
            if offset>=page.get('num_rows_total',limit): break
        counts[name]=accepted
    if not rows: raise ValueError('No valid public examples downloaded')
    write_jsonl(output/'public-conversations.jsonl',rows)
    manifest={'sources':list(SOURCES.values()),'counts':counts,'conversations':len(rows),'trainingDataSha256':hashlib.sha256((output/'public-conversations.jsonl').read_bytes()).hexdigest(),'changes':['Removed malformed, duplicate and truncated records','Redacted likely contact details and credentials','Rejected selected foreign identity boilerplate'],'quality':'Not individually reviewed; public examples can contain mistakes.'}
    (output/'public-sources.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    print(json.dumps(manifest),flush=True)
    return manifest

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',default=str(Path(__file__).resolve().parent/'data'))
    parser.add_argument('--everyday',type=int,default=2260); parser.add_argument('--magpie',type=int,default=5000)
    args=parser.parse_args()
    try: download(args.output,args.everyday,args.magpie)
    except KeyboardInterrupt: sys.exit('Stopped; downloaded pages are cached. Rerun to continue.')
    except Exception as error: sys.exit('Public download failed ('+type(error).__name__+'). Cached pages are preserved; rerun to retry.')
