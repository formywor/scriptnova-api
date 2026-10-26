"""Read-only, bounded data inspection. Reports counts, never text or approvals."""
import collections,json,re
from vd2_data import texts,clean,category,sha,source_split
from vd2_hub import Hub

def audit_sources(inventory,token=None,max_bytes=512_000_000,max_object_bytes=128_000_000,reader=None):
    if reader is None:
        import requests
        hub=object.__new__(Hub);hub.token=token or '';hub.session=requests.Session()
        reader=hub.read_entry # Does not construct Hub, create a repo or write anything.
    groups={}
    for source in inventory['candidates']:
        groups.setdefault((source['entry']['sha256'],source['format']),[]).append(source)
    records={};reports=[];used=0
    for aliases in sorted(groups.values(),key=lambda a:all(source_split(s)!='validation' for s in a)):
        source=aliases[0];size=source['entry']['bytes']
        split='validation' if any(source_split(s)=='validation' for s in aliases) else 'train'
        report=dict(repo=source['repo'],revision=source['revision'],key=source['key'],aliases=len(aliases),split=split,bytes=size,approved=False)
        if source['format']!='jsonl':report['status']='not_inspected_encoded_tokens'
        elif size>max_object_bytes or used+size>max_bytes:report['status']='not_inspected_byte_budget'
        else:
            used+=size
            try:
                blob=reader(source['repo'],source['revision'],source['entry'])
                counts=collections.Counter();rejected=0;pending={}
                for value in texts(blob,'jsonl'):
                    text=clean(value)
                    if text is None:rejected+=1;continue
                    fingerprint=sha(re.sub(r'\s+',' ',text).encode());kind=category(text);counts[kind]+=1
                    target='validation' if split=='validation' or int(fingerprint[:8],16)%50==0 else 'train'
                    if fingerprint not in pending or target=='validation':pending[fingerprint]=(target,kind)
                # A malformed object must not contribute a partially parsed corpus.
                for fingerprint,value in pending.items():
                    if fingerprint not in records or value[0]=='validation':records[fingerprint]=value
                report.update(status='inspected',counts=dict(counts),rejected=rejected)
                del blob
            except Exception as error:
                # Exception messages may contain signed URLs or example text.
                report.update(status='inspection_failed',errorType=type(error).__name__)
        reports.append(report)
        print(json.dumps({'vd2SourceAudit':report}),flush=True)
    totals=collections.Counter('/'.join(v) for v in records.values())
    result=dict(readOnly=True,objectsMoved=False,trainingStarted=False,sourcesApproved=False,bytesRead=used,
                inspectedObjects=sum(r['status']=='inspected' for r in reports),totalObjects=len(reports),
                uniqueInspectedDocuments=len(records),counts=dict(totals),minimumCodeDocuments=5000,
                inspectedCodeFloorMet=totals['train/code']>=5000,
                note='Code counts are heuristic; provenance, licenses and uninspected objects still require review.',sources=reports)
    print(json.dumps({'vd2AuditSummary':{k:v for k,v in result.items() if k!='sources'}}),flush=True)
    return result
