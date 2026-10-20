"""Expand complete conversation practice; preserve V11 and its verified selection rules."""
import json,os,time
from pathlib import Path
import torch
from dataflow import write_jsonl,read_jsonl
from kaggle_migrate import restore_data
from research_worker import configure_rules
from research_client import ResearchError
from v10_store import Store
from v6_experiment import compact
from v11_eval import evaluate
from v11_experiment import main as verified_main,sound
from verified_grading import protocol
from v12_data import merge,digest
from v12_review import review

VERSION='nebula-v12-public-1'
RUN='nebula-v12-public'

def initialize(store,project):
    previous=Store(store.repo,store.token,'nebula-v11-verified');old=previous.state()
    if not old or not old.get('best') or not sound(old.get('bestReport',{})):raise ResearchError('V12_VERIFIED_V11_BEST_REQUIRED')
    seed=project/'model/data/v12-public/conversations.jsonl';manifest=project/'model/data/v12-public/manifest.json';license_file=project/'model/data/v12-public/licenses.json'
    if not all(p.is_file() for p in [seed,manifest,license_file]):raise ResearchError('V12_PUBLIC_SEED_REQUIRED')
    seed_manifest=json.loads(manifest.read_text(encoding='utf-8'))
    if seed_manifest.get('sha256')!=digest(seed) or seed_manifest.get('license')!='apache-2.0':raise ResearchError('V12_PUBLIC_SEED_CHECKSUM_OR_LICENSE')
    source=previous.download(old['sourceData'],project/'source-data.pt');restore_data(source,project);configure_rules(project)
    base=previous.download(old['data'],project/'source-train.jsonl');validation=previous.download(old['validationData'],project/'model/data/fixed-validation.jsonl')
    legacy=previous.download(old['evaluationData'],project/'model/data/legacy.jsonl');checks=previous.download(old['checks'],project/'model/data/checks.json')
    original=previous.download(old['best'],project/'source-best.pt')
    if old.get('judgeCache'):previous.download(old['judgeCache'],project/'judge-cache.json')
    baseline=evaluate(original,legacy,checks,validation,project/'source-best-report.json')
    if not sound(baseline):raise ResearchError('V12_INITIAL_REVIEW_PENDING_RETRY_LATER')
    proposed=project/'proposed-train.jsonl';merge(base,validation,seed,proposed)
    candidates=project/'public-candidates.jsonl'
    new_rows=[row for row in read_jsonl(proposed) if row.get('source',{}).get('curriculum')=='v12-conversation']
    new_rows.sort(key=lambda row:('rewrite' in row['source'].get('component',''),row['id']))
    write_jsonl(candidates,new_rows)
    bundled_cache=seed.parent/'screening-cache.json';local_cache=project/'public-review-cache.json'
    if bundled_cache.is_file() and not local_cache.is_file():local_cache.write_bytes(bundled_cache.read_bytes())
    reviewed=project/'reviewed-public.jsonl';review_calls=0
    for attempt in range(4):
        result=review(candidates,reviewed,project/'public-review-cache.json',max_calls=96-review_calls,target=200)
        review_calls+=result['calls']
        if result['accepted']>=200:break
        if not result.get('deferred') or review_calls>=94:break
        if attempt<3:
            print(json.dumps({'v12PublicReviewRetryLater':True,'acceptedSoFar':result['accepted'],'waitSeconds':60}),flush=True);time.sleep(60)
    if result['accepted']<200:raise ResearchError('V12_PUBLIC_REVIEW_PENDING_RETRY_LATER')
    data=project/'model/data/v12-train.jsonl';summary=merge(base,validation,reviewed,data,require_review=True)
    summary['publicReview']=result;data.with_suffix('.manifest.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
    anchor=compact(original,project/'anchor.pt');teacher=project/'model/data/teacher.jsonl'
    if old.get('teacherData'):previous.download(old['teacherData'],teacher)
    else:write_jsonl(teacher,[])
    licenses=previous.download(old['licenseTexts'],project/'existing-licenses.json');license_bundle=json.loads(licenses.read_text(encoding='utf-8'))
    license_bundle['V12-public-conversations']=json.loads(license_file.read_text(encoding='utf-8'))
    (project/'licenses.json').write_text(json.dumps(license_bundle,indent=2),encoding='utf-8')
    files={'sourceData':(source,'source-data.pt'),'data':(data,'data/train.jsonl'),'validationData':(validation,'data/validation.jsonl'),'evaluationData':(legacy,'data/legacy.jsonl'),'checks':(checks,'data/checks.json'),
        'qualityAnchor':(anchor,'quality-anchor.pt'),'baseline':(compact(original,project/'baseline.pt'),'baseline.pt'),'best':(original,'best.pt'),'working':(original,'working.pt'),
        'teacherData':(teacher,'data/teacher.jsonl'),'licenseTexts':(project/'licenses.json','data/licenses.json'),'dataManifest':(data.with_suffix('.manifest.json'),'data/manifest.json'),
        'publicSeedManifest':(manifest,'data/public-seed-manifest.json'),'publicReviewCache':(project/'public-review-cache.json','data/public-review-cache.json'),'initialReport':(project/'source-best-report.json','reports/source-best.json')}
    if (project/'judge-cache.json').is_file():files['judgeCache']=(project/'judge-cache.json','evaluation/judge-cache.json')
    state={'format':VERSION,'gradingProtocol':protocol(),'round':0,'rejected':0,'baselineReport':baseline,'bestReport':baseline,'workingReport':baseline,'profile':{'gpus':min(2,torch.cuda.device_count())},
        'sourceRun':previous.prefix,'sourceRevision':previous.revision,'sourceRound':old['round'],'teacherNextIndex':old.get('teacherNextIndex',4000),'dataSummary':summary,'publicAutoUpdate':False,'weightsPreserved':True,'newCurriculumOptimizerReset':True}
    print(json.dumps({'v12PublicDataAdded':summary,'source':'V11 saved best','previousRunsUntouched':True,'weightsPreserved':True,'optimizer':'fresh for changed dataset and anchor; compatible V12 resumes restore it','publicWebsiteUpdated':False}),flush=True)
    return store.publish(state,files,project)

def main(argv=None):return verified_main(argv,initialize_run=initialize,version=VERSION,run_name=RUN)

if __name__=='__main__':main()
