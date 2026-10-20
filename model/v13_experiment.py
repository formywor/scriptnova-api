"""Four-source training fork; old runs and the public website remain untouched."""
import json,os
from pathlib import Path
import torch
from dataflow import read_jsonl,write_jsonl
from kaggle_migrate import restore_data
from research_worker import configure_rules,launch
from research_client import ResearchError
from v10_store import Store
from v6_experiment import compact
from v11_eval import evaluate
from v11_experiment import main as verified_main,sound
from verified_grading import protocol
from v13_data import acquire,merge,SOURCES,atomic_json,digest
from v13_review import review,PROTOCOL as PUBLIC_REVIEW_PROTOCOL

VERSION='nebula-v13-four-sources-1'
RUN='nebula-v13-four-sources'

def use_groq():return os.environ.get('NEBULA_V13_USE_GROQ','false').lower()=='true'

def evaluate_available(checkpoint,legacy,checks,validation,report_path):
    if use_groq():return evaluate(checkpoint,legacy,checks,validation,report_path)
    from verified_grading import Reviewer
    return evaluate(checkpoint,legacy,checks,validation,report_path,reviewer=Reviewer(Path(report_path).parent/'judge-cache.json',key='',max_calls=0))

def initialize(store,project):
    previous=None;old=None
    for name in ['nebula-v12-public','nebula-v11-verified']:
        candidate=Store(store.repo,store.token,name);state=candidate.state()
        if state and state.get('best') and sound(state.get('bestReport',{})):previous=candidate;old=state;break
    if previous is None:raise ResearchError('V13_VERIFIED_SAVED_BEST_REQUIRED')
    source=previous.download(old['sourceData'],project/'source-data.pt');restore_data(source,project);configure_rules(project)
    base=previous.download(old['data'],project/'source-train.jsonl');validation=previous.download(old['validationData'],project/'model/data/fixed-validation.jsonl')
    legacy=previous.download(old['evaluationData'],project/'model/data/legacy.jsonl');checks=previous.download(old['checks'],project/'model/data/checks.json')
    original=previous.download(old['best'],project/'source-best.pt')
    if old.get('judgeCache'):previous.download(old['judgeCache'],project/'judge-cache.json')
    baseline=evaluate_available(original,legacy,checks,validation,project/'source-best-report.json')
    if not sound(baseline):
        if use_groq():raise ResearchError('V13_INITIAL_REVIEW_PENDING_RETRY_LATER')
        baseline={**old['bestReport'],'baselineReportOrigin':'previous saved verified report for these exact source weights'}
    # Preparation has its own private snapshot, so a service failure does not lose downloads/reviews.
    stage=Store(store.repo,store.token,RUN+'-preparation');prepared=stage.state() or {};folder=project/'public-corpus';folder.mkdir(parents=True,exist_ok=True)
    prepared_files=prepared.get('preparationFiles') or {k:v for k,v in prepared.items() if k in {k+s for k in SOURCES for s in ['.json','.jsonl']}|{'manifest.json','public-review-cache.json'}}
    for key,entry in prepared_files.items():
        if key not in {k+suffix for k in SOURCES for suffix in ['.json','.jsonl']}|{'manifest.json','public-review-cache.json'}:raise ResearchError('V13_INVALID_PREPARATION_PATH')
        stage.download(entry,folder/key)
    def backup():
        files={p.name:(p,'public/'+p.name) for p in folder.iterdir() if p.stat().st_size and p.name in {k+s for k in SOURCES for s in ['.json','.jsonl']}|{'manifest.json','public-review-cache.json'}}
        staged=stage.publish({'format':'nebula-v13-preparation-1','publicAutoUpdate':False},files,project)
        staged['preparationFiles']={name:staged[name] for name in files}
        stage.publish(staged,{},project)
        print(json.dumps({'v13PreparationBackupConfirmed':True,'publicWebsiteUpdated':False}),flush=True)
    try:manifest=acquire(folder,on_source=backup)
    except Exception:
        backup();raise ResearchError('V13_PUBLIC_DOWNLOAD_PENDING_RETRY_LATER') from None
    # Remove old records/opening prompts and fixed-validation prompts BEFORE paying for review.
    from v9_data import prompts,canonical
    existing=read_jsonl(base)+read_jsonl(validation);blocked=set().union(*(prompts(r) for r in read_jsonl(validation)));seen={canonical(r['messages']) for r in existing}
    old_first={' '.join(r['messages'][0]['content'].casefold().split()) for r in read_jsonl(base)}
    candidates=[r for r in read_jsonl(folder/'chat.jsonl') if not prompts(r)&blocked and ' '.join(r['messages'][0]['content'].casefold().split()) not in old_first and canonical(r['messages']) not in seen]
    # Prefer conversations over single-turn edits, then use deterministic diverse source order.
    import random
    random.Random(20261018).shuffle(candidates);candidates.sort(key=lambda r:('rewrite' in r['source']['component'],len(r['messages'])==2))
    candidate_path=project/'public-candidates.jsonl';write_jsonl(candidate_path,candidates)
    reviewed=project/'reviewed-public.jsonl'
    cache=folder/'public-review-cache.json'
    if use_groq():
        result=review(candidate_path,reviewed,cache,max_calls=int(os.environ.get('NEBULA_V13_SCREENING_CALLS','400')),target=1000,on_progress=backup)
        if result['accepted']<200:backup();raise ResearchError('V13_PUBLIC_REVIEW_PENDING_RETRY_LATER')
        rows=read_jsonl(reviewed)
    else:
        decisions=json.loads(cache.read_text(encoding='utf-8')) if cache.is_file() else {}
        if decisions and (decisions.get('protocol')!=PUBLIC_REVIEW_PROTOCOL or not isinstance(decisions.get('verdicts'),dict) or any(type(v) is not bool for v in decisions['verdicts'].values())):raise ResearchError('V13_INVALID_PUBLIC_REVIEW_CACHE')
        verdicts=decisions.get('verdicts',{});rows=[]
        for row in candidates:
            if verdicts.get(row['id']) is False:continue
            verified=verdicts.get(row['id']) is True
            row={**row,'approvalMethod':'cached-two-pass-ai-review-not-human-verified' if verified else 'public-structural-filter-not-individually-fact-checked','source':{**row['source'],'semanticReviewComplete':verified,'humanVerified':False}}
            if verified:row['source']['publicReviewProtocol']=PUBLIC_REVIEW_PROTOCOL
            rows.append(row)
        write_jsonl(reviewed,rows)
        if not cache.is_file():atomic_json(cache,{'protocol':PUBLIC_REVIEW_PROTOCOL,'verdicts':{}})
        result={'calls':0,'selected':len(rows),'aiReviewed':sum(r['source'].get('semanticReviewComplete',False) for r in rows),'mode':'local-filters-no-provider-required','humanVerified':False}
        print(json.dumps({'v13ExternalTeachersDisabled':True,'publicChatSelection':result}),flush=True)
    backup()
    for kind in ['cosmopedia','fineweb','stories']:rows.extend(read_jsonl(folder/(kind+'.jsonl')))
    print(json.dumps({'v13InitializationPhase':'merge-and-holdout-filtering','candidates':len(rows)}),flush=True)
    data=project/'model/data/v13-train.jsonl';holdout=project/'model/data/v13-public-heldout.jsonl';summary=merge(base,validation,rows,data,holdout,require_review=use_groq())
    summary['publicReview']=result;summary['acquisition']=manifest
    atomic_json(data.with_suffix('.manifest.json'),summary)
    print(json.dumps({'v13InitializationPhase':'baseline-and-new-public-loss-checks'}),flush=True)
    initial=evaluate_expanded(original,legacy,checks,validation,project/'source-best-report.json')
    if sound(initial):baseline=initial
    elif 'newPublicHeldoutLosses' in initial:baseline={**baseline,'newPublicHeldoutLosses':initial['newPublicHeldoutLosses']}
    anchor=compact(original,project/'anchor.pt');teacher=project/'model/data/teacher.jsonl'
    if old.get('teacherData'):previous.download(old['teacherData'],teacher)
    else:write_jsonl(teacher,[])
    print(json.dumps({'v13InitializationPhase':'license-attribution'}),flush=True)
    licenses=previous.download(old['licenseTexts'],project/'existing-licenses.json');bundle=json.loads(licenses.read_text(encoding='utf-8'))
    # Preserve full dataset cards and licenses captured at pinned source revisions.
    from huggingface_hub import hf_hub_download
    license_folder=project/'public-licenses';license_folder.mkdir(exist_ok=True)
    for kind,spec in SOURCES.items():
        card=Path(hf_hub_download(spec['dataset'],'README.md',repo_type='dataset',revision=manifest[kind]['revision']))
        bundle['V13-'+kind]={'dataset':spec['dataset'],'revision':manifest[kind]['revision'],'license':spec['license'],'source':'https://huggingface.co/datasets/'+spec['dataset'],'datasetCard':card.read_text(encoding='utf-8'),'changes':'Complete passages/answers retained; punctuation normalized; structurally screened and deduplicated. Chat screening mode is recorded per example and in the manifest; no AI verification is claimed for structural-only rows. Not human verified.','terms':'https://opendatacommons.org/licenses/by/1-0/' if spec['license']=='odc-by' else 'https://cdla.dev/sharing-1-0/' if spec['license']=='cdla-sharing-1.0' else 'https://www.apache.org/licenses/LICENSE-2.0','upstreamTerms':'https://commoncrawl.org/terms-of-use' if kind=='fineweb' else None}
    atomic_json(project/'licenses.json',bundle)
    files={'sourceData':(source,'source-data.pt'),'data':(data,'data/train.jsonl'),'validationData':(validation,'data/validation.jsonl'),'evaluationData':(legacy,'data/legacy.jsonl'),'checks':(checks,'data/checks.json'),
      'qualityAnchor':(anchor,'quality-anchor.pt'),'baseline':(compact(original,project/'baseline.pt'),'baseline.pt'),'best':(original,'best.pt'),'working':(original,'working.pt'),
      'teacherData':(teacher,'data/teacher.jsonl'),'licenseTexts':(project/'licenses.json','data/licenses.json'),'dataManifest':(data.with_suffix('.manifest.json'),'data/manifest.json'),
      'newPublicHoldout':(holdout,'data/public-heldout.jsonl'),'publicReviewCache':(folder/'public-review-cache.json','data/public-review-cache.json'),'initialReport':(project/'source-best-report.json','reports/source-best.json')}
    if (project/'judge-cache.json').is_file():files['judgeCache']=(project/'judge-cache.json','evaluation/judge-cache.json')
    state={'format':VERSION,'gradingProtocol':protocol(),'round':0,'rejected':0,'baselineReport':baseline,'bestReport':baseline,'workingReport':baseline,'profile':{'gpus':min(2,torch.cuda.device_count())},'sourceRun':previous.prefix,'sourceRound':old['round'],'teacherNextIndex':old.get('teacherNextIndex',5000),'dataSummary':summary,'publicAutoUpdate':False,'weightsPreserved':True,'newCurriculumOptimizerReset':True}
    print(json.dumps({'v13PublicDataAdded':summary,'source':'verified saved best','previousRunsUntouched':True,'weightsPreserved':True,'publicWebsiteUpdated':False}),flush=True)
    print(json.dumps({'v13InitializationPhase':'save-initial-training-state'}),flush=True)
    store.revision=stage.revision  # Preparation commits advanced this same private repository.
    return store.publish(state,files,project)

def launch_expanded(*args,**kwargs):
    project=Path(args[0]);store=Store(os.environ.get('NEBULA_HF_REPO',''),os.environ.get('NEBULA_HF_TOKEN',''),RUN);state=store.state()
    store.download(state['newPublicHoldout'],project/'model/data/v13-public-heldout.jsonl')
    kwargs['expanded_public']=True
    return launch(*args,**kwargs)

def evaluate_expanded(checkpoint,legacy,checks,validation,report_path):
    report=evaluate_available(checkpoint,legacy,checks,validation,report_path)
    project=Path(report_path).parent;heldout=project/'model/data/v13-public-heldout.jsonl'
    if not heldout.is_file():
        store=Store(os.environ.get('NEBULA_HF_REPO',''),os.environ.get('NEBULA_HF_TOKEN',''),RUN);state=store.state()
        if state and state.get('newPublicHoldout'):store.download(state['newPublicHoldout'],heldout)
    if heldout.is_file():
        import random
        from nebula import load
        from train import evaluate_loss,unique_windows
        from v13_windows import examples
        model,_=load(checkpoint);device=torch.device('cuda' if torch.cuda.is_available() else 'cpu');model.to(device);model.eval()
        losses={};rows=read_jsonl(heldout)
        with torch.no_grad():
            for kind,spec in SOURCES.items():
                windows,_=unique_windows(examples([r for r in rows if r['source']['dataset']==spec['dataset']],model.config.context,True))
                selected=random.Random(13013).sample(windows,min(32,len(windows)))
                if selected:losses[kind]={'loss':evaluate_loss(model,selected,1),'windows':len(selected)}
        report['newPublicHeldoutLosses']=losses;report['newPublicHeldoutIsAdditionalDiagnostic']=True
        del model
        if torch.cuda.is_available():torch.cuda.empty_cache()
        evidence=json.loads(Path(report_path).read_text(encoding='utf-8'));evidence['report']=report
        atomic_json(report_path,evidence);print(json.dumps({'v13AdditionalHeldout':losses,'checkpoint':Path(checkpoint).name}),flush=True)
    return report

def local_safe(base,report):
    """Research continuation only. This never certifies conversational correctness."""
    import math
    fields=['loss','chatLoss','publicChatLoss','languageLoss','health','exactCopyCorrect','contextNameCorrect']
    return (all(type(report.get(k)) in (int,float) and math.isfinite(report[k]) for k in fields)
        and report['loss']<=base['loss']*1.10 and report['publicChatLoss']<=base['publicChatLoss']*1.10
        and report['languageLoss']<=base['languageLoss']*1.10 and report['health']>=base['health']-.10
        and report['exactCopyCorrect']>=base['exactCopyCorrect']-1 and report['contextNameCorrect']>=base['contextNameCorrect']-1
        and all(type(v.get('loss')) in (int,float) and math.isfinite(v['loss']) for v in report.get('newPublicHeldoutLosses',{}).values()))

def save_local_round(store,state,candidates,project,legacy,checks,validation,already_pending=False,evaluate_checkpoint=None):
    """Continue locally measured research while keeping unverified trials out of best."""
    evaluate_fn=evaluate_checkpoint or evaluate_expanded;reports=[];files={}
    for label,path in candidates:
        destination=project/(label+'-report.json');report=evaluate_fn(path,legacy,checks,validation,destination)
        reports.append((label,path,report));files['report-'+label]=(destination,f'reports/{state["round"]+1:04d}-{label}.json')
    if all(sound(r) for _,_,r in reports):
        from v11_experiment import save_assessment
        lookup={str(path):report for _,path,report in reports}
        return save_assessment(store,state,candidates,project,legacy,checks,validation,already_pending,evaluate_checkpoint=lambda path,*_:lookup[str(path)])
    allowed=[entry for entry in reports if local_safe(state['baselineReport'],entry[2])]
    chosen=min(allowed,key=lambda entry:entry[2]['chatLoss']) if allowed else None
    next_state={**state,'round':state['round']+1,'pendingEvaluation':None,'rejected':0 if chosen else state['rejected']+1,'publicAutoUpdate':False,'externalTeachersEnabled':False,'latestNeedsSemanticReview':True}
    if chosen:
        _,path,report=chosen;files['working']=(path,'working.pt');next_state.update(workingReport=report,workingProvisional=True)
    final=next((path for label,path,_ in reports if label=='final'),reports[-1][1]);files['latest']=(compact(final,project/'latest-weights.pt'),'latest.pt')
    cache=project/'judge-cache.json'
    if cache.is_file():files['judgeCache']=(cache,'evaluation/judge-cache.json')
    for key in list(next_state):
        if key.startswith('pendingCandidate'):next_state.pop(key)
    next_state=store.publish(next_state,files,project)
    print(json.dumps({'v13LocalRoundSaved':next_state['round'],'provisionalWorkingContinues':chosen is not None,'semanticReviewRequired':True,'verifiedBestUnchanged':True,'checkpointBackupConfirmed':True,'publicWebsiteUpdated':False}),flush=True)
    return next_state,True

def main(argv=None):
    import sys
    args=list(sys.argv[1:] if argv is None else argv)
    if not use_groq():
        if '--teacher-calls' in args:args[args.index('--teacher-calls')+1]='0'
        else:args+=['--teacher-calls','0']
    return verified_main(args,initialize_run=initialize,version=VERSION,run_name=RUN,launch_training=launch_expanded,evaluate_checkpoint=evaluate_expanded,save_round=None if use_groq() else save_local_round)

if __name__=='__main__':main()
