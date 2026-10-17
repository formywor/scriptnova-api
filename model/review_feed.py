"""A fresh private API read each round. No replay of cached withdrawn data."""
import json
from dataflow import eligible,example_id,write_jsonl
from nebula import encode
from rules import with_owner_rules
from v4_data import exercises,forbidden,blocked_questions
from research_client import ResearchError

def validated_rows(rows):
    _,checks=exercises();blocked=blocked_questions(checks);result=[];seen=set()
    for row in rows[:64]:
        source=row.get('source',{}) if isinstance(row,dict) else {}
        if not isinstance(source,dict):continue
        if source.get('kind')!='teacher' or source.get('curriculum')!='v6-reviewed' or source.get('validation')!='two-pass-review-v1' or not eligible(row):continue
        messages=row['messages']
        if len(messages)!=2 or len(encode(with_owner_rules(messages))[0])>1024 or forbidden(row,checks,blocked):continue
        identifier=example_id(messages)
        if identifier in seen:continue
        seen.add(identifier);result.append({**row,'id':identifier})
    return result

def refresh_reviews(client,path):
    # Erase previous round's feed before accessing the service.
    write_jsonl(path,[])
    try:
        value=client.call('review-training')
        if not isinstance(value,dict) or value.get('format')!='nebula-reviewed-training-1' or value.get('requiresFreshConsent') is not True or not isinstance(value.get('rows'),list):raise ResearchError('REVIEW_FEED_INVALID')
        rows=validated_rows(value['rows']);write_jsonl(path,rows)
        print(json.dumps({'reviewTrainingFeedAvailable':True,'checkedReviewExamples':len(rows),'cachedUserDataReused':False}),flush=True)
        return len(rows)
    except (ResearchError,ValueError,KeyError,TypeError):
        print(json.dumps({'reviewTrainingFeedAvailable':False,'checkedReviewExamples':0,'cachedUserDataReused':False}),flush=True);return 0
