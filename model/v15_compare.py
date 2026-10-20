"""Conservative predeclared decisions; pending answers are never treated as correct."""
import hashlib,json,math

def tasks(report):
    return [{'category':r['case']['category'],'expected':r['case'].get('expected',r['case'].get('number')),'users':[m['content'] for m in r['messages'] if m['role']=='user']} for r in report['answers']]

def summary(report):
    answers=report['answers'];grades=[r['grade']['passed'] for r in answers]
    if not answers or any(type(g) is not bool and g is not None for g in grades):raise ValueError('Invalid evaluation grades')
    r=report['report']
    if len(answers)!=r['generationCases'] or sum(g is True for g in grades)!=r['localPass'] or sum(g is False for g in grades)!=r['localFail'] or sum(g is None for g in grades)!=r['pendingSemanticReview']:raise ValueError('Evaluation counts mismatch')
    return {k:r[k] for k in ['generationCases','localPass','localFail','pendingSemanticReview','readableReplies']}

def decision(baseline,control,candidate):
    if tasks(baseline)!=tasks(control) or tasks(baseline)!=tasks(candidate):raise ValueError('V15 evaluations must use identical questions and references')
    base,a,b=map(summary,[baseline,control,candidate]);references=[base,a]
    worse=all((b['localPass']<=r['localPass']-2 and b['localFail']>=r['localFail']+2) or (b['readableReplies']<=r['readableReplies']-4 and b['localFail']>=r['localFail']+3 and b['localPass']<=r['localPass']) for r in references)
    improved=all(b['localPass']>=r['localPass']+2 and b['localFail']<=r['localFail'] and b['readableReplies']>=r['readableReplies'] for r in references)
    unchanged=b==base and b==a
    status='clear-local-regression' if worse else 'local-improvement' if improved else 'no-detected-change' if unchanged else 'mixed-or-unknown'
    return {'protocol':'nebula-v15-comparison-1','status':status,'dataAction':'remove' if worse else 'keep','baseline':base,'filteredControl':a,'fullChatCandidate':b,'humanVerified':False,'qualityApproved':False,'publicWebsiteUpdated':False,
      'reason':'Compare exact passes, explicit failures and readability against BOTH the starting checkpoint and equal-budget filtered control. Require a margin of 2 exact checks or 4 readable replies and 3 failures for regression. Unknown grades remain unknown. Matching aggregate scores do not prove no behavioral change. Data retention is not a release decision.','manualReviewRequired':not worse,'taskSha256':hashlib.sha256(json.dumps(tasks(candidate),sort_keys=True).encode()).hexdigest()}
