"""Target weak skill categories, never send frozen probes or user chats to the teacher."""
import re
from v9_data import prompts
from v7_teacher import TASKS,collect as collect_original

def focus_tasks(report):
    tasks=list(TASKS)
    groups=[('conversation',['clarify','rewrite','plan','explain','story','uncertainty','friendly','edit']),('identity',['identity']),('memory',['memory','context','preferences']),('extraction',['context','memory']),('math',['arithmetic'])]
    for metric,names in groups:
        score=report.get(metric,.5)
        weight=max(1,min(4,round((1-score)*4)))
        for name in names:
            match=next((task for task in TASKS if task[0]==name),None)
            if name=='arithmetic':match=('arithmetic','Use small exact arithmetic in an everyday situation, then remember the quantities correctly in a follow-up. Explicitly verify every calculation. Use varied original prompts.')
            if match:tasks.extend([match]*weight)
    return tasks

def factual_checks(row,blocked=()):
    if prompts(row)&set(blocked):return False
    for message in row['messages']:
        if message['role']!='assistant':continue
        for a,b,result in re.findall(r'(?<![\d-])(\d+)\s*\+\s*(\d+)\s*=\s*(-?\d+)',message['content']):
            if int(a)+int(b)!=int(result):return False
    return True

def collect(path,report,blocked=(),**kwargs):
    tasks=focus_tasks(report)
    print(__import__('json').dumps({'teacherTargetingWeakSkills':True,'evaluationPromptsSent':False,'categories':sorted({name for name,_ in tasks})}),flush=True)
    return collect_original(path,tasks=tasks,validator=lambda row:factual_checks(row,blocked),**kwargs)
