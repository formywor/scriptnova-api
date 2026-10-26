"""Same bounded tasks for owned byte-100M and subword-250M checkpoints. No code execution."""
import ast,gc,io,json,re,time

def suite():
    cases=[]
    for a,b in [(28,47),(63,19),(107,36),(84,29),(17,8),(91,14),(56,37),(125,42)]:
        cases.append(dict(category='arithmetic',messages=[dict(role='user',content=f'What is {a} + {b}? Reply with only the number.')],number=a+b))
    for color,obj in [('mauve','lantern'),('cobalt','parcel'),('amber','ribbon'),('teal','vase'),('violet','button'),('silver','cup')]:
        cases.append(dict(category='extraction',messages=[dict(role='user',content=f'The {obj} is {color}. What color is the {obj}? Reply with only the color.')],word=color))
    for name in ['Zorivelle','Pemadora','Kivonelle','Talumira']:
        cases.append(dict(category='context',messages=[dict(role='user',content=f'My name is {name}.'),dict(role='assistant',content=f'Hello, {name}.'),dict(role='user',content='What is my name? Reply with only my name.')],word=name))
    for name,task,op in [('total_lumens','returns sum(values)','sum'),('largest_pebble','returns max(values)','max'),('smallest_pebble','returns min(values)','min'),('count_pebbles','returns len(values)','len')]:
        cases.append(dict(category='coding_static',messages=[dict(role='user',content=f'Write Python function {name}(values) that {task}. Return only Python code.')],function=name,call=op))
    for prompt in ['Explain why leaves need sunlight in two sentences.','Write a friendly two-sentence invitation to a picnic.','Explain what a Python list is with a small example.','I have ten minutes to organize my desk. Give three useful steps.']:
        cases.append(dict(category='qualitative',messages=[dict(role='user',content=prompt)]))
    return cases

def grade(case,text):
    if case['category']=='qualitative':return None
    if 'number' in case:
        numbers=re.findall(r'(?<![\w.])-?\d+(?![\w.])',text)
        return len(numbers)==1 and int(numbers[0])==case['number']
    if 'word'in case:return re.search(r'\b'+re.escape(case['word'])+r'\b',text,re.I) is not None
    code=text.strip()
    if '```' in code:
        match=re.search(r'```(?:python|py)?\s*\n(.*?)```',code,re.S)
        if not match:return False
        code=match.group(1)
    try:tree=ast.parse(code)
    except (SyntaxError,ValueError,RecursionError):return False
    for node in tree.body:
        if isinstance(node,ast.FunctionDef) and node.name==case['function']:
            return any(isinstance(n,ast.Return) and isinstance(n.value,ast.Call) and isinstance(n.value.func,ast.Name) and n.value.func.id==case['call'] and len(n.value.args)==1 and isinstance(n.value.args[0],ast.Name) and n.value.args[0].id=='values' for n in ast.walk(node))
    return False

def compare(specs,token='',max_new_tokens=64,read_entry=None):
    import torch
    from tokenizers import Tokenizer
    from vd2_hub import Hub
    from v30_expanded_model import Model,Config,encode_chat
    import requests
    device='cuda:0' if torch.cuda.is_available() else 'cpu';torch.set_num_threads(2);reports=[];tasks=suite()
    reader=object.__new__(Hub);reader.token=token;reader.session=requests.Session();read_entry=read_entry or reader.read_entry
    for spec in specs:
        label=spec['label'];state=spec['state'];key=spec['checkpointKey'];started=time.monotonic()
        print(json.dumps({'comparisonLoading':label,'checkpoint':state[key]['sha256'],'bytes':state[key]['bytes']}),flush=True)
        blob=read_entry(spec['repo'],spec['revision'],state[key]);saved=torch.load(io.BytesIO(blob),map_location='cpu',weights_only=True);del blob
        byte=spec['encoding']=='bytes'
        if byte:
            c=Config(vocab=262,**saved['config']);weights=saved['state'];tokenizer=None
        else:
            c=Config(**saved['config']);weights=saved['model'];tokenizer=Tokenizer.from_str(read_entry(spec['repo'],spec['revision'],state['tokenizer']).decode())
        model=Model(c);model.load_state_dict(weights);del weights,saved;gc.collect()
        model.set_attention_backend('math');model.to(device).eval();count=sum(p.numel() for p in model.parameters());rows=[]
        for index,case in enumerate(tasks):
            if byte:
                roles={'system':258,'user':259,'assistant':260};ids=[256]
                for m in case['messages']:ids+=[roles[m['role']]]+list(m['content'].encode())+[257]
                ids+=[260];eos=257
            else:ids=encode_chat(tokenizer,case['messages'],True)[0];eos=2
            out=[];begin=time.monotonic()
            budget=128 if case['category']=='coding_static' else max_new_tokens
            with torch.inference_mode():
                for _ in range(min(budget,c.context-len(ids))):
                    logits=model(torch.tensor([ids+out],device=device))[0,-1].float()
                    if not torch.isfinite(logits).all():raise ValueError('Nonfinite inference logits')
                    if byte:logits[256]=-float('inf');logits[258:]=-float('inf')
                    else:logits[[0,1,3,4,5,6,7,8]]=-float('inf')
                    next_token=int(logits.argmax())
                    if next_token==eos:break
                    out.append(next_token)
            text=bytes(out).decode('utf-8',errors='replace') if byte else tokenizer.decode(out,skip_special_tokens=True)
            row=dict(index=index,category=case['category'],messages=case['messages'],reply=text,passed=grade(case,text),seconds=round(time.monotonic()-begin,3),generatedTokens=len(out));rows.append(row)
            print(json.dumps({'comparisonCase':label,**row}),flush=True)
        categories={}
        for category in ['arithmetic','extraction','context','coding_static']:
            chosen=[r for r in rows if r['category']==category];categories[category]=dict(passed=sum(r['passed'] for r in chosen),cases=len(chosen))
        report=dict(model=label,parameters=count,device=device,repo=spec['repo'],revision=spec['revision'],checkpoint=state[key]['sha256'],categories=categories,passed=sum(r['passed'] is True for r in rows),scoredCases=sum(r['passed'] is not None for r in rows),qualitativeCases=4,rows=rows,seconds=round(time.monotonic()-started,2),scope='Small task check, not general intelligence. Coding checks syntax/structure only; no generated code executed. No checkpoint promotion or training on these tasks.')
        reports.append(report);print(json.dumps({'comparisonSummary':{k:v for k,v in report.items() if k!='rows'}}),flush=True)
        del model,tokenizer;gc.collect();torch.cuda.empty_cache()
    return reports
