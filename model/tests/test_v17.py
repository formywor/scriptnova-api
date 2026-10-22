import ast
import contextlib
import copy
import io
import json
import random
import tempfile
import hashlib
import shutil
import unittest
from pathlib import Path
from unittest.mock import patch
import torch
from nebula import Nebula,Config,load,save,EOS
from v17_data import curriculum,pair_split,public_pools,Pool,training_batch,HELD_ORDER,NAMES,COLORS
from v17_train import fit,evaluate
from v17_lab import DEFAULT,validate,main


class V17Tests(unittest.TestCase):
    def setUp(self):torch.set_num_threads(2)
    def temporary(self):return tempfile.TemporaryDirectory(dir=Path(__file__).parent)
    def test_independent_axes_and_reserved_pairs_openings_and_values(self):
        data=curriculum(1000,17017,12)
        self.assertEqual(data, curriculum(1000,17017,12))
        openings={r['messages'][0]['content'] for r in data['training']}
        self.assertTrue(all(pair_split(*r['pair'])>=2 for r in data['training']))
        self.assertTrue(all(pair_split(*r['pair'])==1 for r in data['validation']))
        self.assertTrue(all(tuple(r['order'])!=HELD_ORDER for r in data['training']))
        self.assertFalse(openings & {r['messages'][0]['content'] for r in data['tests']})
        self.assertEqual({r['axis'] for r in data['tests']},{'new_combinations','new_values','new_wording','field_order','multi_turn','updated_facts'})
        for row in data['tests']:
            if row['axis']=='new_combinations':self.assertEqual(pair_split(*row['pair']),0)
            if row['axis']=='field_order':self.assertEqual(tuple(row['order']),HELD_ORDER)
        self.assertTrue(any(len(r['messages'])==4 for r in data['training']))

    def test_public_overlap_and_whole_record_split(self):
        def row(i,kind):return {'messages':[{'role':'user','content':f'Question {i}.'},{'role':'assistant','content':f'Public answer {i}.'}],
            'source':{'kind':'public','dataset':'test','license':'test-license','recordId':str(i),'curriculum':kind}}
        texts=[row(i,'v13-language') for i in range(30)]
        chats=[row(i,'v13-conversation') for i in range(30)]
        # Duplicate source identities and openings must be blocked even with changed answers.
        copy_chat=copy.deepcopy(chats[25]);copy_chat['messages'][1]['content']='Different answer.'
        result=public_pools(texts,texts[25:],chats+[copy_chat],chats[25:],100,[])
        self.assertEqual(len(result['language']),25);self.assertEqual(len(result['public']),25)
        with self.assertRaises(ValueError):public_pools(texts,texts,chats,chats,100,[])

    def test_full_raw_targets_eos_and_measured_80_20_update_mix(self):
        raw={'messages':[{'role':'user','content':'Read.'},{'role':'assistant','content':'A complete document. '*80}]}
        pool=Pool([raw],64,True)
        learned=[int(t) for _,y in pool.get(0) for t in y if int(t)!=-100]
        self.assertEqual(learned,list(raw['messages'][1]['content'].encode())+[EOS])
        class Fixed:
            def sample(self,rng):return 'example'
        pools={k:Fixed() for k in ['language','context','public']}
        keys=[training_batch(pools,'conversation',2,i,17,80)[1] for i in range(100)]
        self.assertEqual(keys.count('public'),80);self.assertEqual(keys.count('context'),20)

    def test_resume_is_exact_and_signature_changes_are_rejected(self):
        with self.temporary() as d,contextlib.redirect_stdout(io.StringIO()):
            root=Path(d);rules=root/'rules.json';rules.write_text(json.dumps({'instructions':['You are Nebula.']}))
            with patch.dict('os.environ',{'NEBULA_RULES_FILE':str(rules)}):
                torch.manual_seed(17);model=Nebula(Config(width=32,heads=2,layers=1,context=256));save(model,root/'initial.pt',{})
                data=curriculum(100,17017,2);pools={'context':Pool(data['training'],256)}
                plan=copy.deepcopy(DEFAULT);plan.update(batch=2,microbatch=1,localSaveEvery=2,cloudSaveEvery=2);plan['steps']['context']=4
                full,_=load(root/'initial.pt');a=fit(full,pools,'context',root/'full.pt',plan=plan)
                class Pause(Exception):pass
                def stop(*args):raise Pause()
                part,_=load(root/'initial.pt')
                with self.assertRaises(Pause):fit(part,pools,'context',root/'part.pt',plan=plan,callback=stop)
                resumed,_=load(root/'part.pt');b=fit(resumed,pools,'context',root/'resumed.pt',plan=plan,resume=root/'part.pt')
                self.assertEqual(a['inputPositions'],b['inputPositions']);self.assertEqual(a['supervisedTokens'],b['supervisedTokens'])
                for x,y in zip(full.parameters(),resumed.parameters()):self.assertTrue(torch.equal(x,y))
                changed=copy.deepcopy(plan);changed['learningRates']['context']*=2
                with self.assertRaisesRegex(ValueError,'CONFIG_CHANGED'):
                    fit(resumed,pools,'context',root/'invalid.pt',plan=changed,resume=root/'part.pt')

    def test_followup_uses_generated_history_and_open_answers_remain_pending(self):
        class Model:
            def __init__(self):self.histories=[]
            def eval(self):return self
            def parameters(self):yield torch.tensor(1.)
            def reply(self,messages,**kw):self.histories.append(messages);return 'wrong'
        case={'axis':'multi_turn','messages':[{'role':'user','content':'Name: Ada. Give only the name.'},{'role':'assistant','content':'Ada'}],
              'followup':{'prompt':'Where?','expected':'attic'}}
        with self.temporary() as d,contextlib.redirect_stdout(io.StringIO()):
            path=Path(d)/'rules.json';path.write_text(json.dumps({'instructions':['You are Nebula.']}))
            with patch.dict('os.environ',{'NEBULA_RULES_FILE':str(path)}),patch('v17_train.completion',return_value={'grade':'pending'}):
                model=Model();result=evaluate(model,[case])
        self.assertEqual(model.histories[1][-2]['content'],'wrong')
        self.assertEqual(result['summary']['exactCorrect'],0)
        self.assertTrue(all(r['grade']=='pending-human-review' for r in result['openAnswers']))

    def test_configuration_validation_and_notebook_settings_current_sources(self):
        validate(copy.deepcopy(DEFAULT))
        for field,value in [('microbatch',100),('conversationPercent',101),('arms',['current','current'])]:
            plan=copy.deepcopy(DEFAULT);plan[field]=value
            with self.assertRaises(ValueError):validate(plan)
        from build_v17_colab import build
        root=Path(__file__).parents[1];nb=json.loads(build().read_text(encoding='utf-8'))
        code=[''.join(c['source']) for c in nb['cells'] if c['cell_type']=='code']
        self.assertIn("userdata.get('NEBULA_HF_TOKEN')",code[0]);self.assertNotIn('drive.mount',code[0])
        settings={};exec(code[1].split('project=')[0],settings)
        self.assertEqual(settings['CONFIG'],DEFAULT)
        embedded=ast.literal_eval(ast.parse(code[2]).body[0].value)
        self.assertIn('nebula-rules.json',embedded)
        for name,text in embedded.items():
            self.assertEqual(text,(root.parent/name).read_text(encoding='utf-8'))
            if name.endswith('.py'):ast.parse(text)
        for c in nb['cells']:
            if c['cell_type']=='code':ast.parse(''.join(c['source']));self.assertEqual(c['outputs'],[])

    def test_complete_staged_lab_with_private_store_double_and_cpu_models(self):
        # Exercise the controller, manifest transitions and source protection without a real cloud/GPU.
        with self.temporary() as folder,contextlib.redirect_stdout(io.StringIO()):
            root=Path(folder);project=root/'project';project.mkdir();remote=root/'remote';remote.mkdir()
            (project/'nebula-rules.json').write_text(json.dumps({'instructions':['You are Nebula.']}))
            states={};uploads=[]
            class LocalStore:
                def __init__(self,repo,token,run):self.run=run;self.repo=repo;self.token=token;self.revision='test-revision'
                def state(self):return copy.deepcopy(states.get(self.run))
                def download(self,entry,path):
                    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
                    if Path(entry['path']).resolve()!=path.resolve():shutil.copyfile(entry['path'],path)
                    return path
                def publish(self,state,files,project):
                    result=copy.deepcopy(state)
                    names=[name for _,name in files.values()]
                    if len(names)!=len(set(names)):raise AssertionError('Duplicate remote commit path')
                    for key,(local,name) in files.items():
                        target=remote/self.run/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(local,target)
                        result[key]={'path':str(target),'sha256':hashlib.sha256(target.read_bytes()).hexdigest()}
                    states[self.run]=copy.deepcopy(result);uploads.append((self.run,set(files)))
                    return result
            def entry(path):return {'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
            torch.manual_seed(17);save(Nebula(Config(width=32,heads=2,layers=1,context=512)),root/'source.pt',{})
            original_hash=entry(root/'source.pt')['sha256']
            states['nebula-v15-full-chats']={'fullWeights':entry(root/'source.pt')}
            state={}
            for name,kind,offset,count in [('foundationData','v13-language',0,25),('foundationValidation','v13-language',100,5),
                                            ('conversationData','v13-conversation',200,25),('conversationValidation','v13-conversation',300,5)]:
                rows=[{'messages':[{'role':'user','content':f'Question {i}.'},{'role':'assistant','content':f'A complete answer for fixture {i}.'}],
                       'source':{'kind':'public','dataset':'fixture','license':'fixture','recordId':str(i),'curriculum':kind}}
                       for i in range(offset,offset+count)]
                path=root/(name+'.jsonl');path.write_text(''.join(json.dumps(r)+'\n' for r in rows));state[name]=entry(path)
            licenses=root/'licenses.json';licenses.write_text('{}');state['licenseTexts']=entry(licenses)
            states['nebula-v14-foundation']=state
            plan=copy.deepcopy(DEFAULT);plan.update(contextScenarios=100,publicRecords=20,casesPerAxis=2,
                 batch=2,microbatch=1,localSaveEvery=1,cloudSaveEvery=2)
            plan['steps']={key:2 for key in plan['steps']}
            fake_report={'summary':{'exactCorrect':0,'cases':16,'byAxis':{},'qualityApproved':False},'answers':[]}
            with patch('v17_lab.Store',LocalStore),patch('v17_lab.evaluate',return_value=fake_report),patch.dict('os.environ',
                {'NEBULA_HF_REPO':'test/private','NEBULA_HF_TOKEN':'unit-test','NEBULA_RULES_FILE':str(project/'nebula-rules.json')}):
                (project/'STOP').touch()
                main(project,'nebula-v17-unit',plan,hours=1,device='cpu')
                self.assertEqual(states['nebula-v17-unit']['taskIndex'],0)
                (project/'STOP').unlink()
                main(project,'nebula-v17-unit',plan,hours=1,device='cpu')
                finished=states['nebula-v17-unit']
                self.assertEqual(finished['phase'],'complete');self.assertEqual(finished['taskIndex'],6)
                self.assertEqual(len(finished['reports']),8)  # two baselines plus six stage reports
                self.assertEqual(len(finished['completedTasks']),6)
                self.assertEqual(entry(root/'source.pt')['sha256'],original_hash)
                self.assertTrue(all(name=='nebula-v17-unit' for name,_ in uploads))
                dashboard=json.loads((project/'dashboard.json').read_text())
                self.assertEqual(dashboard['v17Totals']['updates'],12)
                with patch('v17_lab.fit') as fit_mock:
                    main(project,'nebula-v17-unit',plan,hours=1,device='cpu');fit_mock.assert_not_called()
                changed=copy.deepcopy(plan);changed['steps']['context']=3
                with self.assertRaisesRegex(ValueError,'Settings/code changed'):
                    main(project,'nebula-v17-unit',changed,hours=1,device='cpu')
                continuation=copy.deepcopy(plan);continuation.update(sourceRun='nebula-v17-unit',sourceKey='current-contextWeights',arms=['current'],stages=['context'])
                main(project,'nebula-v17-continuation',continuation,hours=1,device='cpu')
                self.assertEqual(states['nebula-v17-continuation']['phase'],'complete')
                self.assertEqual(states['nebula-v17-unit']['taskIndex'],6)

    def test_balanced_public_selection_does_not_take_only_story_prefix(self):
        def rows(start,end,kind):
            return [{'messages':[{'role':'user','content':f'Opening {i}.'},{'role':'assistant','content':f'Answer {i}.'}],
                     'source':{'kind':'public','dataset':['stories','education','web'][i//40],
                               'license':'fixture','recordId':str(i),'curriculum':kind}}
                    for i in range(start,end)]
        train=rows(0,120,'v13-language');valid=rows(0,120,'v13-language')
        # Reserve five rows in every source, while keeping the source file grouped by dataset.
        valid=[r for i,r in enumerate(valid) if i%40>=35]
        chats=rows(0,120,'v13-conversation');chat_valid=[r for i,r in enumerate(chats) if i%40>=35]
        result=public_pools(train,valid,chats,chat_valid,30,[])
        self.assertEqual({name:sum(r['source']['dataset']==name for r in result['language']) for name in ['stories','education','web']},
                         {'stories':10,'education':10,'web':10})


if __name__=='__main__':unittest.main()
