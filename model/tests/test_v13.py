import ast,io,json,tempfile,unittest
from pathlib import Path
from contextlib import redirect_stdout
from unittest.mock import patch,Mock
from dataflow import read_jsonl,write_jsonl,eligible
from v13_data import convert,rejection,merge,acquire,SOURCES,digest
from v13_windows import examples,windows
from v9_data import prompts,canonical
from nebula import encode,EOS,BOS
from v13_review import review,PROTOCOL

def chat(i=80000):
    return {'source':'smol-magpie-ultra-short','messages':[{'role':'user','content':f'Help plan a lantern festival invitation, exercise {i}.'},
        {'role':'assistant','content':f'For invitation {i}, begin by naming the occasion, then state the place and time. Keep the tone welcoming. Ask guests to reply so you know how many seats to prepare. Include any supplies they should bring. Finish with a friendly closing.'},
        {'role':'user','content':f'How can I make invitation {i} warmer?'},{'role':'assistant','content':'Mention that you look forward to spending time together.'}]}

def passage(i=80000):
    return {'text':f'A lantern festival {i} brings neighbors together. Children paint paper lanterns while adults arrange tables. Families share food and tell stories in the evening. As darkness falls, the lanterns glow with gentle colors. Everyone helps clean the square before going home.','language':'en','score':4.2}

class V13Tests(unittest.TestCase):
    def temporary(self):return tempfile.TemporaryDirectory(dir=Path(__file__).parent)
    def test_heldout_matcher_matches_literal_checks_including_failure_links(self):
        import random,string
        from v13_data import HeldoutMatcher
        rng=random.Random(13)
        patterns=['a shared prefix and suffix','shared prefix and suffix!','prefix and suffix','(a literal [pattern]?)','x'*17,'too short']
        patterns+=[''.join(rng.choices(string.ascii_lowercase+' ',k=rng.randrange(17,60))) for _ in range(200)]
        matcher=HeldoutMatcher(patterns)
        texts=['','too short','literal unprotected text','x'*16,'x'*17,'a shared prefix and suffix!','The text has (a literal [pattern]?) inside.']
        for _ in range(200):
            text=''.join(rng.choices(string.ascii_lowercase+' ',k=200))
            if rng.random()<.5:text=text[:40]+rng.choice(patterns)+text[40:]
            texts.append(text)
        for text in texts:self.assertEqual(matcher.contains(text),any(len(p)>16 and p in text for p in patterns))
    def test_full_long_dialogues_and_three_text_formats(self):
        item=chat();row,reason=convert(item,'chat',0,'pinned')
        self.assertIsNone(reason);self.assertEqual(row['messages'],item['messages']);self.assertGreater(len(row['messages'][1]['content']),220)
        for kind in ['cosmopedia','fineweb','stories']:
            row,reason=convert(passage(),kind,0,'pinned');self.assertIsNone(reason);self.assertTrue(eligible(row));self.assertEqual(row['messages'][1]['content'],passage()['text'])
            self.assertEqual(row['source']['curriculum'],'v13-language')
        self.assertEqual(convert({**passage(),'score':2},'fineweb',1,'pin')[1],'language_or_education_score')
        item=chat();item['messages'][1]['content']='This is unfinished...';self.assertIsNone(convert(item,'chat',0,'pin')[0])
        item=chat();item['messages'][1]['content']='The total is 42 + 17 = 61.';self.assertIsNone(convert(item,'chat',0,'pin')[0])
        item=chat();item['messages'][0]['content']='You are a 35 year old woman named Jane.';self.assertIsNone(convert(item,'chat',0,'pin')[0])
    def test_every_assistant_target_once_no_user_loss_or_invented_eos(self):
        row,_=convert(chat(),'chat',1,'pin');tokens,learn=encode(row['messages'])
        result=examples([row],64,False)
        actual=[int(t) for _,y in result for t in y if int(t)!=-100]
        expected=[t for t,m in zip(tokens[1:],learn[1:]) if m]
        self.assertEqual(actual,expected);self.assertEqual(actual.count(EOS),2)
        self.assertGreater(len(result),4);self.assertTrue(all(len(x)<=64 and len(x)==len(y) for x,y in result))
        self.assertEqual(actual[-1],EOS)
    def test_language_windows_learn_entire_raw_text_without_chat_wrapper(self):
        row,_=convert(passage(),'cosmopedia',1,'pin');result=examples([row],64,True)
        targets=[int(t) for _,y in result for t in y if int(t)!=-100]
        self.assertEqual(targets,list(passage()['text'].encode()));self.assertNotIn(EOS,targets)
    def test_merge_all_sources_new_holdout_and_old_validation_intact(self):
        with self.temporary() as d:
            root=Path(d);old,_=convert(chat(70000),'chat',0,'pin');fixed,_=convert(chat(70001),'chat',1,'pin')
            write_jsonl(root/'old.jsonl',[old]);write_jsonl(root/'fixed.jsonl',[fixed]);before=digest(root/'fixed.jsonl')
            rows=[]
            for i in range(240):
                row,_=convert(chat(80000+i),'chat',i,'pin');row['source']['publicReviewProtocol']=PROTOCOL;row['messages'][2]['content']='Can you make the tone warmer?';rows.append(row)
            for kind in ['cosmopedia','fineweb','stories']:
                rows.extend(convert(passage(90000+i),kind,i,'pin')[0] for i in range(80))
            # The same passage in different corpora is deduplicated: make their text distinct.
            for i,r in enumerate(rows[240:]):
                r['messages'][1]['content']+=f' This version uses symbol number {i}.';r['source']['recordId']+=str(i);r['splitGroup']+=str(i)
            rows.extend([rows[0],fixed,old])
            result=merge(root/'old.jsonl',root/'fixed.jsonl',rows,root/'train.jsonl',root/'held.jsonl')
            train=read_jsonl(root/'train.jsonl');held=read_jsonl(root/'held.jsonl')
            self.assertEqual(before,digest(root/'fixed.jsonl'));self.assertGreater(result['newTrainingRows'],300)
            self.assertEqual(len(result['sources']),4);self.assertFalse({r['splitGroup'] for r in train}&{r['splitGroup'] for r in held})
            self.assertFalse({canonical(r['messages']) for r in train}&{canonical(r['messages']) for r in held})
            self.assertNotIn(fixed,train);self.assertNotIn(fixed,held)
    def test_acquisition_caches_complete_source_and_survives_failure(self):
        with self.temporary() as d:
            targets={k:2 for k in SOURCES}
            def stream(kind,spec):return 'pinned',iter([chat(80000+i) if kind=='chat' else passage(80000+i) for i in range(5)])
            result=acquire(d,targets,stream);self.assertEqual(set(result),set(SOURCES));self.assertTrue(all(v['accepted']==2 for v in result.values()))
            self.assertEqual(acquire(d,targets,Mock(side_effect=AssertionError('network'))),result)
        with self.temporary() as d:
            def broken(kind,spec):
                def items():yield chat();raise OSError('private response must not be logged')
                return 'pinned',items()
            with self.assertRaisesRegex(RuntimeError,'V13_SOURCE_DOWNLOAD_DEFERRED:chat'):acquire(d,{k:2 for k in SOURCES},broken)
            self.assertEqual(len(read_jsonl(Path(d)/'chat.jsonl')),1)
    def test_two_pass_public_review_with_long_batches_and_cached_resume(self):
        with self.temporary() as d:
            root=Path(d);rows=[convert(chat(82000+i),'chat',i,'pin')[0] for i in range(6)];write_jsonl(root/'in.jsonl',rows)
            sent=[]
            def request(messages,key,model):
                values=json.loads(messages[1]['content']);sent.extend(values)
                return {'acceptedIndices':list(range(len(values)))}
            with redirect_stdout(io.StringIO()):result=review(root/'in.jsonl',root/'out.jsonl',root/'cache.json',key='test',request=request,sleep=lambda _:None,max_calls=8)
            self.assertEqual(result['accepted'],6);self.assertEqual(result['calls'],4);self.assertTrue(all(len(v['messages'])==4 for v in sent))
            with redirect_stdout(io.StringIO()):result=review(root/'in.jsonl',root/'out.jsonl',root/'cache.json',key='test',request=Mock(side_effect=AssertionError('cached')))
            self.assertEqual(result['calls'],0)
    def test_review_transport_reserves_only_bounded_verdict_output(self):
        import v13_review
        def transport(messages,key,model,fetch):return fetch('https://example.invalid',json={'max_completion_tokens':4096})
        with patch.object(v13_review,'http_json',side_effect=transport),patch('requests.post',return_value={'ok':True}) as post:
            self.assertEqual(v13_review.review_request([], 'test', 'test'),{'ok':True})
        self.assertEqual(post.call_args.kwargs['json']['max_completion_tokens'],1024)
    def test_no_groq_evaluation_ignores_present_provider_keys_and_teacher_budget(self):
        import os,v13_experiment as runner
        with patch.dict(os.environ,{'NEBULA_V13_USE_GROQ':'false','NEBULA_TEACHER_GROQ_KEY':'configured-but-disabled'}),patch.object(runner,'evaluate',return_value={}) as evaluator:
            runner.evaluate_available('weights','legacy','checks','valid',Path('report.json'))
            reviewer=evaluator.call_args.kwargs['reviewer'];self.assertEqual(reviewer.key,'');self.assertEqual(reviewer.max_calls,0)
        with patch.dict(os.environ,{'NEBULA_V13_USE_GROQ':'false'}),patch.object(runner,'verified_main') as main:
            runner.main(['--teacher-calls','96']);self.assertEqual(main.call_args.args[0],['--teacher-calls','0']);self.assertIs(main.call_args.kwargs['save_round'],runner.save_local_round)
    def test_unreviewed_training_requires_explicit_merge_mode_and_honest_metadata(self):
        with self.temporary() as d:
            root=Path(d);write_jsonl(root/'base.jsonl',[]);write_jsonl(root/'validation.jsonl',[])
            rows=[convert(chat(95000+i),'chat',i,'pin')[0] for i in range(200)]
            for n,kind in enumerate(['cosmopedia','fineweb','stories']):rows.extend(convert(passage(96000+n*1000+i),kind,i,'pin')[0] for i in range(40))
            with self.assertRaises(ValueError):merge(root/'base.jsonl',root/'validation.jsonl',rows,root/'train.jsonl',root/'held.jsonl')
            result=merge(root/'base.jsonl',root/'validation.jsonl',rows,root/'train.jsonl',root/'held.jsonl',require_review=False)
            self.assertFalse(result['publicChatReviewRequired']);self.assertGreater(result['newTrainingRows'],200)
            self.assertTrue(all('publicReviewProtocol' not in r['source'] for r in read_jsonl(root/'train.jsonl')))
    def test_pending_semantic_review_continues_provisionally_and_keeps_verified_best(self):
        import shutil,v13_experiment as runner
        from test_v11 import report
        with self.temporary() as d:
            root=Path(d);checkpoint=root/'round.pt';checkpoint.write_bytes(b'full-working-optimizer')
            base=report();candidate={**base,'reviewComplete':False,'pendingReview':4,'chatPendingReview':3,'chatChecks':0}
            state={'round':0,'rejected':0,'best':'protected-best','bestReport':base,'baselineReport':base,'workingReport':base,'working':'old-working'}
            store=Mock();saved={}
            def publish(value,files,project):saved.update(files);return {**value,**{k:v[0] for k,v in files.items()}}
            store.publish.side_effect=publish
            def evaluate(*args):args[4].write_text(json.dumps(candidate));return candidate
            def compact(src,dest):shutil.copyfile(src,dest);return dest
            with patch.object(runner,'compact',side_effect=compact),redirect_stdout(io.StringIO()):
                result,complete=runner.save_local_round(store,state,[('final',checkpoint)],root,None,None,None,evaluate_checkpoint=evaluate)
            self.assertTrue(complete);self.assertTrue(result['workingProvisional']);self.assertEqual(result['best'],'protected-best');self.assertNotIn('best',saved)
            self.assertFalse(result['workingReport']['reviewComplete']);self.assertTrue(result['latestNeedsSemanticReview']);self.assertFalse(result['publicAutoUpdate'])
            self.assertEqual(result['round'],1);self.assertIsNone(result['pendingEvaluation']);self.assertEqual(result['working'].read_bytes(),b'full-working-optimizer')
            self.assertFalse(runner.local_safe(base,{**candidate,'loss':float('nan')}))
    def test_additional_local_losses_preserve_generated_answer_evidence(self):
        import v13_experiment as runner
        from nebula import Nebula,Config,save
        with self.temporary() as d:
            root=Path(d);(root/'model/data').mkdir(parents=True)
            rows=[convert(chat(),'chat',0,'pin')[0]]+[convert(passage(),k,0,'pin')[0] for k in ['cosmopedia','fineweb','stories']]
            write_jsonl(root/'model/data/v13-public-heldout.jsonl',rows)
            save(Nebula(Config(width=16,heads=2,layers=1,context=64)),root/'weights.pt',{'steps':0})
            def evaluate(*args):
                args[4].write_text(json.dumps({'report':{'reviewComplete':False},'answers':[{'reply':'Preserve this actual generated answer.'}],'taskAnswers':[{'passed':None}]}));return {'reviewComplete':False}
            with patch.object(runner,'evaluate_available',side_effect=evaluate),patch('torch.cuda.is_available',return_value=False),redirect_stdout(io.StringIO()):
                report=runner.evaluate_expanded(root/'weights.pt',None,None,None,root/'report.json')
            saved=json.loads((root/'report.json').read_text());self.assertEqual(saved['answers'][0]['reply'],'Preserve this actual generated answer.');self.assertIsNone(saved['taskAnswers'][0]['passed'])
            self.assertFalse(saved['report']['reviewComplete']);self.assertEqual(len(report['newPublicHeldoutLosses']),4)
    def test_expanded_real_cpu_training_sources_and_optimizer_resume(self):
        import torch,v10_train,test_v9
        from nebula import Nebula,Config,save,load
        with self.temporary() as d:
            root=Path(d);test_v9.V9Tests.fixtures(self,root)
            rows=read_jsonl(root/'data.jsonl')
            rows.extend(convert(chat(83000+i),'chat',i,'pin')[0] for i in range(12))
            for kind in ['cosmopedia','fineweb','stories']:rows.append(convert(passage(84000+len(rows)),kind,1,'pin')[0])
            write_jsonl(root/'expanded.jsonl',rows)
            save(Nebula(Config(width=16,heads=2,layers=1,context=768)),root/'anchor.pt',{'steps':35012})
            args=['--data',str(root/'expanded.jsonl'),'--validation-data',str(root/'validation.jsonl'),'--quality-anchor',str(root/'anchor.pt'),'--batch','2','--device','cpu','--conversation-mix','--expanded-public','--lr','.0000015']
            with redirect_stdout(io.StringIO()):v10_train.main(args+['--resume',str(root/'anchor.pt'),'--output',str(root/'round.pt'),'--steps','100'])
            info=load(root/'round.pt')[1];self.assertEqual(info['qualityVersion'],13);self.assertEqual(info['stepsThisRun'],100);self.assertEqual(info['conversationUpdates'],80)
            self.assertEqual(len(info['languageSourceUpdates']),3);self.assertTrue(all(n>=1 for n in info['languageSourceUpdates'].values()));self.assertFalse(info['optimizerStateRestored'])
            with redirect_stdout(io.StringIO()):v10_train.main(args+['--resume',str(root/'round.pt'),'--output',str(root/'next.pt'),'--steps','1'])
            self.assertTrue(load(root/'next.pt')[1]['optimizerStateRestored'])
    def test_notebook_contains_current_sources_no_keys_and_defaults_safe(self):
        from build_v13_notebook import build
        book=json.loads(build().read_text(encoding='utf-8'));codes=[''.join(c['source']) for c in book['cells'] if c['cell_type']=='code']
        for code in codes:ast.parse(code)
        sources=ast.literal_eval(ast.parse(codes[1]).body[0].value)
        for name in ['v13_data.py','v13_review.py','v13_windows.py','v13_experiment.py']:
            self.assertEqual(sources['model/'+name],(Path(__file__).parents[1]/name).read_text(encoding='utf-8'))
        self.assertIn('nebula-v13-four-sources',codes[0]);self.assertIn('datasets>=3.6',codes[0]);self.assertNotRegex(''.join(codes),r'(?:gsk_|hf_)[A-Za-z0-9]{20,}')
    def test_initialize_preserves_best_backups_all_sources_and_syncs_repository_revision(self):
        import shutil,test_v9,v13_experiment as runner
        from nebula import Nebula,Config,save,load
        from test_v11 import report
        with self.temporary() as d:
            root=Path(d);test_v9.V9Tests.fixtures(self,root);project=root/'project';project.mkdir()
            save(Nebula(Config(width=16,heads=2,layers=1,context=768)),root/'anchor.pt',{'steps':35012})
            before=digest(root/'anchor.pt');(root/'checks.json').write_text('{}');(root/'licenses.json').write_text('{}');(root/'card.md').write_text('Dataset attribution and license.')
            old={'round':3,'rejected':3,'bestReport':report(),'sourceData':root/'anchor.pt','data':root/'data.jsonl','validationData':root/'validation.jsonl','evaluationData':root/'data.jsonl','checks':root/'checks.json','best':root/'anchor.pt','teacherData':root/'teachers.jsonl','licenseTexts':root/'licenses.json'}
            previous=Mock();previous.state.return_value=old;previous.prefix='experiments/nebula-v12-public/';previous.revision='source-commit'
            def download(src,dest):dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(src,dest);return dest
            previous.download.side_effect=download
            stage=Mock();stage.state.return_value=None;stage.revision='preparation-commit'
            def publish(state,files,project):return {**state,**{k:v[0] for k,v in files.items()}}
            stage.publish.side_effect=publish
            store=Mock(repo='private',token='test');store.publish.side_effect=publish
            def acquire(folder,on_source=None):
                manifests={}
                for kind in SOURCES:
                    rows=[convert(chat(85000+i) if kind=='chat' else passage(86000+i+(list(SOURCES).index(kind)*1000)),kind,i,'pinned')[0] for i in range(260 if kind=='chat' else 80)]
                    write_jsonl(folder/(kind+'.jsonl'),rows);(folder/(kind+'.json')).write_text('{}');manifests[kind]={'revision':'pinned'}
                    if on_source:on_source()
                (folder/'manifest.json').write_text(json.dumps(manifests));return manifests
            def review(source,output,cache,**kwargs):
                rows=[{**r,'source':{**r['source'],'publicReviewProtocol':PROTOCOL}} for r in read_jsonl(source)];write_jsonl(output,rows);cache.write_text('{}');return {'accepted':len(rows),'calls':2,'protocol':PROTOCOL}
            def evaluate(*args,**kwargs):args[4].write_text('{}');return report()
            with patch.object(runner,'Store',side_effect=lambda repo,token,run:stage if run.endswith('-preparation') else previous),patch.object(runner,'restore_data'),patch.object(runner,'configure_rules'),patch.object(runner,'acquire',side_effect=acquire),patch.object(runner,'review',side_effect=review),patch.object(runner,'evaluate',side_effect=evaluate),patch.object(runner,'evaluate_expanded',side_effect=evaluate),patch('huggingface_hub.hf_hub_download',return_value=str(root/'card.md')),patch('torch.cuda.device_count',return_value=2),redirect_stdout(io.StringIO()):
                state=runner.initialize(store,project)
            self.assertEqual(len(state['dataSummary']['sources']),4);self.assertEqual(state['round'],0);self.assertFalse(state['publicAutoUpdate'])
            self.assertEqual(store.revision,stage.revision);self.assertEqual(digest(root/'anchor.pt'),before);self.assertEqual(load(state['best'])[1]['steps'],35012)
            self.assertEqual(digest(state['validationData']),digest(root/'validation.jsonl'));previous.publish.assert_not_called();self.assertGreater(stage.publish.call_count,4)

if __name__=='__main__':unittest.main()
