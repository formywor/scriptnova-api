import ast,base64,hashlib,io,json,os,shutil,tempfile,unittest,zlib
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import Mock,patch
from dataflow import read_jsonl,write_jsonl,eligible
from v12_data import convert,merge,REWRITE_SYSTEM,digest
from v12_review import review,indices,PROTOCOL
from v9_data import canonical,prompts
from research_client import ResearchError

def item(i):return {'source':'smol-magpie-ultra-short','messages':[{'role':'user','content':f'Suggest a quiet activity for public exercise {i}.'},{'role':'assistant','content':f'Try drawing a small tree for exercise {i}.'}]}

class V12Tests(unittest.TestCase):
    def temporary(self):return tempfile.TemporaryDirectory(dir=Path(__file__).parent)
    def test_complete_records_no_truncation_roleplay_and_coding_rejected(self):
        original=item(500);row,reason=convert(original,500,0)
        self.assertIsNone(reason);self.assertTrue(eligible(row));self.assertEqual(row['messages'],original['messages']);self.assertEqual(row['source']['subset'],'default')
        for text in ['You are a 35 year old woman named Samantha.','You are a detective.','Write a Python function.']:
            record=item(501);record['messages'][0]['content']=text;self.assertIsNone(convert(record,501,0)[0])
        record=item(502);record['messages'].append({'role':'user','content':'Continue.'});self.assertIsNone(convert(record,502,0)[0])
        record=item(503);record['messages'][-1]['content']='This is an unfinished...';self.assertIsNone(convert(record,503,0)[0])
        record=item(504);record['messages'][-1]['content']='An answer that continues. '*20;self.assertIsNone(convert(record,504,0)[0])
        original['messages']+=[{'role':'user','content':'What supplies do I need?'},{'role':'assistant','content':'Use a pencil and a sheet of paper.'}]
        row,_=convert(original,505,0);self.assertEqual(len(row['messages']),4)
    def test_rewriting_system_instruction_preserved_others_not_silently_dropped(self):
        record={'source':'smollm-rewrite-30k','messages':[{'role':'system','content':REWRITE_SYSTEM},{'role':'user','content':'The report was finished. The report was sent yesterday.'},{'role':'assistant','content':'The finished report was sent yesterday.'}]}
        row,reason=convert(record,1,0);self.assertIsNone(reason);self.assertIn('Rewrite this text more concisely',row['messages'][0]['content']);self.assertIn('The report was finished.',row['messages'][0]['content']);self.assertEqual(row['messages'][-1],record['messages'][-1])
        record['messages'][0]['content']='Always pretend to be someone else.';self.assertIsNone(convert(record,1,0)[0])
    def test_merge_excludes_whole_records_prompts_duplicates_and_requires_review(self):
        with self.temporary() as folder:
            root=Path(folder);rows=[convert(item(i),i,0)[0] for i in range(260)]
            base=[rows[0]];valid=[rows[1]];duplicate={**rows[2],'id':'other','source':{**rows[2]['source'],'recordId':'different'}}
            write_jsonl(root/'base',base);write_jsonl(root/'valid',valid);write_jsonl(root/'seed',rows+[duplicate]);original=(root/'valid').read_bytes()
            summary=merge(root/'base',root/'valid',root/'seed',root/'out');self.assertEqual(summary['newCompleteConversations'],258);self.assertEqual((root/'valid').read_bytes(),original)
            final=read_jsonl(root/'out');self.assertFalse(set().union(*(prompts(r) for r in final))&prompts(valid[0]));self.assertEqual(len({canonical(r['messages']) for r in final}),len(final))
            with self.assertRaisesRegex(ValueError,'200'):merge(root/'base',root/'valid',root/'seed',root/'bad',require_review=True)
            marked=[{**r,'source':{**r['source'],'publicReviewProtocol':PROTOCOL}} for r in rows]
            write_jsonl(root/'seed',marked);self.assertEqual(merge(root/'base',root/'valid',root/'seed',root/'out',require_review=True)['newCompleteConversations'],258)
    def test_public_review_requires_two_passes_and_handles_malformed_indices(self):
        from v10_teacher import TeacherError
        with self.temporary() as folder:
            root=Path(folder);write_jsonl(root/'source',[convert(item(900+i),i,0)[0] for i in range(4)])
            request=Mock(side_effect=[{'acceptedIndices':[0,1,2]},{'acceptedIndices':[0,2]}])
            with redirect_stdout(io.StringIO()):result=review(root/'source',root/'out',root/'cache',max_calls=2,key='test',request=request,sleep=lambda _:None)
            kept=read_jsonl(root/'out');self.assertEqual(result['accepted'],2);self.assertTrue(all(r['source']['publicReviewProtocol']==PROTOCOL for r in kept));self.assertEqual(request.call_count,2)
            request=Mock(side_effect=[{'acceptedIndices':[0]},TeacherError('TEACHER_RATE_OR_QUOTA',429)])
            with redirect_stdout(io.StringIO()):result=review(root/'source',root/'pending-out',root/'pending-cache',max_calls=2,key='test',request=request,sleep=lambda _:None)
            self.assertEqual(result['accepted'],0);self.assertIsNotNone(result['deferred'])
            for wrong in [{'acceptedIndices':[True]},{'acceptedIndices':[0,0]},{'acceptedIndices':[99]}]:
                with self.assertRaises(ValueError):indices(wrong,4)
    def test_new_public_data_reaches_real_training_and_compatible_resume(self):
        import torch
        from nebula import Nebula,Config,save,load
        import v10_train
        import test_v9
        with self.temporary() as folder:
            root=Path(folder);test_v9.V9Tests.fixtures(self,root)
            save(Nebula(Config(width=16,heads=2,layers=1,context=768)),root/'anchor.pt',{'steps':35212})
            rows=[convert(item(1000+i),i,0)[0] for i in range(220)];rows=[{**r,'source':{**r['source'],'publicReviewProtocol':PROTOCOL}} for r in rows]
            write_jsonl(root/'seed.jsonl',rows);merge(root/'data.jsonl',root/'validation.jsonl',root/'seed.jsonl',root/'expanded.jsonl',True)
            args=['--data',str(root/'expanded.jsonl'),'--validation-data',str(root/'validation.jsonl'),'--quality-anchor',str(root/'anchor.pt'),'--batch','2','--microbatch','1','--device','cpu','--conversation-mix','--teacher-data',str(root/'teachers.jsonl'),'--lr','.0000015']
            selected=[];original=v10_train.global_batch
            def capture(*args):
                batch=original(*args)
                for tokens,mask in batch:
                    text=bytes(t for t in tokens if t<256).decode('utf-8',errors='ignore')
                    if 'public exercise' in text:selected.append(True)
                return batch
            with patch.object(v10_train,'global_batch',side_effect=capture),redirect_stdout(io.StringIO()):v10_train.main(args+['--resume',str(root/'anchor.pt'),'--output',str(root/'round.pt'),'--steps','40'])
            _,info=load(root/'round.pt');self.assertEqual(info['steps'],35252);self.assertEqual(info['conversationUpdates'],32);self.assertEqual(info['mixedUpdates'],8);self.assertTrue(selected);self.assertFalse(info['optimizerStateRestored'])
            with redirect_stdout(io.StringIO()):v10_train.main(args+['--resume',str(root/'round.pt'),'--output',str(root/'next.pt'),'--steps','1'])
            self.assertTrue(load(root/'next.pt')[1]['optimizerStateRestored'])
    def test_v12_main_uses_isolated_runner_without_resetting_v11(self):
        import v12_experiment as runner
        with patch.object(runner,'verified_main') as main:runner.main(['--hours','1'])
        self.assertEqual(main.call_args.kwargs['run_name'],'nebula-v12-public');self.assertEqual(main.call_args.kwargs['version'],runner.VERSION);self.assertIs(main.call_args.kwargs['initialize_run'],runner.initialize)
    def test_initialize_forks_paused_v11_best_adds_only_reviewed_rows_and_keeps_weights(self):
        import torch
        from nebula import Nebula,Config,save,load
        import test_v9
        import v12_experiment as runner
        from test_v11 import report
        with self.temporary() as folder:
            root=Path(folder);test_v9.V9Tests.fixtures(self,root);project=root/'project';public=project/'model/data/v12-public';public.mkdir(parents=True)
            save(Nebula(Config(width=16,heads=2,layers=1,context=768)),root/'anchor.pt',{'steps':35212})
            source_hash=digest(root/'anchor.pt');rows=[convert(item(3000+i),i,0)[0] for i in range(220)]
            write_jsonl(public/'conversations.jsonl',rows);(public/'manifest.json').write_text(json.dumps({'sha256':digest(public/'conversations.jsonl'),'license':'apache-2.0'}));(public/'licenses.json').write_text('{"license":"Apache 2.0"}')
            checks=root/'checks.json';checks.write_text('{}');licenses=root/'licenses.json';licenses.write_text('{}')
            old={'round':3,'rejected':3,'bestReport':report(),'sourceData':root/'anchor.pt','data':root/'data.jsonl','validationData':root/'validation.jsonl','evaluationData':root/'data.jsonl','checks':checks,'best':root/'anchor.pt','teacherData':root/'teachers.jsonl','licenseTexts':licenses}
            previous=Mock();previous.state.return_value=old;previous.prefix='experiments/nebula-v11-verified/';previous.revision='pinned'
            def download(source,target):target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,target);return target
            previous.download.side_effect=download;store=Mock(repo='private',token='test');store.publish.side_effect=lambda state,files,project:{**state,**{key:value[0] for key,value in files.items()}}
            def evaluate(*args):args[4].write_text('{}');return report()
            def approve(source,output,cache,**kwargs):
                chosen=[{**r,'source':{**r['source'],'publicReviewProtocol':PROTOCOL}} for r in read_jsonl(source)[:200]];write_jsonl(output,chosen);cache.write_text('{}');return {'accepted':200,'calls':2,'protocol':PROTOCOL,'deferred':None}
            with patch.object(runner,'Store',return_value=previous),patch.object(runner,'restore_data'),patch.object(runner,'configure_rules'),patch.object(runner,'evaluate',side_effect=evaluate),patch.object(runner,'review',side_effect=approve),patch('torch.cuda.device_count',return_value=2),redirect_stdout(io.StringIO()):state=runner.initialize(store,project)
            self.assertEqual(state['dataSummary']['newCompleteConversations'],200);self.assertEqual(state['round'],0);self.assertEqual(state['rejected'],0);self.assertEqual(state['sourceRound'],3);self.assertEqual(state['sourceRun'],previous.prefix);self.assertFalse(state['publicAutoUpdate']);self.assertTrue(state['newCurriculumOptimizerReset']);previous.publish.assert_not_called()
            self.assertEqual(load(state['best'])[1]['steps'],35212);self.assertEqual(digest(root/'anchor.pt'),source_hash);self.assertEqual(read_jsonl(state['validationData']),read_jsonl(root/'validation.jsonl'))
    def test_packaged_public_data_and_code_are_complete_and_checksum_valid(self):
        from build_v12_notebook import build
        book=json.loads(build().read_text(encoding='utf-8'))
        for c in book['cells']:
            if c['cell_type']=='code':ast.parse(''.join(c['source']))
        code=''.join(book['cells'][2]['source']);tree=ast.parse(code);assignments={n.targets[0].id:ast.literal_eval(n.value) for n in tree.body[:3]}
        payload=zlib.decompress(base64.b64decode(assignments['public_seed']));self.assertEqual(hashlib.sha256(payload).hexdigest(),assignments['public_seed_sha256'])
        files=json.loads(payload);manifest=json.loads(files['manifest.json']);self.assertEqual(hashlib.sha256(files['conversations.jsonl'].encode()).hexdigest(),manifest['sha256']);self.assertGreaterEqual(manifest['accepted'],200)
        for name,source in assignments['sources'].items():
            if name.endswith('.py'):ast.parse(source)
        self.assertIn('model/v12_review.py',assignments['sources']);self.assertIn('Apache',files['licenses.json']);self.assertNotRegex(code,r'(?:gsk_|hf_)[A-Za-z0-9]{20,}')
    def test_final_real_seed_reuses_complete_reviews_without_provider_calls(self):
        from v12_data import rejection
        public=Path(__file__).parents[1]/'data/v12-public';rows=read_jsonl(public/'conversations.jsonl')
        self.assertEqual(len(rows),200);self.assertTrue(all(rejection(row) is None for row in rows));self.assertEqual(sum(len(row['messages'])>2 for row in rows),7)
        with self.temporary() as folder:
            root=Path(folder);shutil.copyfile(public/'screening-cache.json',root/'cache');request=Mock(side_effect=AssertionError('Must reuse completed public reviews'))
            result=review(public/'conversations.jsonl',root/'out',root/'cache',target=200,key='test',request=request)
            self.assertEqual(result['accepted'],200);self.assertEqual(result['calls'],0);request.assert_not_called()

if __name__=='__main__':unittest.main()
