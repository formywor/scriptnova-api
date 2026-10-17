import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import torch
from dataflow import write_jsonl
from nebula import Nebula,config_for_preset,load,save
from research_eval import correct,healthy,research_rows
from research_worker import prefer

class ResearchTraining(unittest.TestCase):
    def test_locked_questions_and_names_are_excluded_from_training(self):
        rows=[]
        for question in ['Compute 37 + 48.','My friend Maribel has a bag.','Explain a small task.']:
            rows.append({'reviewStatus':'approved','source':{'kind':'seed'},'messages':[
                {'role':'user','content':question},{'role':'assistant','content':'Example.'}]})
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            path=Path(folder)/'data.jsonl';write_jsonl(path,rows)
            filtered=research_rows(path)
            self.assertEqual(len(filtered),1)
            self.assertEqual(filtered[0]['messages'][0]['content'],'Explain a small task.')
    def test_metrics_reject_wrong_final_numbers_and_repetitive_answers(self):
        self.assertFalse(correct({'number':85},'85? No, 84.'))
        self.assertTrue(correct({'number':85},'37 + 48 = 85.'))
        self.assertFalse(healthy('the story of '*30))
        self.assertTrue(healthy('Your name is Keon.'))
    def test_client_never_forwards_worker_auth_to_storage(self):
        from research_client import Client
        client=Client('https://api.example.test/api/nebula/research','x'*40)
        class Response:
            status_code=200
            def json(self):return {'id':'upload','url':'https://storage.googleapis.com/private','headers':{'content-type':'application/octet-stream'}}
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            path=Path(folder)/'weights.pt';path.write_bytes(b'example')
            with patch('research_client.requests.request',return_value=Response()) as api,patch('research_client.requests.put',return_value=Response()) as storage:
                client.upload(path)
            self.assertIn('Authorization',api.call_args.kwargs['headers'])
            self.assertNotIn('Authorization',storage.call_args.kwargs['headers'])
    def test_two_cpu_ranks_match_one_process_training(self):
        torch.set_num_threads(1)
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            root=Path(folder);data=root/'data.jsonl'
            rows=[{'reviewStatus':'approved','source':{'kind':'seed'},'messages':[
                {'role':'user','content':f'Say {i}.'},{'role':'assistant','content':f'Answer {i}.'}]} for i in range(100)]
            write_jsonl(data,rows)
            torch.manual_seed(42);save(Nebula(config_for_preset('smoke')),root/'start.pt',{'steps':0})
            script=Path(__file__).resolve().parents[1]/'research_train.py'
            common=[sys.executable,str(script),'--data',str(data),'--resume',str(root/'start.pt'),
                    '--steps','3','--batch','4','--device','cpu']
            result=subprocess.run(common+['--output',str(root/'single.pt')],capture_output=True,text=True,timeout=60)
            self.assertEqual(result.returncode,0,result.stderr[-2000:])
            processes=[];streams=[]
            try:
                for rank in range(2):
                    env=dict(os.environ,RANK=str(rank),LOCAL_RANK=str(rank),WORLD_SIZE='2')
                    stream=(root/f'rank-{rank}.log').open('w');streams.append(stream)
                    process=subprocess.Popen(common+['--output',str(root/'multi.pt'),'--rendezvous',str(root/'rendezvous')],
                                             env=env,stdout=stream,stderr=subprocess.STDOUT)
                    processes.append(process)
                for process in processes:process.wait(timeout=60)
            finally:
                for process in processes:
                    if process.poll() is None:process.kill();process.wait()
                for stream in streams:stream.close()
            logs='\n'.join((root/f'rank-{rank}.log').read_text() for rank in range(2))
            self.assertTrue(all(p.returncode==0 for p in processes),logs[-4000:])
            one,_=load(root/'single.pt');two,info=load(root/'multi.pt')
            self.assertEqual(info['worldSize'],2);self.assertEqual(info['steps'],3)
            for key,value in one.state_dict().items():
                torch.testing.assert_close(value,two.state_dict()[key],rtol=1e-4,atol=2e-6)

if __name__=='__main__':unittest.main()
