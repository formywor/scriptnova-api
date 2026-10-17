import os
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from research_combined import main
from research_client import ResearchError
from research_worker import configure_rules,training_plan
from rules import owner_instructions

class CombinedWorkers(unittest.TestCase):
    def setUp(self):
        self.env=patch.dict(os.environ,{'NEBULA_TRAINER_TOKEN':'t'*40,'NEBULA_EVALUATOR_TOKEN':'e'*40,
                                      'NEBULA_WORKER_TOKEN':'original'})
        self.env.start();self.addCleanup(self.env.stop)
    def test_alternates_roles_and_keeps_phase_outputs_separate(self):
        state={'head':'base','candidate':None};calls=[]
        def run(args):
            role=args[args.index('--role')+1];calls.append(role)
            self.assertEqual(os.environ['NEBULA_WORKER_TOKEN'],('t' if role=='trainer' else 'e')*40)
            self.assertEqual(Path(args[args.index('--project')+1]).name,role)
            state['candidate']='candidate' if role=='trainer' else None
        with patch('research_combined.Client') as client:
            client.return_value.call.side_effect=lambda action:dict(state)
            main(['--project','project','--rounds','2'],run_worker=run,clock=lambda:1)
        self.assertEqual(calls,['trainer','evaluator','trainer','evaluator'])
        self.assertEqual(os.environ['NEBULA_WORKER_TOKEN'],'original')
    def test_pending_evaluation_resumes_before_training(self):
        calls=[]
        with patch('research_combined.Client') as client:
            client.return_value.call.return_value={'head':'base','candidate':'pending'}
            main(['--project','project','--rounds','1'],run_worker=lambda args:calls.append(args[1]),clock=lambda:1)
        self.assertEqual(calls,['evaluator'])
    def test_failed_phase_stops_and_restores_original_environment(self):
        def fail(args):raise ResearchError('HF_UPLOAD_FAILED')
        with patch('research_combined.Client') as client:
            client.return_value.call.return_value={'head':'base'}
            with self.assertRaisesRegex(ResearchError,'HF_UPLOAD_FAILED'):
                main(['--project','project'],run_worker=fail,clock=lambda:1)
        self.assertEqual(os.environ['NEBULA_WORKER_TOKEN'],'original')
    def test_campaign_pause_is_respected_without_starting_another_phase(self):
        with patch('research_combined.Client') as client:
            client.return_value.call.return_value={'head':'base','rejectedRounds':3}
            with self.assertRaisesRegex(ResearchError,'RESEARCH_PAUSED_NO_IMPROVEMENT'):
                main(['--project','project'],run_worker=lambda args:self.fail('Should not run'),clock=lambda:1)
    def test_separate_phase_rules_are_used_in_parent_and_training_subprocess(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder,patch.dict(os.environ):
            root=Path(folder).resolve()
            for role in ['trainer','evaluator']:
                project=root/role;project.mkdir()
                (project/'nebula-rules.json').write_text(json.dumps({'instructions':[f'Rules from {role}.']}))
                configure_rules(project)
                self.assertEqual(owner_instructions(),f'Rules from {role}.')
                result=subprocess.run([sys.executable,'-c','from rules import owner_instructions; print(owner_instructions())'],
                                      cwd=root,env=dict(os.environ),capture_output=True,text=True,timeout=15)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual(result.stdout.strip(),f'Rules from {role}.')
    def test_missing_phase_rules_cannot_fall_back_to_other_rules(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            with self.assertRaisesRegex(ResearchError,'RESTORED_OWNER_RULES_MISSING'):configure_rules(Path(folder))
    def test_rejections_change_focus_and_lower_lr_without_using_rejected_weights(self):
        report={'identity':0,'math':0,'memory':0,'extraction':.5,'health':1}
        state={'head':'stable','lastEvaluation':{'report':report}}
        plans=[training_plan({**state,'rejectedRounds':count}) for count in range(3)]
        self.assertEqual([plan['focus'] for plan in plans],['balanced','identity','math'])
        self.assertGreater(plans[0]['lr'],plans[1]['lr'])
        self.assertGreater(plans[1]['lr'],plans[2]['lr'])
        self.assertEqual(state['head'],'stable')
        self.assertNotIn('checkpoint',plans[1])
        unhealthy=training_plan({'rejectedRounds':1,'lastEvaluation':{'report':{'health':.5}}})
        self.assertEqual(unhealthy['focus'],'language')

if __name__=='__main__':unittest.main()
