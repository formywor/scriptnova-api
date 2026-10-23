import ast
import copy
import contextlib
import io
import unittest
from pathlib import Path
from unittest.mock import patch
import v26_answers as trainer
import v26_sweep as sweep
import test_v25_answers as previous

class SweepTests(unittest.TestCase):
    def test_only_learning_rate_changes_across_arms(self):
        configs=sweep.arm_configs()
        self.assertEqual([c['learningRate'] for _,c in configs],[1e-6,3e-6,1e-5])
        for _,config in configs:
            self.assertEqual({k:v for k,v in config.items() if k!='learningRate'},
                             {k:v for k,v in trainer.DEFAULT.items() if k!='learningRate'})
            self.assertEqual(config['updates'],500)
            self.assertEqual(config['sourceRun'],'nebula-v22-conversation')
        self.assertEqual(len({name for name,_ in configs}),3)

    def test_sequential_shared_baseline_and_paused_arm(self):
        baseline=dict(exactCorrect=35,byAxis={k:{'correct':2} for k in sweep.PROTECTED},heldoutMixed={'loss':1.},heldoutPublic={'loss':1.})
        calls=[]
        def runner(name,config,**kwargs):
            calls.append((name,config,kwargs))
            if len(calls)==1:return dict(baseline=baseline,final=dict(baseline,exactCorrect=36,exactCases=96))
            self.assertEqual(kwargs['shared_baseline'],baseline)
            return {'updates':100}
        with contextlib.redirect_stdout(io.StringIO()):result=sweep.run_sweep(runner=runner,clock=lambda:0)
        self.assertEqual(len(calls),2)
        self.assertFalse(result['complete']);self.assertEqual(result['pausedArm'],'reference')
        self.assertIsNone(calls[0][2]['shared_baseline'])
        self.assertEqual(calls[0][2]['deadline'],25200)

    def test_no_promotion_from_loss_alone_or_regressed_skills(self):
        baseline=dict(exactCorrect=35,byAxis={k:{'correct':2} for k in sweep.PROTECTED},heldoutMixed={'loss':1.},heldoutPublic={'loss':1.})
        final=copy.deepcopy(baseline);final.update(exactCases=96,exactCorrect=36)
        report=dict(baseline=baseline,final=final)
        self.assertTrue(sweep.assess(report)['eligibleForManualInspection'])
        final['byAxis']['updated-facts']['correct']=1
        self.assertFalse(sweep.assess(report)['eligibleForManualInspection'])
        self.assertFalse(sweep.assess(report)['qualityApproved'])
        self.assertFalse(sweep.assess(report)['publicWebsiteUpdated'])

    def test_session_deadline_prevents_new_arm(self):
        with contextlib.redirect_stdout(io.StringIO()):
            times=iter([0,26000]);result=sweep.run_sweep(clock=lambda:next(times),runner=lambda *a,**k:self.fail('No arm should start'))
        self.assertFalse(result['complete']);self.assertEqual(result['results'],[])

    def test_cpu_resume_exact_and_sources_immutable_no_local_artifacts(self):
        with patch.object(previous,'trainer',trainer):
            previous.AnswerRepairTests('test_independent_weight_and_raw_sources_resume_and_no_local_artifacts').test_independent_weight_and_raw_sources_resume_and_no_local_artifacts()

    def test_notebook_is_self_contained_and_no_output(self):
        import json
        from build_v26_sweep import build
        notebook=json.loads(build().read_text(encoding='utf-8'))
        for cell in notebook['cells']:
            if cell['cell_type']=='code':
                ast.parse(''.join(cell['source']));self.assertEqual(cell['outputs'],[])
        tree=ast.parse(''.join(notebook['cells'][3]['source']))
        sources=ast.literal_eval(tree.body[0].value)
        self.assertIn('v26_sweep.py',sources)
        self.assertNotIn('v25_answers.py',sources)
        for name,source in sources.items():
            ast.parse(source)
            self.assertEqual(source,(Path(trainer.__file__).parent/name).read_text(encoding='utf-8'))

if __name__=='__main__':unittest.main()
