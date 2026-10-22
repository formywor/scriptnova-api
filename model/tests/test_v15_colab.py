import ast,io,json,os,tempfile,types,sys,unittest
from pathlib import Path
from unittest.mock import patch,Mock
from contextlib import redirect_stdout
import torch
from test_v15 import V15Tests

class V15ColabTests(unittest.TestCase):
    def temporary(self):return tempfile.TemporaryDirectory(dir=Path(__file__).parent)
    def test_notebook_uses_native_secrets_same_run_and_current_sources(self):
        from build_v15_colab import build
        root=Path(__file__).parents[1];path=build();nb=json.loads(path.read_text(encoding='utf-8'));setup=''.join(nb['cells'][1]['source']);run=''.join(nb['cells'][2]['source'])
        self.assertIn('from google.colab import userdata',setup);self.assertNotIn('kaggle_secrets',setup);self.assertIn('/content/nebula-v15-full-chats/api',setup);self.assertNotIn('drive.mount',setup)
        self.assertIn('PREPARE_ONLY=False',setup);self.assertNotRegex(path.read_text(),r'(?:hf_|gsk_)[A-Za-z0-9]{20,}')
        sources=ast.literal_eval(ast.parse(run).body[0].value)
        for name,source in sources.items():
            self.assertEqual(source,(root.parent/name).read_text(encoding='utf-8'))
            if name.endswith('.py'):ast.parse(source)
        self.assertIn("RUN='nebula-v15-full-chats'",sources['model/v15_experiment.py'])
    def test_colab_setup_reads_secret_without_printing_it(self):
        from build_v15_colab import build
        nb=json.loads(build().read_text(encoding='utf-8'));setup=''.join(nb['cells'][1]['source']);output=io.StringIO()
        colab=types.ModuleType('google.colab');colab.userdata=Mock();colab.userdata.get.return_value='hf_unit_test'
        google=types.ModuleType('google');google.colab=colab
        with self.temporary() as d,patch.dict(sys.modules,{'google':google,'google.colab':colab}),patch.dict(os.environ),patch('subprocess.run') as pip,patch('pathlib.Path',return_value=Path(d)),redirect_stdout(output):
            values={};exec(setup,values);self.assertEqual(os.environ['NEBULA_HF_TOKEN'],'hf_unit_test');self.assertEqual(values['UPDATES_PER_ARM'],200)
        self.assertNotIn('hf_unit_test',output.getvalue());colab.userdata.get.assert_called_once_with('NEBULA_HF_TOKEN');pip.assert_called_once()
    def test_world_size_change_restores_optimizer_but_other_changes_reject(self):
        import v15_train
        helpers=V15Tests()
        with self.temporary() as d:
            root=Path(d);helpers.fixtures(root)
            with redirect_stdout(io.StringIO()):v15_train.main(helpers.arguments(root,'half.pt',steps=2))
            payload=torch.load(root/'half.pt',weights_only=True);payload['trainingState']['signature']['world']=2;torch.save(payload,root/'from-two.pt')
            with redirect_stdout(io.StringIO()):v15_train.main(helpers.arguments(root,'resumed.pt',resume='from-two.pt',steps=2))
            report=torch.load(root/'resumed.pt',weights_only=True)['metadata'];self.assertTrue(report['optimizerStateRestored']);self.assertTrue(report['worldSizeChangedOnResume']);self.assertEqual(report['stageSteps'],4)
            args=helpers.arguments(root,'invalid.pt',resume='from-two.pt',steps=2);args[args.index('--lr')+1]='0.002'
            with self.assertRaisesRegex(ValueError,'configuration changed'),redirect_stdout(io.StringIO()):v15_train.main(args)

if __name__=='__main__':unittest.main()
