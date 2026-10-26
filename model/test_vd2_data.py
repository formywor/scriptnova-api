import unittest
from vd2_data import *
class Tests(unittest.TestCase):
 def src(self,split='train'):return dict(repo='owner/data',revision='abc',key='code',approved=True,license='owner-created',origin='owner-code',split=split)
 def text(self):return 'def safe_total(values):\n    # Validate inputs before summing numeric values.\n    return sum(values)\n'
 def test_count(self):self.assertEqual(parameter_count(),1007334912)
 def test_holdout_isolation(self):
  c=Corpus();c.add(self.text(),self.src());c.add(self.text().replace('    ','  '),self.src('validation'));self.assertEqual(len(c.records),1);self.assertEqual(next(iter(c.records.values()))['split'],'validation')
 def test_secret_filter(self):self.assertIsNone(clean('def test():\n    return "gsk_'+'A'*45+'"\n'+'x'*80))
 def test_admission(self):
  c=Corpus();s=self.src();s['origin']='historical-unreviewed'
  with self.assertRaises(ValueError):c.add(self.text(),s)
 def test_coding_category(self):self.assertEqual(category(self.text()),'code');self.assertEqual(category('Once upon a time there was a small boat.'),'general')
 def test_bytes_and_subword_separation(self):
  blob=struct.pack('<5H',256,104,105,257,258);self.assertEqual(list(texts(blob,'bytes-u16')),['hi'])
  with self.assertRaises(ValueError):list(texts(b'x','bytes-u16'))
 def test_omit_private_chat(self):
  blob=json.dumps(dict(source={'kind':'user'},text=self.text())).encode();self.assertEqual(list(texts(blob,'jsonl')),[])
 def test_inventory_ignores_weights_and_evaluation(self):
  entry=dict(bytes=2,sha256='0'*64,path='experiments/run/code.jsonl');state={'trainData':entry,'evaluation':entry,'working':dict(entry,path='weights.pt')};r=candidates('owner/model','abc','state.json',state);self.assertEqual(len(r),1);self.assertFalse(r[0]['approved'])
 def test_holdout_names_and_stale_manual_split(self):
  for name in ['publicHoldout','newPublicHoldout','held_out','held-out','validationData']:
   entry=dict(bytes=2,sha256='0'*64,path='data.jsonl')
   row=candidates('owner/model','abc','state.json',{name:entry})[0]
   self.assertEqual(row['split'],'validation',name)
   row.update(self.src(),key=name,split='train');c=Corpus();c.add(self.text(),row)
   self.assertEqual(next(iter(c.records.values()))['split'],'validation',name)
 def test_audit_is_read_only_and_quarantines_aliases(self):
  from vd2_audit import audit_sources
  blob=json.dumps({'text':self.text()}).encode();entry=dict(bytes=len(blob),sha256=sha(blob),path='data.jsonl')
  rows=[dict(self.src(),key=name,format='jsonl',entry=entry) for name in ['trainData','publicHoldout']]
  calls=[]
  def read(*args):calls.append(args);return blob
  report=audit_sources({'candidates':rows},reader=read)
  self.assertEqual(len(calls),1);self.assertEqual(report['counts'],{'validation/code':1});self.assertFalse(report['sourcesApproved'])
 def test_audit_discards_partially_parsed_objects(self):
  from vd2_audit import audit_sources
  blob=(json.dumps({'text':self.text()})+'\n{broken').encode()
  row=dict(self.src(),format='jsonl',entry=dict(bytes=len(blob),sha256=sha(blob),path='data.jsonl'))
  report=audit_sources({'candidates':[row]},reader=lambda *args:blob)
  self.assertEqual(report['counts'],{});self.assertEqual(report['sources'][0]['status'],'inspection_failed')
if __name__=='__main__':unittest.main()
