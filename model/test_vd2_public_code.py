import io,tarfile,unittest
from vd2_public_code import collect
from vd2_data import sha
from compare_owned_models import grade,suite

def archive(license='Fixture license',files=None):
    out=io.BytesIO()
    with tarfile.open(fileobj=out,mode='w:gz') as tar:
        entries={'repo/LICENSE':license.encode(),**(files or {})}
        for name,data in entries.items():
            member=tarfile.TarInfo(name);member.size=len(data);tar.addfile(member,io.BytesIO(data))
    return out.getvalue()

class Tests(unittest.TestCase):
    def spec(self,blob):return dict(repo='owner/repo',revision='a'*40,prefix='',licensePath='LICENSE',license='MIT',licenseText='Fixture license',approved=True,origin='public-licensed',archiveSha256=sha(blob))
    def test_bad_license_or_archive_is_rejected(self):
        blob=archive();spec=self.spec(blob);spec['licenseText']='Unreviewed'
        with self.assertRaises(ValueError):collect([spec],fetcher=lambda s:blob)
        spec=self.spec(blob);spec['archiveSha256']='0'*64
        with self.assertRaises(ValueError):collect([spec],fetcher=lambda s:blob)
    def test_paths_syntax_and_duplicate_filtering_without_execution(self):
        text=b'def total(values):\n    # A complete independently syntax-checked file.\n    return sum(values)\n'
        blob=archive(files={'repo/src/a.py':text,'repo/src/b.py':text,'repo/../escape.py':text,'repo/vendor/c.py':text,'repo/src/bad.py':b'def broken(\n'+b'#'*80})
        corpus,provenance,skipped=collect([self.spec(blob)],fetcher=lambda s:blob)
        self.assertEqual(len(corpus.records),1);self.assertEqual(skipped['syntax-or-encoding'],1);self.assertEqual(provenance[0]['syntaxCheckedPythonFiles'],2)
    def test_comparison_scores_do_not_accept_echoed_question_numbers(self):
        case=suite()[0];self.assertFalse(grade(case,'28 + 47 = 75'));self.assertTrue(grade(case,'75'))
    def test_coding_grade_checks_the_requested_function_body(self):
        case=next(c for c in suite() if c['category']=='coding_static')
        self.assertTrue(grade(case,'def total_lumens(values):\n    return sum(values)'))
        self.assertFalse(grade(case,'def total_lumens(values):\n    return max(values)'))
        self.assertFalse(grade(case,'sum(values)'))
if __name__=='__main__':unittest.main()
