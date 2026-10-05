"""10 проверок интеграции: subprocess-заглушки с реальными CLI, без внешней сети."""
from __future__ import annotations

import ast
import asyncio
from contextlib import redirect_stdout, redirect_stderr
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import unittest
from unittest.mock import patch

from pipeline_manager import Pipeline, ProcessRunner, Scope, arguments, filter_records
from start import pipeline_args

ROOT = Path(__file__).resolve().parent

# Каждый дочерний процесс сначала проверяет argv настоящим парсером сканера.
SHIM = r'''
import importlib.util, json, os, sys, time
from pathlib import Path
from unittest.mock import patch
name = Path(sys.argv[0]).name
root = Path(__ROOT__)
sys.path.insert(0, str(root))
spec = importlib.util.spec_from_file_location('checked_child', root / name)
module = importlib.util.module_from_spec(spec)
sys.modules['checked_child'] = module
spec.loader.exec_module(module)
with patch('shutil.which', return_value='/fake/tool'):
    if name == 'scanner.py':
        args, _, _ = module.arguments(sys.argv[1:])
    elif name == 'post_scanner.py':
        args, _, _, _ = module.load_args(sys.argv[1:])
    elif name == 'smuggling_scanner.py':
        args = module.build_parser().parse_args(sys.argv[1:])
        module.load_targets(args)
    else:
        args = module.arguments(sys.argv[1:])
log = Path(__CALLS__)
def event(kind):
    with log.open('a') as stream:
        stream.write(json.dumps({'script':name,'event':kind,'time':time.monotonic(),'argv':sys.argv[1:]})+'\n')
event('begin')
if Path(__FAIL__).exists() and Path(__FAIL__).read_text() == name:
    print('intentional fixture failure', file=sys.stderr)
    raise SystemExit(7)
if name in ('scanner.py', 'post_scanner.py'):
    time.sleep(.15)
output = Path(args.output)
output.mkdir(parents=True, exist_ok=True)
if name == 'js_secrets_finder.py':
    (output/'extracted_endpoints.txt').write_text('https://example.test/from-js?id=8\nhttps://outside.test/api?id=9\nhttps://deny.example.test/api?id=1\n')
if name == 'subdomain_monitor.py':
    (output/'known_subdomains.txt').write_text('example.test\n')
(output/'summary.json').write_text(json.dumps({'status':'completed'}))
event('end')
'''

class IntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.tools = self.base / 'tools'
        self.tools.mkdir()
        self.calls = self.base / 'calls.jsonl'
        self.failure = self.base / 'failure'
        self.targets = self.base / 'targets.txt'
        self.targets.write_text('example.test\n')
        self.recon = self.base / 'recon.txt'
        self.recon.write_text('https://example.test/page?id=1\nhttps://example.test/main.js\nhttps://outside.test/main.js\n')
        self.post = self.base / 'post_requests.jsonl'
        self.post.write_text(json.dumps({'url':'https://example.test/search','method':'POST','body':'q=hello'})+'\n')
        (self.base / 'first.cookie').write_text('session=first-test-account')
        (self.base / 'second.cookie').write_text('session=second-test-account')
        self.idor = self.base / 'idor_requests.jsonl'
        self.idor.write_text(json.dumps({'url':'https://example.test/order', 'data':{'id':100}, 'json':True,
            'cookie_victim_file':'first.cookie','cookie_attacker_file':'second.cookie',
            'attacker_ids':{'id':200},'id_params':['id']})+'\n')
        code = SHIM.replace('__ROOT__',repr(str(ROOT))).replace('__CALLS__',repr(str(self.calls))).replace('__FAIL__',repr(str(self.failure)))
        for name in ('scanner.py','post_scanner.py','js_secrets_finder.py','idor_scanner.py','subdomain_monitor.py','smuggling_scanner.py'):
            (self.tools/name).write_text(code)
        self.old_umask = os.umask(0o077)

    async def asyncTearDown(self):
        os.umask(self.old_umask)
        self.tmp.cleanup()

    def make(self, extra=(), all_stages=True):
        argv = ['--targets',str(self.targets),'--recon-input',str(self.recon),
                '--get-scanner',str(self.tools/'scanner.py'),'--post-scanner',str(self.tools/'post_scanner.py'),
                '--python',sys.executable,'--output',str(self.base/'runs'),
                '--error-log',str(self.base/'errors.log'),'--monitor-output',str(self.base/'monitor'),
                '--rate','1000','--workers','2','--exclude-host','deny.example.test',*extra]
        if all_stages:
            argv.insert(0,'--all')
        args = arguments(pipeline_args(argv,self.base))
        pipeline = Pipeline(args)
        pipeline.extras.root = self.tools
        return pipeline

    async def execute(self,pipeline):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            result = await pipeline.run()
        return result, [json.loads(x) for x in self.calls.read_text().splitlines()] if self.calls.exists() else []

    def starts(self, events):
        return [e['script'] for e in events if e['event']=='begin']

    async def test_01_launcher_flags_and_python310_syntax(self):
        values = pipeline_args(['--all','--without-smuggling','--oast-domain','oast.example.test'],self.base)
        self.assertIn('--with-js',values)
        self.assertIn('--with-monitor',values)
        self.assertNotIn('--with-smuggling',values)
        self.assertIn(str(self.idor),values)
        self.assertIn('xss,lfi,redirect,sqli,ssti,crlf,ssrf',values)
        self.assertIn('gau --providers wayback --threads 2 --o {output} {domain}',values)
        with self.assertRaises(ValueError):
            pipeline_args(['--with-js','--without-js'],self.base)
        for file in ROOT.rglob('*.py'):
            if '.venv' not in file.parts:
                ast.parse(file.read_text(),feature_version=(3,10))

    async def test_02_scope_keeps_js_without_query(self):
        path = self.base/'records.txt'
        path.write_text('https://example.test/app.js?v=1\nhttps://example.test/plain.js\n'
                        'https://example.test/api?id=1\nhttps://sub.example.test/app.js\n'
                        'https://example.test:8080/app.js\nhttps://example.test.evil.test/app.js\n')
        data = filter_records([path],Scope('example.test'),100,10000)
        self.assertEqual(len(data.resource_urls),3)
        self.assertIn('https://example.test/plain.js',data.resource_urls)
        self.assertEqual(data.counts['out_of_scope'],3)

    async def test_03_all_serial_with_real_cli_contracts(self):
        result,events = await self.execute(self.make(['--mode','serial']))
        self.assertEqual(result['status'],'completed',result)
        self.assertEqual(self.starts(events),['subdomain_monitor.py','js_secrets_finder.py',
            'scanner.py','post_scanner.py','idor_scanner.py','smuggling_scanner.py'])
        folder = Path(result['directory'])/'example.test'
        urls = (folder/'get_urls.txt').read_text()
        self.assertIn('/from-js?id=8',urls)
        self.assertNotIn('outside.test',urls)
        self.assertNotIn('deny.example.test',urls)
        monitor = events[0]['argv']
        self.assertIn('--roots-only',monitor)
        idor = next(e for e in events if e['script']=='idor_scanner.py')
        self.assertIn('--data-file',idor['argv'])
        self.assertNotIn('session=first-test-account',json.dumps(events))
        self.assertEqual(result['targets'][0]['smuggling']['state'],'ok')

    async def test_04_parallel_only_get_post_overlap(self):
        result,events = await self.execute(self.make(['--mode','parallel']))
        self.assertEqual(result['status'],'completed',result)
        times = {(e['script'],e['event']):e['time'] for e in events}
        self.assertLess(max(times[('scanner.py','begin')],times[('post_scanner.py','begin')]),
                        min(times[('scanner.py','end')],times[('post_scanner.py','end')]))
        self.assertGreater(times[('idor_scanner.py','begin')],max(times[('scanner.py','end')],times[('post_scanner.py','end')]))
        self.assertGreater(times[('smuggling_scanner.py','begin')],times[('idor_scanner.py','end')])

    async def test_05_child_crash_does_not_stop_other_stages(self):
        self.failure.write_text('js_secrets_finder.py')
        result,events = await self.execute(self.make(['--mode','serial']))
        self.assertEqual(result['status'],'completed_with_errors')
        self.assertIn('smuggling_scanner.py',self.starts(events))
        self.assertEqual(result['targets'][0]['js']['state'],'nonzero')
        self.assertIn('js',(self.base/'errors.log').read_text())
        js_error = Path(result['targets'][0]['js']['stderr']).read_text()
        self.assertIn('intentional fixture failure',js_error)

    async def test_06_offline_dry_run_runs_no_children(self):
        result,events = await self.execute(self.make(['--dry-run']))
        self.assertEqual(events,[])
        self.assertEqual(result['monitor']['state'],'skipped')
        self.assertEqual(result['targets'][0]['status'],'prepared_only')
        self.assertEqual(result['targets'][0]['idor']['state'],'skipped')
        self.assertTrue((Path(result['directory'])/'example.test/js_urls.txt').exists())

    async def test_07_idor_outside_scope_and_cookie_paths(self):
        row = json.loads(self.idor.read_text())
        row['url']='https://outside.test/order'
        self.idor.write_text(json.dumps(row)+'\n')
        result,events = await self.execute(self.make(['--without-monitor','--without-js','--without-smuggling']))
        self.assertNotIn('idor_scanner.py',self.starts(events))
        self.assertEqual(result['idor_scope']['out_of_scope'],1)
        self.idor.unlink()
        values = pipeline_args(['--all'],self.base)
        self.assertNotIn('--idor-config',values)
        self.assertIn('--post-input',values)

    async def test_08_monitor_exact_scope_history_and_smuggling_summary(self):
        spec=importlib.util.spec_from_file_location('monitor_test',ROOT/'subdomain_monitor.py')
        m=importlib.util.module_from_spec(spec)
        sys.modules['monitor_test']=m
        spec.loader.exec_module(m)
        self.assertTrue(m.Scope(('example.test',),(),False).contains('example.test'))
        self.assertFalse(m.Scope(('example.test',),(),False).contains('sub.example.test'))
        self.assertTrue(m.Scope(('example.test',),(),True).contains('sub.example.test'))
        with patch('shutil.which',return_value=None):
            args=m.arguments(['--targets',str(self.targets),'--roots-only'])
            self.assertTrue(args.roots_only)
        result,_=await self.execute(self.make(['--dry-run']))
        self.assertEqual(result['monitor']['state'],'skipped')
        sm_spec=importlib.util.spec_from_file_location('smuggling_test',ROOT/'smuggling_scanner.py')
        sm=importlib.util.module_from_spec(sm_spec)
        sys.modules['smuggling_test']=sm
        sm_spec.loader.exec_module(sm)
        parsed=sm.build_parser().parse_args(['-u','https://example.test/','-o',str(self.base/'smug')])
        reports=sm.Reports(parsed.output)
        with patch.object(sm.Scanner,'scan',return_value='inconclusive'), redirect_stdout(io.StringIO()):
            await sm.run(parsed,[sm.parse_target(parsed.url)],reports)
        reports.close()
        summary=json.loads((parsed.output/'summary.json').read_text())
        self.assertEqual(summary['status'],'completed_with_inconclusive')
        self.assertEqual((parsed.output/'summary.json').stat().st_mode & 0o777,0o600)

    async def test_09_timeout_and_stop_reap_child(self):
        stop=asyncio.Event()
        runner=ProcessRunner(stop,grace=.05)
        hung=[sys.executable,'-c','import time; time.sleep(30)']
        result=await runner.run(hung,'hang',self.base/'timeout',.1)
        self.assertEqual(result.state,'timeout')
        task=asyncio.create_task(runner.run(hung,'cancel',self.base/'cancel',20))
        await asyncio.sleep(.05)
        stop.set()
        result=await task
        self.assertEqual(result.state,'interrupted')
        self.assertIsNotNone(result.returncode)

    async def test_10_start_exec_and_real_pipeline_end_to_end(self):
        stop=asyncio.Event()
        runner=ProcessRunner(stop,grace=.2)
        command=[sys.executable,str(ROOT/'start.py'),'--all','--dry-run',
            '--targets',str(self.targets),'--recon-input',str(self.recon),
            '--output',str(self.base/'launch_runs'),'--error-log',str(self.base/'launch_errors.log'),
            '--idor-config',str(self.idor),'--post-input',str(self.post)]
        result=await runner.run(command,'start',self.base/'start_logs',10,cwd=ROOT)
        self.assertEqual(result.state,'ok',Path(result.stderr).read_text())
        files=list((self.base/'launch_runs').glob('*/pipeline_summary.json'))
        self.assertEqual(len(files),1)
        summary=json.loads(files[0].read_text())
        self.assertEqual(summary['status'],'completed')
        self.assertEqual(summary['targets'][0]['status'],'prepared_only')
        self.assertIn('IDOR',Path(result.stdout).read_text())

if __name__=='__main__':
    unittest.main(verbosity=2)
