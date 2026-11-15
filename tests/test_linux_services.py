"""隔离配置、合成供应商响应、NAS 路径和真实本机 socket；不访问账号。"""
import base64
import hashlib
import http.client
import json
import os
import stat
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from arl.client import Client
from arl.contracts import Fault
from arl.linux_host import make_runtime
from arl.linux_services import ServiceSettings,Services,CONFIG,NAS_LIST,NAS_READ
from arl.linux_service_io import execute,travel,strict_json
from arl.linux_settings import Settings,SettingsServer


class LinuxServicesTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir='/var/tmp')
        self.home=Path(self.temp.name);self.home.chmod(0o700)
        self.settings=ServiceSettings(self.home)
    def tearDown(self):self.temp.cleanup()
    def nas(self):
        root=self.home/'share';root.mkdir();(root/'sample.txt').write_text('合成文本')
        self.settings.configure('nas',{'root':str(root)},apps=['demo'],enabled=True,expected_revision=0)
        return root
    def test_wheel_protocol_snapshots_match_source(self):
        root=Path(__file__).resolve().parents[1]
        for name in ('mio-tools.json','service-connections.json'):
            self.assertEqual((root/'docs'/name).read_bytes(),(root/'arl/static'/name).read_bytes())

    def test_private_settings_redact_secret_and_require_revision(self):
        self.settings.configure('amap',{},secret='synthetic-key',apps=['demo'],enabled=True,expected_revision=0)
        self.assertNotIn('synthetic-key',json.dumps(self.settings.snapshot()))
        self.assertEqual(stat.S_IMODE((self.home/CONFIG).stat().st_mode),0o600)
        with self.assertRaises(Fault):self.settings.pause('amap',expected_revision=0)
        self.settings.pause('amap',expected_revision=1)
        self.assertFalse(Services(self.home).grants('demo'))
        self.settings.configure('amap',{},apps=[],enabled=True,expected_revision=2)
        self.assertEqual(self.settings.load()['services']['amap']['secret'],'synthetic-key')
        with self.assertRaises(Fault):self.settings.configure('amap',{},apps=[[]],expected_revision=3)
    def test_music_writes_need_separate_opt_in_and_probe_cannot_write(self):
        from arl.linux_services import WRITE_MUSIC
        params={'binary':'/synthetic/ncm','sha256':'a'*64}
        self.settings.configure('netease',params,apps=['demo'],enabled=True,expected_revision=0)
        broker=Services(self.home)
        self.assertFalse(broker.grants('demo')&WRITE_MUSIC)
        self.settings.configure('netease',dict(params,allow_writes=True),apps=['demo'],enabled=True,expected_revision=1)
        self.assertEqual(broker.grants('demo')&WRITE_MUSIC,WRITE_MUSIC)
        self.assertTrue(all(not t.idempotent for t in broker.tools() if t.name in WRITE_MUSIC))
        with self.assertRaises(Fault):Settings(self.home).action('probe',dict(service='netease',tool='netease.playlist.create.v1',args={'name':'synthetic'}))

    def test_unsafe_secret_file_and_duplicate_json_rejected(self):
        self.nas();(self.home/CONFIG).chmod(0o644)
        with self.assertRaises(Fault):self.settings.load()
        for value in (b'{"a":1,"a":2}',b'{"a":NaN}'):
            with self.assertRaises(Fault):strict_json(value)
    def test_nas_read_is_bounded_and_cannot_escape_by_links(self):
        root=self.nas();row=self.settings.load()['services']['nas']
        data=execute('nas',row,NAS_READ,{'path':'sample.txt'})
        self.assertEqual(base64.b64decode(data['data']).decode(),'合成文本')
        (root/'linked').symlink_to(self.home/CONFIG)
        for path in ('../'+CONFIG,'/etc/passwd','linked'):
            with self.assertRaises(Fault):execute('nas',row,NAS_READ,{'path':path})
        (root/'large').write_bytes(b'x'*32769)
        with self.assertRaises(Fault):execute('nas',row,NAS_READ,{'path':'large'})
        os.mkfifo(root/'pipe')
        with self.assertRaises(Fault):execute('nas',row,NAS_READ,{'path':'pipe'})
        names=[x['name'] for x in execute('nas',row,NAS_LIST,{})['entries']]
        self.assertNotIn('linked',names)
    def test_weather_alias_and_secret_echo_are_checked(self):
        calls=[];row={'secret':'synthetic-key'}
        def send(*args):calls.append(args);return 'application/json',b'{"status":"1","infocode":"10000","lives":[]}'
        value=travel(row,'mio_maps_weather',{'adcode':'110101','mode':'forecast'},send)
        self.assertTrue(value['adaptation']['complete'])
        self.assertIn('city=110101',calls[0][1]);self.assertIn('extensions=all',calls[0][1])
        with self.assertRaises(Fault):travel(row,'mio_maps_weather',{'city':'x','adcode':'y'},send)
        with self.assertRaises(Fault):travel(row,'mio_maps_weather',{'city':'x'},lambda *a:('application/json',b'{"status":"1","secret":"synthetic-key"}'))
    def test_network_worker_keeps_secrets_out_of_argv_and_has_total_timeout(self):
        from arl.linux_service_io import request
        import subprocess
        reply=json.dumps(dict(media='application/json',body=base64.b64encode(b'{}').decode())).encode()
        with patch('arl.linux_service_io.subprocess.run',return_value=SimpleNamespace(returncode=0,stdout=reply)) as run:
            self.assertEqual(request('GET','https://restapi.amap.com/test',{'Authorization':'synthetic-secret'},None)[1],b'{}')
            self.assertNotIn('synthetic-secret',repr(run.call_args.args))
            self.assertEqual(run.call_args.kwargs['timeout'],12)
        with patch('arl.linux_service_io.subprocess.run',side_effect=subprocess.TimeoutExpired('synthetic',12)):
            with self.assertRaises(Fault) as failure:request('GET','https://restapi.amap.com/test',{},None)
            self.assertEqual(failure.exception.code,'service_timed_out')

    def test_flyai_signed_post_uses_numeric_arguments_and_sse_envelope(self):
        calls=[]
        def send(*args):calls.append(args);return 'text/event-stream',b'data: {"jsonrpc":"2.0","id":1,"result":{"structuredContent":{"status":0,"data":{"itemList":[]}}}}\n\n'
        with patch('arl.linux_service_io.fly_context',return_value=('synthetic agent','synthetic-context')):
            travel({'secret':'synthetic-key'},'mio_flyai_search_flight',{'origin':'Shanghai','journey_type':'1','max_price':1234},send)
        method,url,headers,body=calls[0]
        self.assertEqual(method,'POST');self.assertEqual(url,'https://flyai.open.fliggy.com/mcp')
        args=json.loads(body)['params']['arguments'];self.assertEqual(args['journeyType'],1)
        self.assertEqual(args['maxPrice'],1234);self.assertEqual(headers['x-flyai-sign-ver'],'7')
        self.assertTrue(headers['x-flyai-sign'])
    def test_vendor_success_requires_business_status_and_rejects_unknown_credentials(self):
        row={'secret':'synthetic-key'}
        for body in (b'{}',b'{"status":"1","infocode":"10000","access_token":"unexpected"}'):
            with self.assertRaises(Fault):travel(row,'mio_maps_weather',{'city':'test'},lambda *a:('application/json',body))
        with patch('arl.linux_service_io.fly_context',return_value=('agent','context')):
            raw=b'{"jsonrpc":"2.0","id":1,"result":{"structuredContent":{"status":401,"data":{}}}}'
            with self.assertRaises(Fault):travel(row,'mio_flyai_search_flight',{'origin':'test'},lambda *a:('application/json',raw))

    def test_revocation_during_read_never_returns_result(self):
        self.settings.configure('amap',{},secret='synthetic-key',apps=['demo'],enabled=True,expected_revision=0)
        def send(*args):
            self.settings.pause('amap',expected_revision=1)
            return 'application/json',b'{"status":"1","infocode":"10000","lives":[]}'
        broker=Services(self.home,request=send)
        with self.assertRaises(Fault):broker.call('demo','mio_maps_weather',{'city':'test'},SimpleNamespace(check_cancelled=lambda:None))
    def test_runtime_grants_read_only_service_and_revokes_without_restart(self):
        self.nas();runtime=make_runtime(self.home)
        thread=threading.Thread(target=runtime.run,daemon=True);thread.start()
        client=Client(self.home,'demo')
        try:
            Client(self.home,'settings').connect(timeout=5)
            accepted=client.open_app_session('演示应用',[NAS_LIST,NAS_READ])
            self.assertIn(NAS_LIST,accepted)
            job=client.submit(NAS_READ,{'path':'sample.txt'},'synthetic-read')
            result=client.wait(job["id"],timeout=5)
            self.assertEqual(result['state'],'succeeded')
            self.settings.pause('nas',expected_revision=1)
            with self.assertRaises(Fault):client.submit(NAS_LIST,{},'revoked')
            self.assertFalse(any(x.startswith('apple.') for x in runtime.policies['demo'].tools))
        finally:
            client.close_app_session();runtime.shutdown();thread.join(10)
        self.assertFalse(thread.is_alive())


class SettingsHTTPTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir='/var/tmp');Path(self.temp.name).chmod(0o700)
        self.server=SettingsServer(self.temp.name,0)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
    def tearDown(self):self.server.shutdown();self.server.server_close();self.thread.join();self.temp.cleanup()
    def call(self,method,path,data=None,**headers):
        client=http.client.HTTPConnection('127.0.0.1',self.server.server_port,timeout=3)
        headers.setdefault('Authorization','Bearer '+self.server.token)
        raw=json.dumps(data) if data is not None else None
        if raw is not None:headers['Content-Type']='application/json'
        client.request(method,path,raw,headers);response=client.getresponse();body=response.read();client.close()
        return response.status,body
    def test_loopback_requires_token_and_rejects_foreign_origin_and_host(self):
        status,raw=self.call('GET','/api/status');self.assertEqual(status,200)
        self.assertNotIn(self.server.token.encode(),raw)
        self.assertEqual(self.call('GET','/api/status',Authorization='Bearer wrong')[0],401)
        self.assertEqual(self.call('GET','/api/status',Origin='https://example.invalid')[0],403)
        self.assertEqual(self.call('GET','/api/status',Host='example.invalid')[0],403)
        self.assertEqual(self.call('GET','/')[0],200)
    def test_configuration_does_not_probe_and_status_never_echoes_secret(self):
        with patch('arl.linux_service_io.execute',side_effect=AssertionError('不得连接')):
            status,raw=self.call('POST','/api/configure',dict(service='amap',parameters={},secret='synthetic-key',apps=['demo'],enabled=False,revision=0))
            self.assertEqual(status,200);self.assertNotIn(b'synthetic-key',raw)
            self.assertEqual(self.call('POST','/api/scheduler',{'max_parallel':3})[0],200)
            self.assertEqual(self.call('POST','/api/scheduler',{'max_parallel':99})[0],400)
            self.assertEqual(self.call('GET','/api/status')[0],200)


if __name__=='__main__':unittest.main()
