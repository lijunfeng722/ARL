"""Linux 本机设置：只监听回环地址，使用每次启动的新令牌保护配置。"""
from __future__ import annotations

import argparse
import getpass
import hmac
import json
import os
import secrets
import stat
import threading
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path

from .codex_packages import PackageRegistry,atomic,read_private
from .contracts import Fault
from .linux_services import ServiceSettings,SERVICES,WRITE_MUSIC,descriptions,service_for
from .platform_paths import state_home


class Settings:
    def __init__(self,home):
        self.services=ServiceSettings(home);self.home=self.services.home
        self.lock=threading.RLock()

    def snapshot(self):
        result=self.services.snapshot()
        from .linux_host import CONFIG,configuration
        try:result['models']=dict(configuration(self.home),state='configured_not_probed')
        except FileNotFoundError:result['models']={'state':'not_configured'}
        except (OSError,ValueError,Fault):result['models']={'state':'invalid_configuration'}
        try:result['scheduler']=read_private(self.home/'model-scheduler-v1.json',4096)
        except FileNotFoundError:result['scheduler']=dict(schema_version=1,max_parallel=2)
        result['disabled']=(self.home/'disabled').exists()
        try:
            catalog=read_private(self.home/'CodexPackages/catalog-v2.json')
            config=PackageRegistry(self.home/'CodexPackages').load()
            result['packages']=dict(config,catalog=catalog)
        except (FileNotFoundError,Fault,ValueError):result['packages']=None
        return result

    def action(self,operation,data):
        if type(data) is not dict:raise Fault('invalid_arguments')
        with self.lock:
            return self._action(operation,data)

    def _action(self,operation,data):
        if operation=='configure':
            if set(data)-{'service','parameters','secret','apps','enabled','revision'} or not {'service','parameters','apps','enabled','revision'}<=set(data):raise Fault('invalid_arguments')
            return self.services.configure(data['service'],data['parameters'],secret=data.get('secret'),apps=data['apps'],enabled=data['enabled'],expected_revision=data['revision'])
        if operation in ('pause','remove'):
            if set(data)!={'service','revision'}:raise Fault('invalid_arguments')
            return getattr(self.services,operation)(data['service'],expected_revision=data['revision'])
        if operation=='scheduler':
            if set(data)!={'max_parallel'} or type(data['max_parallel']) is not int or not 1<=data['max_parallel']<=8:raise Fault('invalid_arguments')
            atomic(self.home/'model-scheduler-v1.json',dict(schema_version=1,**data))
            return {'saved':True,'restart_required':False}
        if operation=='models':
            from .linux_host import CONFIG,configuration
            import tempfile
            if set(data)!={'binary','sha256','model','max_calls'}:raise Fault('invalid_arguments')
            value=dict(schema_version=1,**data)
            with tempfile.TemporaryDirectory(dir=self.home) as temporary:
                atomic(Path(temporary)/CONFIG,value);configuration(temporary)
            atomic(self.home/CONFIG,value)
            return {'saved':True,'restart_required':True,'login_performed':False}
        if operation=='disable-models':
            if data:raise Fault('invalid_arguments')
            from .linux_host import CONFIG
            (self.home/CONFIG).unlink(missing_ok=True)
            return {'saved':True,'restart_required':True}
        if operation=='packages':
            catalog=read_private(self.home/'CodexPackages/catalog-v2.json')
            PackageRegistry(self.home/'CodexPackages').save(data,catalog['models'])
            return {'saved':True,'restart_required':False}
        if operation=='probe':
            # 仅点击检查时访问供应商；保存和查看页面从不执行连接测试。
            from .linux_service_io import execute
            from .contracts import validate
            if set(data)!={'service','tool','args'} or type(data['service']) is not str or data['service'] not in SERVICES:raise Fault('invalid_arguments')
            if type(data['tool']) is not str or data['tool'] not in descriptions() or service_for(data['tool'])!=data['service']:raise Fault('invalid_arguments')
            if data['tool'] in WRITE_MUSIC:raise Fault('probe_must_be_read_only')
            validate(data['args'],descriptions()[data['tool']])
            row=self.services.load()['services'].get(data['service'])
            if row is None:raise Fault('service_not_configured')
            execute(data['service'],row,data['tool'],data['args'])
            return {'connection':'read_response_received','scope':'one_explicit_read','inference_attempted':False}
        raise Fault('unknown_settings_operation')


class SettingsServer(ThreadingHTTPServer):
    daemon_threads=True
    def __init__(self,home,port=18745):
        self.settings=Settings(home)
        self.token=secrets.token_urlsafe(32)
        self.slots=threading.BoundedSemaphore(8)
        super().__init__(('127.0.0.1',port),Handler)
        self.origin='http://127.0.0.1:'+str(self.server_port)
        self.authority='127.0.0.1:'+str(self.server_port)
    def process_request(self,request,client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request);return
        try:super().process_request(request,client_address)
        except BaseException:self.slots.release();raise
    def process_request_thread(self,*args):
        try:super().process_request_thread(*args)
        finally:self.slots.release()


class Handler(BaseHTTPRequestHandler):
    server_version='ARL'
    def setup(self):
        super().setup();self.connection.settimeout(5)
    def log_message(self,*_):pass
    def reply(self,status,data,content_type='application/json; charset=utf-8'):
        body=data if isinstance(data,bytes) else json.dumps(data,ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header('Content-Type',content_type);self.send_header('Content-Length',str(len(body)))
        self.send_header('Cache-Control','no-store');self.send_header('Referrer-Policy','no-referrer')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Content-Security-Policy',"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
        self.end_headers();self.wfile.write(body)
    def allowed(self):
        if self.headers.get_all('Host')!=[self.server.authority]:return False
        origins=self.headers.get_all('Origin')
        if origins is not None and origins!=[self.server.origin]:return False
        if self.headers.get('Sec-Fetch-Site') not in (None,'same-origin','none'):return False
        return True
    def authorized(self):
        values=self.headers.get_all('Authorization')
        return bool(values and len(values)==1 and hmac.compare_digest(values[0],'Bearer '+self.server.token))
    def do_GET(self):
        if not self.allowed():return self.reply(403,{'error':'origin_rejected'})
        assets={'/':('linux_settings.html','text/html; charset=utf-8'),'/settings.js':('linux_settings.js','text/javascript; charset=utf-8'),'/settings.css':('linux_settings.css','text/css; charset=utf-8')}
        if self.path in assets:
            file,kind=assets[self.path]
            return self.reply(200,(Path(__file__).parent/'static'/file).read_bytes(),kind)
        if self.path!='/api/status':return self.reply(404,{'error':'not_found'})
        if not self.authorized():return self.reply(401,{'error':'authorization_required'})
        try:self.reply(200,self.server.settings.snapshot())
        except (OSError,ValueError,Fault):self.reply(400,{'error':'configuration_unavailable'})
    def do_POST(self):
        if not self.allowed():return self.reply(403,{'error':'origin_rejected'})
        if not self.authorized():return self.reply(401,{'error':'authorization_required'})
        try:
            if self.headers.get('Transfer-Encoding') or len(self.headers.get_all('Content-Length') or [])!=1 or self.headers.get('Content-Type')!='application/json':raise Fault('invalid_request')
            count=int(self.headers['Content-Length'])
            if not 0<count<=32768:raise Fault('invalid_request')
            raw=self.rfile.read(count)
            if len(raw)!=count:raise Fault('invalid_request')
            from .linux_service_io import strict_json
            if not self.path.startswith('/api/'):raise Fault('unknown_settings_operation')
            result=self.server.settings.action(self.path[5:],strict_json(raw))
            self.reply(200,result)
        except Fault as error:self.reply(400,{'error':error.code})
        except (OSError,ValueError,TypeError,KeyError):self.reply(400,{'error':'invalid_configuration'})


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=['status','serve','configure','pause','remove','probe'])
    parser.add_argument('--home',type=Path,default=state_home());parser.add_argument('--port',type=int,default=18745)
    parser.add_argument('--service',choices=SERVICES);parser.add_argument('--revision',type=int)
    parser.add_argument('--parameters',default='{}');parser.add_argument('--apps',default='')
    parser.add_argument('--enabled',action='store_true');parser.add_argument('--replace-secret',action='store_true')
    parser.add_argument('--tool');parser.add_argument('--args',default='{}')
    args=parser.parse_args()
    if os.name!='posix' or __import__('sys').platform!='linux':parser.error('此入口仅用于 Linux')
    try:
        settings=Settings(args.home)
        if args.command=='serve':
            if not 0<=args.port<=65535:parser.error('端口范围无效')
            server=SettingsServer(args.home,args.port)
            # 令牌仅显示在操作者终端；URL fragment 不进入 HTTP 请求与访问日志。
            print(server.origin+'/#'+server.token,flush=True)
            try:server.serve_forever()
            except KeyboardInterrupt:pass
            finally:server.server_close()
            return 0
        if args.command=='status':result=settings.snapshot()
        elif args.command=='probe':result=settings.action('probe',dict(service=args.service,tool=args.tool,args=json.loads(args.args)))
        else:
            if args.service is None or args.revision is None:parser.error('需要 --service 和从 status 取得的 --revision')
            data=dict(service=args.service,revision=args.revision)
            if args.command=='configure':
                data.update(parameters=json.loads(args.parameters),apps=[x for x in args.apps.split(',') if x],enabled=args.enabled)
                if args.replace_secret:data['secret']=getpass.getpass('服务凭据（不回显）：')
            result=settings.action(args.command,data)
        print(json.dumps(result,ensure_ascii=False));return 0
    except (OSError,ValueError,Fault) as error:
        print(json.dumps({'error':getattr(error,'code','settings_unavailable')}));return 1


if __name__=='__main__':raise SystemExit(main())
