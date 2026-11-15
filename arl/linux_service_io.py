"""Linux 只读服务传输；固定供应商端点、已挂载 NAS 和已核对的官方 CLI。"""
from __future__ import annotations

import base64
import gzip
import hashlib
import hmac
import json
import math
import os
import platform
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from types import SimpleNamespace

from .contracts import Fault
from .linux_services import NAS_LIST, NAS_READ, READ_MUSIC, WRITE_MUSIC

MAP_PATHS = dict(geo='/v3/geocode/geo',regeocode='/v3/geocode/regeo',text_search='/v3/place/text',
    around_search='/v3/place/around',search_detail='/v3/place/detail',direction_driving='/v3/direction/driving',
    direction_walking='/v3/direction/walking',bicycling='/v4/direction/bicycling',
    direction_transit_integrated='/v3/direction/transit/integrated',distance='/v3/distance',weather='/v3/weather/weatherInfo')
# 来源与现有 Swift 客户端一致：供应商公开 CLI 1.0.16 协议材料，不是用户密钥。
SIGNING = b'XSbdYnucPARDc9knhD8+X6hxdD1Nh6ZGI6Hadg25kBw='
NUMERIC = {'journey_type','sort_type','dep_hour_start','dep_hour_end','arr_hour_start','arr_hour_end','total_duration_hour','max_price','limit','poi_level'}


def strict_json(raw):
    def pairs(rows):
        out={}
        for key,value in rows:
            if key in out:raise Fault('service_protocol_failure')
            out[key]=value
        return out
    try:return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError()))
    except (ValueError,UnicodeError,RecursionError):raise Fault('service_protocol_failure') from None


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*_):raise Fault('service_redirect_rejected')


def _request_direct(method,url,headers,body):
    """不继承代理，不跟随重定向，不把供应商正文和凭据放入异常。"""
    parsed=urllib.parse.urlsplit(url)
    if (parsed.scheme!='https' or parsed.hostname not in {'restapi.amap.com','flyai.open.fliggy.com'}
            or parsed.username or parsed.password or parsed.port or parsed.fragment):
        raise Fault('service_endpoint_rejected')
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    try:
        with opener.open(urllib.request.Request(url,data=body,headers=headers,method=method),timeout=12) as response:
            raw=response.read(60001)
            if len(raw)>60000:raise Fault('service_response_too_large')
            return response.headers.get_content_type(),raw
    except urllib.error.HTTPError as error:
        code={401:'service_credential_rejected',403:'service_permission_denied',429:'service_rate_limited'}.get(error.code,'service_vendor_unavailable')
        raise Fault(code) from None
    except (urllib.error.URLError,TimeoutError,OSError):raise Fault('service_network_unavailable') from None


def request(method,url,headers,body):
    """将 DNS、TLS 和响应读取一起纳入可杀死的十二秒进程预算。"""
    packet=json.dumps(dict(method=method,url=url,headers=headers,
        body=base64.b64encode(body).decode() if body is not None else None)).encode()
    if len(packet)>32768:raise Fault('service_request_too_large')
    code='import sys;sys.path.insert(0,'+repr(str(Path(__file__).resolve().parents[1]))+');from arl.linux_service_io import read_worker;read_worker()'
    try:
        result=subprocess.run([sys.executable,'-I','-B','-c',code],input=packet,
            stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=12,
            env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'})
    except subprocess.TimeoutExpired:raise Fault('service_timed_out') from None
    except OSError:raise Fault('service_network_unavailable') from None
    if result.returncode or len(result.stdout)>85000:raise Fault('service_protocol_failure')
    value=strict_json(result.stdout)
    if type(value) is not dict:raise Fault('service_protocol_failure')
    if 'error' in value:
        allowed={'service_redirect_rejected','service_endpoint_rejected','service_response_too_large',
            'service_credential_rejected','service_permission_denied','service_rate_limited',
            'service_vendor_unavailable','service_network_unavailable','service_protocol_failure'}
        raise Fault(value['error'] if value['error'] in allowed else 'service_protocol_failure')
    try:return value['media'],base64.b64decode(value['body'],validate=True)
    except (KeyError,ValueError,TypeError):raise Fault('service_protocol_failure') from None


def read_worker():
    try:
        packet=strict_json(sys.stdin.buffer.read(32769))
        body=base64.b64decode(packet['body'],validate=True) if packet['body'] is not None else None
        media,raw=_request_direct(packet['method'],packet['url'],packet['headers'],body)
        result=dict(media=media,body=base64.b64encode(raw).decode())
    except Fault as error:result={'error':error.code}
    except Exception:result={'error':'service_protocol_failure'}
    sys.stdout.write(json.dumps(result))


def fly_context():
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    cpus=os.cpu_count() or 1
    memory=os.sysconf('SC_PAGE_SIZE')*os.sysconf('SC_PHYS_PAGES')/(1024**3)
    tier=next((n for n in (2,4,8,16,32) if memory<=n),32)
    agent='ARLLinuxSettings/1.0 (Python; FlyAI transport 1.0.16)'
    value={'machine':{'platform':'linux','arch':'x64' if platform.machine()=='x86_64' else platform.machine(),
        'cpus':cpus,'memoryTierGB':tier,'osType':'Linux','nodeVersion':'python','osReleaseMajor':platform.release().split('.')[0]},
        'fingerprint':{'language':'en','platform':'Linux','userAgent':agent,'hardwareConcurrency':cpus,
        'deviceMemory':min(8,max(2,tier)),'clientSurface':'native','timezoneOffset':-time.timezone//60,
        'deviceId':hashlib.sha256(uuid.uuid4().bytes).hexdigest()}}
    nonce=os.urandom(12)
    sealed=AESGCM(hashlib.sha256(SIGNING).digest()).encrypt(nonce,gzip.compress(json.dumps(value,sort_keys=True).encode(),mtime=0),None)
    return agent,base64.b64encode(b'\x01'+nonce+sealed).decode()


def travel(row,name,args,send):
    if 'cursor' in args:raise Fault('service_cursor_unavailable')
    if any(isinstance(v,str) and any(ord(c)<32 or ord(c)==127 for c in v) for v in args.values()):
        raise Fault('invalid_arguments')
    secret=row['secret']
    if name.startswith('mio_maps_'):
        operation=name.removeprefix('mio_maps_');query=dict(args)
        if operation=='text_search' and not (query.get('keywords') or query.get('types')):raise Fault('invalid_arguments')
        if operation=='weather':
            city=query.pop('adcode',None);mode=query.pop('mode',None)
            if city and query.get('city',city)!=city:raise Fault('invalid_arguments')
            if city:query['city']=city
            if not query.get('city'):raise Fault('invalid_arguments')
            if mode:
                expected='all' if mode=='forecast' else 'base'
                if query.get('extensions',expected)!=expected:raise Fault('invalid_arguments')
                query['extensions']=expected
        query.update(key=secret,output='JSON')
        media,raw=send('GET','https://restapi.amap.com'+MAP_PATHS[operation]+'?'+urllib.parse.urlencode(query),{'Accept':'application/json'},None)
        result=strict_json(raw)
        success=(type(result) is dict and (str(result.get('errcode'))=='0' if operation=='bicycling'
                 else str(result.get('status'))=='1' and str(result.get('infocode'))=='10000'))
        if not success:
            raise Fault('service_vendor_rejected')
    else:
        names={'mio_flyai_search_flight':'search_flight','mio_flyai_search_hotel':'search_hotels',
            'mio_flyai_keyword_search':'fliggy_fast_search','mio_flyai_ai_search':'fliggy_ai_search',
            'mio_flyai_search_train':'search_domestic_train','mio_flyai_search_poi':'search_poi'}
        mapped={}
        for key,value in args.items():
            if key in NUMERIC:
                try:value=json.loads(value) if isinstance(value,str) else value
                except ValueError:raise Fault('invalid_arguments') from None
                if type(value) not in (int,float) or not math.isfinite(value):raise Fault('invalid_arguments')
            parts=key.split('_');mapped[parts[0]+''.join(x.title() for x in parts[1:])]=value
        body=json.dumps(dict(id=1,jsonrpc='2.0',method='tools/call',params=dict(arguments=mapped,name=names[name])),sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
        authorization='Bearer '+secret;ts=str(int(time.time()*1000));nonce=uuid.uuid4().hex
        canonical='\n'.join(('POST','/mcp',ts,nonce,hashlib.sha256(body).hexdigest(),hashlib.sha256(authorization.encode()).hexdigest()))
        signature=base64.urlsafe_b64encode(hmac.digest(SIGNING,canonical.encode(),'sha256')).decode().rstrip('=')
        agent,context=fly_context()
        headers={'Authorization':authorization,'Content-Type':'application/json','Accept':'application/json, text/event-stream',
            'User-Agent':agent,'x-ff-ctx':context,'x-ttid':'ai2c(sk.clawhub)','x-flyai-sign-ver':'7',
            'x-flyai-sign-alg':'hmac-sha256','x-flyai-ts':ts,'x-flyai-nonce':nonce,'x-flyai-sign':signature}
        media,raw=send('POST','https://flyai.open.fliggy.com/mcp',headers,body)
        if any(s.encode() in raw for s in (secret,authorization,context,signature)):raise Fault('service_response_contains_secret')
        if media=='text/event-stream':
            # 只接受一个完整 JSON-RPC 回执；不解释服务器提供的后续端点。
            events=[]
            for event in raw.replace(b'\r\n',b'\n').split(b'\n\n'):
                data=b'\n'.join(line[5:].lstrip(b' ') for line in event.splitlines() if line.startswith(b'data:'))
                if data:events.append(strict_json(data))
            matching=[e for e in events if type(e) is dict and type(e.get('id')) is int and e['id']==1]
            if len(matching)!=1:raise Fault('service_protocol_failure')
            result=matching[0]
        else:result=strict_json(raw)
        if (type(result) is not dict or result.get('jsonrpc')!='2.0' or type(result.get('id')) is not int or result['id']!=1
                or 'error' in result or type(result.get('result')) is not dict):raise Fault('service_vendor_rejected')
        result=result['result']
        if result.get('isError'):raise Fault('service_vendor_rejected')
        candidates=[]
        structured=result.get('structuredContent')
        if isinstance(structured,dict) and set(structured)&{'status','data','error','code'}:candidates.append(structured)
        blocks=result.get('content',[])
        if type(blocks) is not list:raise Fault('service_protocol_failure')
        for block in blocks:
            if type(block) is not dict:raise Fault('service_protocol_failure')
            if block.get('type')=='text':
                text=block.get('text')
                if not isinstance(text,str):raise Fault('service_protocol_failure')
                if text.lstrip().startswith('{'):
                    inner=strict_json(text)
                    if type(inner) is dict and set(inner)&{'status','data','error','code'}:candidates.append(inner)
        def signature(item):
            return {k:(str(v) if k in ('status','code') else v) for k,v in item.items()
                    if k in ('status','data','error','code','success') and v is not None}
        if not candidates or any(signature(c)!=signature(candidates[0]) for c in candidates):raise Fault('service_protocol_failure')
        result=candidates[0]
        rejected_codes={'UNAUTHORIZED','INVALID_API_KEY','AUTHENTICATION_FAILED','FORBIDDEN',
            'PERMISSION_DENIED','RATE_LIMITED','QUOTA_EXCEEDED','SERVICE_UNAVAILABLE',
            'UNSUPPORTED_SIGN_VERSION','UNSUPPORTED_TOOL'}
        if (result.get('error') is not None or str(result.get('code')) in rejected_codes or str(result.get('status'))!='0'
                or result.get('success',True) is not True):raise Fault('service_vendor_rejected')
    if secret.encode() in raw:raise Fault('service_response_contains_secret')
    reject_authentication(result)
    return dict(provider=result,adaptation=dict(complete=True,next_cursor=None,byte_limit=60000))


def reject_authentication(value):
    """上游未知认证字段和带凭据的 URL 不进入持久任务结果。"""
    names={'authorization','accesstoken','refreshtoken','password','cookie','apikey','secret','sessiontoken','xffctx','xflyaisign'}
    normalize=lambda text:''.join(c for c in text.lower() if c.isalnum())
    if isinstance(value,dict):
        for key,item in value.items():
            if normalize(key) in names:raise Fault('service_response_contains_secret')
            reject_authentication(item)
    elif isinstance(value,list):
        for item in value:reject_authentication(item)
    elif isinstance(value,str) and value.startswith(('http://','https://')):
        try:
            url=urllib.parse.urlsplit(value)
            if url.username or url.password or any(normalize(k) in names|{'key','token'} for k,_ in urllib.parse.parse_qsl(url.query)):
                raise Fault('service_response_contains_secret')
        except ValueError:raise Fault('service_protocol_failure') from None


def nas(root,name,args):
    relative=args.get('path','')
    if relative.startswith('/') or '\x00' in relative or any(x in ('.','..') for x in relative.split('/')):
        raise Fault('nas_path_rejected')
    parts=[x for x in relative.split('/') if x]
    descriptor=None
    try:
        # 每一层都由目录句柄打开，拒绝根路径与子路径中的符号链接及竞态替换。
        descriptor=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
        for part in Path(root).parts[1:]:
            following=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=descriptor)
            os.close(descriptor);descriptor=following
        for index,part in enumerate(parts):
            flags=os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK
            if index<len(parts)-1 or name==NAS_LIST:flags|=os.O_DIRECTORY
            following=os.open(part,flags,dir_fd=descriptor)
            os.close(descriptor);descriptor=following
        info=os.fstat(descriptor)
        if name==NAS_LIST:
            if not stat.S_ISDIR(info.st_mode):raise Fault('nas_not_directory')
            entries=[]
            with os.scandir(descriptor) as iterator:
                for entry in iterator:
                    if len(entries)>=1000:raise Fault('nas_directory_too_large')
                    meta=entry.stat(follow_symlinks=False)
                    if stat.S_ISLNK(meta.st_mode):continue
                    entries.append(dict(name=entry.name,kind='directory' if stat.S_ISDIR(meta.st_mode) else 'file' if stat.S_ISREG(meta.st_mode) else 'unsupported',bytes=meta.st_size))
            return dict(entries=sorted(entries,key=lambda x:x['name']),complete=True)
        if not stat.S_ISREG(info.st_mode) or not parts:raise Fault('nas_not_regular_file')
        if info.st_size>32768:raise Fault('nas_file_too_large')
        data=os.read(descriptor,32769)
        if len(data)>32768:raise Fault('nas_file_too_large')
        return dict(encoding='base64',data=base64.b64encode(data).decode(),bytes=len(data))
    except OSError:raise Fault('nas_path_unavailable') from None
    finally:
        if descriptor is not None:os.close(descriptor)


def execute(service,row,name,args,*,request=None,check_cancelled=lambda:None):
    if service in ('amap','fliggy'):return travel(row,name,args,request or globals()['request'])
    if service=='nas':return nas(row['parameters']['root'],name,args)
    if service=='netease' and name in READ_MUSIC|WRITE_MUSIC:
        if name in WRITE_MUSIC and not row['parameters'].get('allow_writes',False):raise Fault('service_write_not_authorized')
        from .netease_music import NcmCliTransport,NeteaseMusicAdapter
        transport=NcmCliTransport(row['parameters']['binary'])
        if transport._executable_hash.hex()!=row['parameters']['sha256']:raise Fault('music_cli_changed')
        return NeteaseMusicAdapter(transport).execute(name,args,SimpleNamespace(check_cancelled=check_cancelled))
    raise Fault('service_not_supported')
