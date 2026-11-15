"""Linux 服务配置、只读连接与应用授权；秘密只保存在当前账号私有文件。"""

from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
import re
import stat
import threading
import time
import uuid
from pathlib import Path

from .codex_packages import atomic, read_private
from .contracts import Fault, Tool, object_schema, string, validate
from .lifecycle import private_home

SERVICES = ('amap','fliggy','netease','nas')
NAMES = dict(amap='高德地图',fliggy='飞猪',netease='网易云音乐',nas='NAS 文件')
APPLE = ('日历','提醒事项','信息','备忘录','钥匙串')
CONFIG = 'linux-services-v1.json'
EMPTY = dict(schema_version=1,revision=0,services={})
APP = re.compile(r'[A-Za-z0-9_.-]{1,64}\Z')
WRITE_MUSIC = {'netease.playlist.create.v1','netease.playlist.append_song.v1'}
READ_MUSIC = {'netease.playlist.list.v1','netease.playlist.describe.v1','netease.song.search.v1'}
NAS_LIST,NAS_READ='nas.directory.list.v1','nas.file.read.v1'


def text(value, limit=4096):
    return type(value) is str and len(value)<=limit and not any(ord(c)<32 or ord(c)==127 for c in value)


def parameters(service, params):
    if type(params) is not dict:
        raise Fault('invalid_service_configuration')
    params=dict(params)
    if service=='netease':params.setdefault('allow_writes',False)
    expected={'amap':set(),'fliggy':set(),'netease':{'binary','sha256','allow_writes'},'nas':{'root'}}[service]
    if set(params)!=expected or not all(text(v) for k,v in params.items() if k!='allow_writes'):
        raise Fault('invalid_service_configuration')
    if service=='netease':
        if type(params['allow_writes']) is not bool or not Path(params['binary']).is_absolute() or not re.fullmatch('[a-f0-9]{64}',params['sha256']):
            raise Fault('invalid_service_configuration')
    if service=='nas':
        root=Path(params['root'])
        if not root.is_absolute() or root==Path('/') or root.resolve()!=root:
            raise Fault('invalid_service_configuration')
    return dict(params)


class ServiceSettings:
    def __init__(self, home):
        self.home=private_home(home)
        self.lock=threading.RLock()

    def load(self):
        try:value=read_private(self.home/CONFIG,65536)
        except FileNotFoundError:return dict(EMPTY,services={})
        if (type(value) is not dict or set(value)!={'schema_version','revision','services'}
                or value['schema_version']!=1 or type(value['revision']) is not int or value['revision']<0
                or type(value['services']) is not dict or set(value['services'])-set(SERVICES)):
            raise Fault('invalid_service_configuration')
        for name,row in value['services'].items():
            if (type(row) is not dict or set(row)!={'parameters','secret','enabled','apps','generation'}
                    or type(row['enabled']) is not bool or not text(row['secret'],8192)
                    or type(row['apps']) is not list or len(row['apps'])>32
                    or any(type(x) is not str or APP.fullmatch(x) is None or x=='settings' for x in row['apps'])
                    or len(row['apps'])!=len(set(row['apps']))
                    or type(row['generation']) is not str or re.fullmatch('[a-f0-9]{32}',row['generation']) is None):
                raise Fault('invalid_service_configuration')
            parameters(name,row['parameters'])
        return value

    def edit(self, change, expected_revision):
        with self.lock:
            descriptor=os.open(self.home/'linux-services.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
            try:
                info=os.fstat(descriptor)
                if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077:
                    raise Fault('unsafe_service_configuration')
                fcntl.flock(descriptor,fcntl.LOCK_EX)
                value=self.load()
                if type(expected_revision) is not int or value['revision']!=expected_revision:
                    raise Fault('service_revision_conflict')
                change(value['services'])
                value['revision']+=1
                atomic(self.home/CONFIG,value)
            finally:os.close(descriptor)
        return self.snapshot()

    def configure(self, service, params, *, secret=None, apps=(), enabled=False, expected_revision):
        if (service not in SERVICES or type(enabled) is not bool or type(apps) not in (list,tuple)
                or len(apps)>32
                or any(type(x) is not str or APP.fullmatch(x) is None or x=='settings' for x in apps)
                or len(set(apps))!=len(apps)
                or secret is not None and not text(secret,8192)):
            raise Fault('invalid_service_configuration')
        params=parameters(service,params)
        def change(rows):
            saved=secret if secret is not None else rows.get(service,{}).get('secret','')
            if service in ('amap','fliggy') and not saved.strip():
                raise Fault('service_credential_required')
            if service not in ('amap','fliggy') and saved:
                raise Fault('unexpected_service_credential')
            rows[service]=dict(parameters=params,secret=saved,apps=list(apps),enabled=enabled,generation=uuid.uuid4().hex)
        return self.edit(change,expected_revision)

    def pause(self, service, *, expected_revision):
        if service not in SERVICES:raise Fault('unknown_service')
        def change(rows):
            if service not in rows:raise Fault('service_not_configured')
            rows[service].update(enabled=False,generation=uuid.uuid4().hex)
        return self.edit(change,expected_revision)

    def remove(self, service, *, expected_revision):
        if service not in SERVICES:raise Fault('unknown_service')
        return self.edit(lambda rows:rows.pop(service,None),expected_revision)

    def snapshot(self):
        value=self.load();rows=[]
        for name in SERVICES:
            row=value['services'].get(name)
            rows.append(dict(id=name,name=NAMES[name],configured=row is not None,
                enabled=bool(row and row['enabled']),credential_present=bool(row and row['secret']),
                parameters=row['parameters'] if row else {},apps=row['apps'] if row else [],
                connection='not_probed',writes=('enabled' if row and row['parameters'].get('allow_writes') else 'disabled') if name=='netease' else 'not_exposed',login_owner='official_cli' if name=='netease' else 'local_settings'))
        return dict(schema_version=1,revision=value['revision'],services=rows,
                    apple=[dict(name=name,state='unsupported') for name in APPLE],
                    secret_storage='owner_only_files_0600',inference_attempted=False)


def descriptions():
    from .travel import TravelAdapter
    from .netease_music import SCHEMAS
    rows={t['name']:t['inputSchema'] for t in TravelAdapter().descriptors
          if t['name'].startswith(('mio_maps_','mio_flyai_'))}
    for schema in rows.values():
        schema["properties"].pop("cursor",None)
    # 补齐原生 TravelReadContract 中已公开的关键词、AI、火车和景点查询。
    for name in ('mio_flyai_keyword_search','mio_flyai_ai_search'):
        rows[name]=object_schema({'query':string(16384)},('query',))
    import copy
    rows['mio_flyai_search_train']=copy.deepcopy(rows['mio_flyai_search_flight'])
    rows['mio_flyai_search_train']['properties'].pop('limit',None)
    rows['mio_flyai_search_poi']=object_schema({'city_name':string(16384),'keyword':string(16384),
        'poi_level':dict(type='integer',minimum=1,maximum=5),'category':string(16384)},('city_name',))
    # Linux 有界响应不产生本地游标，供应商 page/offset 仍保留原始语义。
    for name in READ_MUSIC|WRITE_MUSIC:rows[name]=SCHEMAS[name]
    rows[NAS_LIST]=object_schema({'path':dict(type='string',maxLength=2048)},())
    rows[NAS_READ]=object_schema({'path':string(2048)},('path',))
    return rows


def service_for(tool):
    if tool.startswith('mio_maps_'):return 'amap'
    if tool.startswith('mio_flyai_'):return 'fliggy'
    if tool in READ_MUSIC|WRITE_MUSIC:return 'netease'
    if tool in (NAS_LIST,NAS_READ):return 'nas'
    raise Fault('tool_not_authorized')


class Services:
    def __init__(self, home, *, request=None):
        self.settings=ServiceSettings(home);self.request=request
        self.runtime=None;self.schema=descriptions()

    def grants(self, owner):
        rows=self.settings.load()['services']
        return frozenset(name for name in self.schema
            if (row:=rows.get(service_for(name))) and row['enabled'] and owner in row['apps']
            and (name not in WRITE_MUSIC or row['parameters'].get('allow_writes',False)))

    def admit(self, owner, name, args):
        if (self.settings.home/'disabled').exists() or name not in self.grants(owner):
            raise Fault('service_not_authorized')
        if self.runtime is not None and not self.runtime.application_platform.active(owner):
            raise Fault('application_session_expired')
        validate(args,self.schema[name])

    def tools(self):
        return [Tool(name,schema,lambda args,context,n=name:self.call(context.owner,n,args,context),
                     idempotent=name not in WRITE_MUSIC,
                     permissions=('linux_service_write',) if name in WRITE_MUSIC else ('linux_service_read',),
                     description='经本机设置和当前应用授权的服务')
                for name,schema in self.schema.items()]

    def call(self, owner, name, args, context):
        self.admit(owner,name,args);context.check_cancelled()
        service=service_for(name);row=self.settings.load()['services'][service]
        from .linux_service_io import execute
        def guard():
            context.check_cancelled();self.admit(owner,name,args)
            current=self.settings.load()['services'].get(service)
            if current is None or current['generation']!=row['generation']:raise Fault('service_configuration_changed')
        result=execute(service,row,name,args,request=self.request,check_cancelled=guard)
        context.check_cancelled();self.admit(owner,name,args)
        if self.settings.load()['services'][service]['generation']!=row['generation']:
            raise Fault('service_configuration_changed')
        # 凭据和鉴权头不进入队列结果；即使上游回显也整体拒绝，避免片段泄漏。
        raw=json.dumps(result,ensure_ascii=False)
        if row['secret'] and row['secret'] in raw:raise Fault('service_response_contains_secret')
        if len(raw.encode())>60000:raise Fault('service_response_too_large')
        return result
