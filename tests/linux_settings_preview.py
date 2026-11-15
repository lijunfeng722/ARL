"""可重复的无账号设置截图夹具；只返回合成配置，拒绝保存或探测服务。"""
import argparse
import copy
import tempfile
from pathlib import Path

from arl.linux_settings import SettingsServer
from arl.contracts import Fault


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--port',type=int,default=18746)
    args=parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='arl-settings-preview-') as temporary:
        home=Path(temporary);home.chmod(0o700)
        server=SettingsServer(home,args.port)
        value=server.settings.snapshot();value['demo']=True
        for row in value['services']:
            row.update(configured=row['id'] in ('amap','nas'),enabled=False,apps=['demo.friday'] if row['id']=='amap' else [])
            if row['id']=='amap':row['credential_present']=True
            if row['id']=='nas':row['parameters']={'root':'/mnt/example-share'}
        server.token='synthetic-preview'
        server.settings.snapshot=lambda:copy.deepcopy(value)
        def reject(*_):raise Fault('preview_read_only')
        server.settings.action=reject
        print(server.origin+'/#synthetic-preview',flush=True)
        try:server.serve_forever()
        except KeyboardInterrupt:pass
        finally:server.server_close()


if __name__=='__main__':main()
