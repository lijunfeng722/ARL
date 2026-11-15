"""Linux 独立宿主：复用应用会话、持久队列与模型回执，Apple 服务不装配。"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import signal
import threading
from pathlib import Path

from .linux_application import LinuxApplicationPlatform
from .linux_services import Services
from .codex_packages import atomic, read_private
from .codex_server import CodexService, CodexTextAdapter
from .compat_host import metadata_policies
from .contracts import Fault
from .lifecycle import private_home
from .platform_paths import state_home
from .service import Runtime

CONFIG = 'linux-model-service-v1.json'
UNSUPPORTED = ['apple.calendar', 'apple.reminders', 'apple.notes', 'apple.messages', 'macos.keychain']


def configuration(home, *, verify_binary=True):
    """配置只保存运行路径和授权范围，不保存账号、令牌或用户指令。"""
    value = read_private(Path(home)/CONFIG, 8192)
    if (type(value) is not dict or set(value) != {'schema_version', 'binary', 'sha256', 'model', 'max_calls'}
            or type(value['schema_version']) is not int or value['schema_version'] != 1
            or type(value['binary']) is not str or not Path(value['binary']).is_absolute()
            or type(value['sha256']) is not str or re.fullmatch('[a-f0-9]{64}', value['sha256']) is None
            or type(value['model']) is not str or re.fullmatch('[A-Za-z0-9][A-Za-z0-9._/-]{0,149}', value['model']) is None
            or type(value['max_calls']) is not int or not 1 <= value['max_calls'] <= 1000):
        raise Fault('linux_model_configuration_invalid')
    binary = Path(value['binary'])
    try:
        info = binary.stat()
    except FileNotFoundError:
        raise Fault('provider_binary_missing') from None
    if (not binary.is_file() or not os.access(binary, os.X_OK) or info.st_mode & 0o022
            or info.st_uid not in {0, os.geteuid()}):
        raise Fault('provider_binary_unsafe')
    if verify_binary and hashlib.sha256(binary.read_bytes()).hexdigest() != value['sha256']:
        raise Fault('provider_binary_changed')
    return value


def make_runtime(home):
    home = private_home(home)
    if (home/'disabled').exists():
        raise Fault('user_disabled')
    try:
        config = configuration(home)
    except FileNotFoundError:
        config = None
    route = None
    if config is not None:
        def signature():
            info = Path(config['binary']).stat()
            return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        pinned = signature()

        def current():
            try:
                # 高频撤销检查比较不可回退的文件代次；启动和实际执行仍校验完整摘要。
                return (configuration(home, verify_binary=False) == config
                        and signature() == pinned and not (home/'disabled').exists())
            except (OSError, ValueError, Fault):
                return False

        adapter = CodexTextAdapter(config['binary'], enabled=True, expected_sha256=config['sha256'])
        adapter.timeout = 180
        route = CodexService(adapter, caller='linux-owner', model=config['model'],
                             max_calls=config['max_calls'], reasoning_effort='medium',
                             authorization_current=current, peer_current=current,
                             allow_model_selection=True, package_home=home/'CodexPackages')
    services = Services(home)
    services.settings.load()
    def admission(owner, name, args):
        if route and name == route.name:
            return route.admit(owner, name, args)
        return services.admit(owner, name, args)
    runtime = Runtime(home, policies=metadata_policies(), providers={}, local_enabled=False,
                      identity_verifier=lambda *_: None, execute_jobs=True,
                      extra_tools=services.tools()+([route.tool()] if route else []), codex_service=route,
                      admission=admission, work_scope=frozenset(),
                      application_catalog=(lambda _: route.status()['execution_catalog']) if route else None)
    if route:
        from .codex_context import TRANSPORT_FRAME_BYTES
        runtime.max_request_frame_bytes = TRANSPORT_FRAME_BYTES
        route.runtime = runtime
    services.runtime = runtime
    runtime.linux_services = services
    runtime.application_platform = LinuxApplicationPlatform(runtime, services)
    return runtime


def serve(home):
    runtime = make_runtime(home)
    finished = threading.Event()

    def stop(*_):
        threading.Thread(target=runtime.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    def monitor():
        next_probe = 0
        import time
        while not finished.wait(.5):
            if (runtime.home/'disabled').exists():
                runtime.shutdown()
                return
            route = runtime.codex_service
            if route and runtime.ready.is_set() and time.monotonic() >= next_probe:
                try:
                    route.preflight()
                except Exception:
                    pass  # 具体错误由现有模型状态协议报告，不能伪造就绪。
                next_probe = time.monotonic()+45

    watcher = threading.Thread(target=monitor, daemon=True)
    watcher.start()
    try:
        runtime.run()
    finally:
        finished.set()
        runtime.shutdown()
        watcher.join(timeout=35)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['check', 'serve', 'configure-models'])
    parser.add_argument('--home', type=Path, default=state_home())
    parser.add_argument('--binary', type=Path)
    parser.add_argument('--sha256')
    parser.add_argument('--model')
    parser.add_argument('--max-calls', type=int, default=100)
    args = parser.parse_args()
    if platform.system() != 'Linux':
        parser.error('此入口仅用于 Linux')
    try:
        if args.command == 'configure-models':
            if not args.binary or not args.sha256 or not args.model:
                parser.error('需要 --binary、--sha256 和 --model；摘要须来自已核对的发行包')
            home = private_home(args.home)
            value = dict(schema_version=1, binary=str(args.binary.resolve(strict=True)),
                         sha256=args.sha256, model=args.model, max_calls=args.max_calls)
            # 先验证临时独立目录内的同一配置，再原子替换正式配置。
            import tempfile
            with tempfile.TemporaryDirectory(dir=home) as temporary:
                atomic(Path(temporary)/CONFIG, value)
                configuration(temporary)
            atomic(home/CONFIG, value)
            print(json.dumps(dict(configured=True, login_performed=False, inference_attempted=False)))
        elif args.command == 'serve':
            serve(args.home)
        else:
            try:
                configuration(args.home)
                model_state = 'configured_not_probed'
            except FileNotFoundError:
                model_state = 'not_configured'
            print(json.dumps(dict(platform=platform.machine(), model_state=model_state,
                                  apple_services='unsupported', unsupported=UNSUPPORTED,
                                  inference_attempted=False)))
        return 0
    except (OSError, ValueError, Fault) as error:
        print(json.dumps(dict(error=getattr(error, 'code', 'linux_host_unavailable'))))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
