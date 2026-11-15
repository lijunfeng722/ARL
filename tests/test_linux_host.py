"""Linux 入口的真实 socket 与配置边界；不连接账号或模型。"""

import hashlib
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from arl.application_session import ApplicationSession
from arl.client import Client
from arl.codex_packages import atomic
from arl.contracts import Fault
from arl.linux_host import CONFIG, configuration, make_runtime


@unittest.skipUnless(sys.platform.startswith('linux'), '仅在 Linux 验证宿主入口')
class LinuxHostTests(unittest.TestCase):
    def setUp(self):
        # 容器的宿主共享目录不支持 socket chmod；/var/tmp 保留 Linux 本机文件语义。
        self.temporary = tempfile.TemporaryDirectory(dir='/var/tmp')
        self.home = Path(self.temporary.name)
        self.home.chmod(0o700)

    def tearDown(self):
        self.temporary.cleanup()

    def test_unconfigured_host_registers_without_model_or_apple_grants(self):
        runtime = make_runtime(self.home)
        thread = threading.Thread(target=runtime.run, daemon=True)
        thread.start()
        session = ApplicationSession(self.home, 'linux-test-app', '测试应用', [])
        try:
            Client(self.home, 'settings').connect(timeout=5)
            session.register()
            self.assertTrue(session.connected)
            self.assertEqual(session.accepted, [])
            self.assertIsNone(runtime.codex_service)
            self.assertFalse(runtime.policies['linux-test-app'].tools)
            with self.assertRaises(Fault):
                session.client.rpc('apple.reminders.list', {})
        finally:
            session.close()
            runtime.shutdown()
            thread.join(10)
        self.assertFalse(thread.is_alive())

    def test_changed_binary_or_public_configuration_rejected(self):
        binary = self.home/'codex'
        binary.write_bytes(b'synthetic executable bytes')
        binary.chmod(0o700)
        value = dict(schema_version=1, binary=str(binary),
                     sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                     model='synthetic-model', max_calls=2)
        atomic(self.home/CONFIG, value)
        self.assertEqual(configuration(self.home), value)
        binary.write_bytes(b'changed executable')
        with self.assertRaises(Fault) as error:
            configuration(self.home)
        self.assertEqual(error.exception.code, 'provider_binary_changed')
        (self.home/CONFIG).chmod(0o644)
        with self.assertRaises(Fault):
            configuration(self.home)

    def test_invalid_config_does_not_fall_back_to_enabled_host(self):
        atomic(self.home/CONFIG, {'schema_version': 1})
        with self.assertRaises(Fault):
            make_runtime(self.home)

    def test_configured_model_scope_revokes_when_binary_changes_without_execution(self):
        binary = self.home/'codex'
        binary.write_bytes(b'synthetic; never execute')
        binary.chmod(0o700)
        atomic(self.home/CONFIG, dict(schema_version=1, binary=str(binary),
               sha256=hashlib.sha256(binary.read_bytes()).hexdigest(), model='synthetic-model', max_calls=2))
        runtime = make_runtime(self.home)
        try:
            self.assertTrue(runtime.codex_service.current())
            binary.write_bytes(b'changed; never execute')
            self.assertFalse(runtime.codex_service.current())
        finally:
            runtime.shutdown()

    def test_missing_configured_binary_is_not_silently_unconfigured(self):
        atomic(self.home/CONFIG, dict(schema_version=1, binary=str(self.home/'missing'),
               sha256='0'*64, model='synthetic-model', max_calls=2))
        with self.assertRaises(Fault) as error:
            make_runtime(self.home)
        self.assertEqual(error.exception.code, 'provider_binary_missing')

    def test_disabled_intent_preserved(self):
        (self.home/'disabled').touch(mode=0o600)
        with self.assertRaises(Fault) as error:
            make_runtime(self.home)
        self.assertEqual(error.exception.code, 'user_disabled')


if __name__ == '__main__':
    unittest.main()
