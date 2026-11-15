"""各平台共享状态位置；Linux 不创建 macOS 的 Library 目录。"""

import os
import sys
from pathlib import Path


def state_home():
    if sys.platform == 'darwin':
        return Path.home()/'Library/Application Support/ARL'
    base = Path(os.environ.get('XDG_STATE_HOME', str(Path.home()/'.local/state')))
    if not base.is_absolute():
        raise ValueError('state_home_must_be_absolute')
    return base/'arl'
