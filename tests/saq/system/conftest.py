from datetime import datetime
import threading
from typing import Union, Optional

from saq.system import get_system
import saq.system.threaded

import pytest

@pytest.fixture(autouse=True, scope='session')
def initialize_ace_system():
    saq.system.threaded.initialize()

@pytest.fixture(autouse=True, scope='function')
def reset_ace_system():
    get_system().reset()
