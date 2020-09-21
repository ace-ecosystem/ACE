import pytest

import saq
import saq.tip

from saq.tip import GenericTIP, tip_factory
from saq.tip.misp import MISP


@pytest.mark.unit
def test_factory():
    saq.CONFIG['tip']['enabled'] = 'no'
    assert type(tip_factory()) is GenericTIP

    saq.CONFIG['tip']['enabled'] = 'misp'
    assert isinstance(tip_factory(), MISP)
