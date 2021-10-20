# vim: sw=4:ts=4:et:cc=120
import pytest

from saq.constants import *
from saq.observables import create_observable

@pytest.mark.unit
def test_snort_signature_observable():
    o = create_observable(F_SNORT_SIGNATURE, '1:2802042:3')
    assert o.signature_id == '2802042'
    assert o.rev == '3'

    o = create_observable(F_SNORT_SIGNATURE, '1:2802042')
    assert o.signature_id is None
    assert o.rev is None
