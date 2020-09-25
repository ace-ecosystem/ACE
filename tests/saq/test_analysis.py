# vim: sw=4:ts=4:et

from saq.analysis import RootAnalysis, Analysis, AnalysisModuleType
from saq.observables import IPv4Observable

import pytest

@pytest.mark.integration
def test_add_analysis():
    root = RootAnalysis()
    o = root.add_observable(IPv4Observable('1.2.3.4'))

    analysis = Analysis()
    analysis.type = AnalysisModuleType(
            name="ipv4_analysis",
            description="Test Module")
    o.add_analysis(analysis)
    assert analysis.type.name in o.analysis
