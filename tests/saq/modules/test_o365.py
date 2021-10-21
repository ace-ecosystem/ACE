import pytest
import saq
from saq.database import Alert, Observable, ObservableMapping
from saq.analysis import RootAnalysis
from saq.constants import *
from saq.modules.o365 import O365FileConversationAnalyzer
    
@pytest.mark.parametrize('conversation, has_detection_points', [
    ('john.doe@company.com|jane.doe@company.com', True),
    ('john.doe@company.com|coworker@company.com', False),
])
@pytest.mark.integration
def test_new_sensitive_conversation(conversation, has_detection_points):
    om = ObservableMapping()
    om.alert = Alert(
        uuid='test',
        location='test',
        storage_dir='test',
        tool='mvision',
        tool_instance='test',
        alert_type='mvision',
        description='test',
        disposition=DISPOSITION_APPROVED_BUSINESS,
    )
    om.observable = Observable(
        type=F_O365_FILE_CONVERSATION,
        value='john.doe@company.com|coworker@company.com'.encode('utf-8'),
        md5='test'.encode('utf-8'),
    )
    saq.db.add(om)
    saq.db.commit()

    saq.CONFIG['analysis_module_config'] = {}
    observable = RootAnalysis().add_observable(F_O365_FILE_CONVERSATION, conversation)
    analyzer = O365FileConversationAnalyzer('analysis_module_config')
    analyzer.execute_analysis(observable)
    analysis = observable.get_analysis(analyzer.generated_analysis_type)
    assert observable.has_detection_points() == has_detection_points
