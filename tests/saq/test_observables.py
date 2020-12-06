import os.path
import shutil

import pytest

from saq.analysis import RootAnalysis
from saq.system.analysis_tracking import get_root_analysis

@pytest.mark.integration
def test_file_observable_download(tmpdir):
    path = str(tmpdir / 'test.txt')
    with open(path, 'w') as fp:
        fp.write('test')

    # create a root analysis and add a file to it
    root = RootAnalysis()
    file_observable = root.add_file(path)
    root.save()
    root.discard()

    root = get_root_analysis(root.uuid)
    file_observable = root.get_observable(file_observable)
    file_observable.load()
    assert root.storage_dir
    assert os.path.isdir(root.storage_dir)
    assert os.path.exists(file_observable.path)
    with open(file_observable.path, 'r') as fp:
        assert fp.read() == 'test'

    root.discard()
