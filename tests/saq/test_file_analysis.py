import time

import pytest

from saq.modules.file_analysis import URLExtractionAnalyzer


class MockAnalysis(object):
    def __init__(self):
        self.details = {}
        self.observables = []

    def add_observable(self, *args, **kwargs):
        self.observables.append(args)


class MockAnalysisModule(object):
    def __init__(self, test_file):
        self.mime_type = f"text/{test_file[len('sample_'):]}"

    @staticmethod
    def wait_for_analysis():
        pass


class TestUrlExtraction:
    @pytest.mark.unit
    def test_order_urls_by_interest(self):
        extracted_urls_unordered = ['https://voltage-pp-0000.wellsfargo.com/brand/rv/19238/zdm/troubleshooting.ftl',
                                    'https://voltage-pp-0000.wellsfargo.com/brand/rv/19238/zdm/troubleshooting.ftl',
                                    'https://voltage-pp-0000.wellsfargo.com/brand/zdm/mobile.ftl',
                                    'https://www.wellsfargo.com/help/secure-email',
                                    'https://www.wellsfargoadvisors.com/video/secureEmail/secureEmail.htm']

        expected_extracted_urls_ordered = ['https://www.wellsfargoadvisors.com/video/secureEmail/secureEmail.htm',
                                           'https://voltage-pp-0000.wellsfargo.com/brand/rv/19238/zdm/troubleshooting.ftl',
                                           'https://voltage-pp-0000.wellsfargo.com/brand/rv/19238/zdm/troubleshooting.ftl',
                                           'https://voltage-pp-0000.wellsfargo.com/brand/zdm/mobile.ftl',
                                           'https://www.wellsfargo.com/help/secure-email']

        expected_extracted_urls_grouping = {
                'wellsfargo.com':
                    ['https://voltage-pp-0000.wellsfargo.com/brand/rv/19238/zdm/troubleshooting.ftl',
                     'https://voltage-pp-0000.wellsfargo.com/brand/rv/19238/zdm/troubleshooting.ftl',
                     'https://voltage-pp-0000.wellsfargo.com/brand/zdm/mobile.ftl',
                     'https://www.wellsfargo.com/help/secure-email'],
                'wellsfargoadvisors.com':
                    ['https://www.wellsfargoadvisors.com/video/secureEmail/secureEmail.htm']}

        url_extraction_analyzer = URLExtractionAnalyzer(config_section='analysis_module_url_extraction')
        extracted_urls_ordered, extracted_urls_grouping = url_extraction_analyzer.order_urls_by_interest(extracted_urls_unordered)

        assert extracted_urls_ordered == expected_extracted_urls_ordered
        assert extracted_urls_grouping == expected_extracted_urls_grouping

    @pytest.mark.unit
    def test_exclude_filtered_domains(self):
        extracted_urls_unfiltered = ['http://schemas.microsoft.com/office/2004/12/omml',
                                     'http://www.w3.org/TR/REC-html40',
                                     'https://voltage-pp-0000.wellsfargo.com/brand/rv/19238/zdm/troubleshooting.ftl',
                                     'https://voltage-pp-0000.wellsfargo.com/brand/rv/19238/zdm/troubleshooting.ftl',
                                     'https://voltage-pp-0000.wellsfargo.com/brand/zdm/mobile.ftl',
                                     'https://www.wellsfargo.com/help/secure-email',
                                     'https://www.wellsfargoadvisors.com/video/secureEmail/secureEmail.htm',
                                     'https://blue',
                                     'https://center',
                                     'https://top']

        expected_extracted_urls_filtered = ['https://voltage-pp-0000.wellsfargo.com/brand/rv/19238/zdm/troubleshooting.ftl',
                                            'https://voltage-pp-0000.wellsfargo.com/brand/rv/19238/zdm/troubleshooting.ftl',
                                            'https://voltage-pp-0000.wellsfargo.com/brand/zdm/mobile.ftl',
                                            'https://www.wellsfargo.com/help/secure-email',
                                            'https://www.wellsfargoadvisors.com/video/secureEmail/secureEmail.htm']

        url_extraction_analyzer = URLExtractionAnalyzer(config_section='analysis_module_url_extraction')
        extracted_urls_filtered = list(filter(url_extraction_analyzer.filter_excluded_domains, extracted_urls_unfiltered))

        assert expected_extracted_urls_filtered == extracted_urls_filtered

    @pytest.mark.parametrize('test_file', ['sample_plain', 'sample_html', 'sample_xml', 'sample_dat', 'sample_rfc822'])
    @pytest.mark.unit
    def test_execute_analysis(self, monkeypatch, datadir, test_file):
        url_extraction_analysis = MockAnalysis()

        def mock_analysis_module(*args, **kwargs):
            return MockAnalysisModule(test_file)

        def mock_get_local_file_path(*args, **kwargs):
            return datadir / f'{test_file}.in'

        class MockFileObservable:
            def __init__(self):
                pass

            @staticmethod
            def get_analysis(*args, **kwargs):
                return url_extraction_analysis

            @staticmethod
            def get_relationship_by_type(*args, **kwargs):
                return None

        monkeypatch.setattr("saq.modules.AnalysisModule.wait_for_analysis", mock_analysis_module)
        monkeypatch.setattr("saq.modules.file_analysis.get_local_file_path", mock_get_local_file_path)
        monkeypatch.setattr("os.path.exists", lambda x: 1 == 1)  # return true that path exists
        monkeypatch.setattr("os.path.getsize", lambda x: 1)  # arbitrary filesize

        url_extraction_analyzer = URLExtractionAnalyzer(config_section='analysis_module_url_extraction')

        t1 = time.time()
        url_extraction_completed = url_extraction_analyzer.execute_analysis(MockFileObservable())
        t2 = time.time()
        elapsed = t2 - t1
        print(f' Execute analysis took {elapsed} seconds.')

        expected_analysis_observables = list()
        with open(datadir / f'{test_file}.out') as f:
            for line in f:
                line = line.strip()
                expected_analysis_observables.append(line)

        expected_analysis_observables = set(expected_analysis_observables)

        assert url_extraction_completed
        for type, value in url_extraction_analysis.observables:
            assert type == 'url'

        assert set([value for type, value in url_extraction_analysis.observables]) == expected_analysis_observables
        #assert str(url_extraction_analysis.observables) == expected_analysis_observables
