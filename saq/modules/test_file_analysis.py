# vim: sw=4:ts=4:et

import datetime
import hashlib
import logging
import os, os.path
import shutil
import tempfile
import threading
import unittest
import uuid

from subprocess import Popen, PIPE

import saq, saq.test
from saq.constants import *
from saq.crypto import decrypt
from saq.test import *
from saq.analysis import Analysis, RootAnalysis
from saq.indicators import Indicator
from saq.service.yara import YSSService
from saq.tip import tip_factory

UNITTEST_SOCKET_DIR = 'socket_unittest'

def get_yara_rules_dir():
    return os.path.join(saq.SAQ_HOME, 'test_data', 'yara_rules')

class TestCase(ACEModuleTestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.yara_service = None

        #self.yss_process = None
        #self.yss_stdout_buffer = []
        #self.yss_stderr_buffer = []
        #self.yss_stdout_reader_thread = None
        #self.yss_stderr_reader_thread = None

    # TODO get rid of this externa execution and replace with just using the class
    def initialize_yss(self):

        service_config = saq.CONFIG['service_yara']
        service_config['socket_dir'] = UNITTEST_SOCKET_DIR
        service_config['signature_dir'] = get_yara_rules_dir()
        self.yara_service = YSSService()
        self.yara_service.start_service(threaded=True)

        # clear existing logs
        #yss_log_path = os.path.join('logs', 'unittest_yss.log')
        #if os.path.exists(yss_log_path):
            #try:
                #os.remove(yss_log_path)
            #except Exception as e:
                #logging.error("unable to remove yss log {}: {}".format(yss_log_path, e))

        #with open(yss_log_path, 'wb') as fp:
            #pass

        #self.yss_process = Popen([ 'yss', 
                                   #'--base-dir', saq.SAQ_HOME,
                                   #'--socket-dir', UNITTEST_SOCKET_DIR,
                                   #'--pid-file', '.yss_unittest.pid',
                                   #'-L', os.path.join('etc', 'unittest_logging.ini'),
                                   #'-d', get_yara_rules_dir(), ], 
                                 #stdout=PIPE, stderr=PIPE, 
                                 #universal_newlines=True, cwd=saq.SAQ_HOME)

        #def _pipe_reader(pipe, buf, marker):
            #try:
                #while True:
                    #line = pipe.readline()
                    #if line == '':
                        #break

                    #logging.info("YSS: {}: {}".format(marker, line.strip()))
                    #buf.append(line.strip())

            #except Exception as e:
                #logging.error("error reading yss_process pipe: {}".format(e))

        #self.yss_stdout_reader_thread = threading.Thread(target=_pipe_reader, 
                                                         #args=(self.yss_process.stdout, self.yss_stdout_buffer, 'STDOUT'))
        #self.yss_stdout_reader_thread.start()

        #self.yss_stderr_reader_thread = threading.Thread(target=_pipe_reader, 
                                                         #args=(self.yss_process.stdout, self.yss_stderr_buffer, 'STDERR'))
        #self.yss_stderr_reader_thread.start()

        # wait for yss to start
        #def _condition():
            #return os.path.exists(yss_log_path)
        #wait_for(_condition, timeout=1)

        wait_for_log_count('waiting for client', 1)

        #tail_process = Popen(['tail', '-f', yss_log_path], stdout=PIPE)
        #for line in tail_process.stdout:
            #if b'waiting for client' in line:
                #break

        #tail_process.kill()

    def setUp(self):

        super().setUp()
    
        # change the yara scanning to point to /opt/saq/yara_scanner
        #saq.CONFIG['analysis_module_yara_scanner_v3_4']['base_dir'] = YSS_BASE_DIR
        # change the location of the unix sockets we're using
        saq.CONFIG['service_yara']['socket_dir'] = UNITTEST_SOCKET_DIR
        saq.CONFIG['service_yara']['signature_dir'] = os.path.join('test_data', 'yara_rules')
            
        #saq.CONFIG['yara']['signature_dir_custom'] = 'test_data/yara_rules/custom'
        #saq.CONFIG['yara']['signature_dir_crits'] = 'test_data/yara_rules/crits'

    def tearDown(self):
        if self.yara_service is not None:
            self.yara_service.stop_service()

        #if self.yss_process:
            #try:
                #self.yss_process.terminate()
                #self.yss_process.wait(5)
            #except Exception as e:
                #print(self.yss_process.poll())
                #logging.error("unable to terminate yss process {}: {}:".format(self.yss_process.pid, e))
                #try:
                    #self.yss_process.kill()
                    #self.yss_process.wait(5)
                #except Exception as e:
                    #logging.critical("unable to kill yss process {}: {}".format(self.yss_process.pid, e))

            #self.yss_stdout_reader_thread.join()
            #self.yss_stdout_reader_thread = None
            #self.yss_stderr_reader_thread.join()
            #self.yss_stderr_reader_thread = None

        # reset the config since we changed stuff
        saq.load_configuration()

        super().tearDown()

    @unittest.skip("test data encrypted -- revisit soon")
    def test_file_analysis_000_url_extraction_000_relative_html_urls(self):
        from saq.modules.file_analysis import URLExtractionAnalysis

        root = create_root_analysis(event_time=datetime.datetime.now())
        root.initialize_storage()

        shutil.copy('test_data/url_extraction_000', root.storage_dir)
        target_file = 'url_extraction_000'
        src_url = 'https://vaishaligarden.com/.opjl/'
        
        url_observable = root.add_observable(F_URL, src_url)
        file_observable = root.add_observable(F_FILE, target_file)
        file_observable.add_directive(DIRECTIVE_EXTRACT_URLS)
        file_observable.add_relationship(R_DOWNLOADED_FROM, url_observable)
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_url_extraction', 'test_groups')
        engine.enable_module('analysis_module_file_type', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root.load()
        file_observable = root.get_observable(file_observable.id)
        self.assertIsNotNone(file_observable)
        analysis = file_observable.get_analysis(URLExtractionAnalysis)
        self.assertIsNotNone(analysis)

        self.assertEquals(len(analysis.get_observables_by_type(F_URL)), 10)

    def test_file_analysis_000_url_extraction_001_pdfparser(self):

        root = create_root_analysis()
        root.initialize_storage()

        shutil.copy('test_data/pdf/Payment_Advice.pdf', root.storage_dir)
        target_file = 'Payment_Advice.pdf'
        
        file_observable = root.add_observable(F_FILE, target_file)
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_pdf_analyzer', 'test_groups')
        engine.enable_module('analysis_module_url_extraction', 'test_groups')
        engine.enable_module('analysis_module_file_type', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root.load()
        file_observable = root.get_observable(file_observable.id)
        self.assertIsNotNone(file_observable)
        from saq.modules.file_analysis import URLExtractionAnalysis, PDFAnalysis
        pdf_analysis = file_observable.get_analysis(PDFAnalysis)
        self.assertIsNotNone(pdf_analysis)
        # should have a single file observable
        pdfparser_file = pdf_analysis.get_observables_by_type(F_FILE)
        self.assertEquals(len(pdfparser_file), 1)
        pdfparser_file = pdfparser_file[0]
        url_analysis = pdfparser_file.get_analysis(URLExtractionAnalysis)
        self.assertIsNotNone(url_analysis)
        # should have a bad url in it
        bad_url = 'http://www.williamtoms.com/wp-includes/354387473a/autodomain/autodomain/autodomain/autofil'
        self.assertTrue(bad_url in [url.value for url in url_analysis.get_observables_by_type(F_URL)])

        tip = tip_factory()
        expected_iocs = [
            tip.create_indicator(I_URL, 'http://www.williamtoms.com/wp-includes/354387473a/autodomain/autodomain/autodomain/autofil'),
            tip.create_indicator(I_DOMAIN, 'www.williamtoms.com'),
            tip.create_indicator(I_DOMAIN, 'williamtoms.com'),
            tip.create_indicator(I_URI_PATH, '/wp-includes/354387473a/autodomain/autodomain/autodomain/autofil'),
            tip.create_indicator(I_URL, 'http://ns.adobe.com/xap/1.0'),
            tip.create_indicator(I_DOMAIN, 'ns.adobe.com'),
            tip.create_indicator(I_DOMAIN, 'adobe.com'),
            tip.create_indicator(I_URI_PATH, '/xap/1.0'),
            tip.create_indicator(I_URL, 'http://ns.adobe.com/pdf/1.3'),
            tip.create_indicator(I_URI_PATH, '/pdf/1.3')
        ]

        self.assertEquals(set(expected_iocs), set(url_analysis.iocs))

    def test_file_analysis_001_oletools_000(self):

        #from saq.modules.file_analysis import OLEVBA_Analysis_v1_2

        KEY_STORAGE_DIR = 'storage_dir'
        KEY_TAGS = 'tags'
        KEY_MACRO_COUNT = 'macro_count'
        KEY_OID = 'oid'
        KEY_SANDBOX = 'sandbox'

        # expected results for the various files
        results = {
            'Past Due Invoices.doc': {
                KEY_OID: None,
                KEY_STORAGE_DIR: None,
                KEY_TAGS: [ 'microsoft_office', 'ole' ],
                KEY_MACRO_COUNT: 4,
                KEY_SANDBOX: True,
            }, 
            'Outstanding Invoices.doc': {
                KEY_OID: None,
                KEY_STORAGE_DIR: None,
                KEY_TAGS: [ 'microsoft_office', 'ole' ],
                KEY_MACRO_COUNT: 3,
                KEY_SANDBOX: True,
            }, 
            'Paid Invoice.doc': {
                KEY_OID: None,
                KEY_STORAGE_DIR: None,
                KEY_TAGS: [ 'microsoft_office', 'ole' ],
                KEY_MACRO_COUNT: 3,
                KEY_SANDBOX: True,
            }, 
            'mortgage_payment-0873821-0565.docm': {
                KEY_OID: None,
                KEY_STORAGE_DIR: None,
                KEY_TAGS: [ 'microsoft_office' ],
                KEY_MACRO_COUNT: 1,
                KEY_SANDBOX: True,
            }, 
            'receipt_687790.doc': {
                KEY_OID: None,
                KEY_STORAGE_DIR: None,
                KEY_TAGS: [ 'microsoft_office' ],
                KEY_MACRO_COUNT: 5,
                KEY_SANDBOX: True,
            }, 
        }

        for file_name in results.keys():
            if not os.path.exists(os.path.join('test_data/ole_files', file_name)):
                self.skipTest(f"missing test data {file_name}")

        for file_name in results.keys():
            root = create_root_analysis(uuid=str(uuid.uuid4()))
            root.initialize_storage()
            target_path = os.path.join('test_data/ole_files', file_name)
            shutil.copy(target_path, root.storage_dir)
            file_observable = root.add_observable(F_FILE, file_name)
            root.save()
            root.schedule()

            results[file_name][KEY_OID] = file_observable.id
            results[file_name][KEY_STORAGE_DIR] = root.storage_dir

        engine = TestEngine()
        engine.enable_module('analysis_module_olevba_v1_2', 'test_groups')
        engine.enable_module('analysis_module_file_type', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        for file_name in results.keys():
            with self.subTest(storage_dir=results[file_name][KEY_STORAGE_DIR], file_name=file_name):
                root = RootAnalysis(storage_dir=results[file_name][KEY_STORAGE_DIR])
                root.load()
                file_observable = root.get_observable(results[file_name][KEY_OID])
                self.assertIsNotNone(file_observable)
                if results[file_name][KEY_SANDBOX]:
                    self.assertTrue(file_observable.has_directive(DIRECTIVE_SANDBOX))
                for tag in results[file_name][KEY_TAGS]:
                    with self.subTest(storage_dir=results[file_name][KEY_STORAGE_DIR], file_name=file_name, tag=tag):
                        self.assertTrue(file_observable.has_tag(tag))

                macro_count = len([f for f in root.all_observables if f.type == F_FILE and f.has_tag('macro')])
                self.assertEquals(macro_count, results[file_name][KEY_MACRO_COUNT])

    def test_file_analysis_002_archive_000_zip(self):

        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.initialize_storage()
        shutil.copy('test_data/zip/test.zip', root.storage_dir)
        _file = root.add_observable(F_FILE, 'test.zip')
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_archive', 'test_groups')
        engine.enable_module('analysis_module_file_type', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root.load()
        _file = root.get_observable(_file.id)
        
        from saq.modules.file_analysis import ArchiveAnalysis
        analysis = _file.get_analysis(ArchiveAnalysis)
        self.assertIsNotNone(analysis)
        self.assertEquals(analysis.file_count, 1)
        _file = analysis.get_observables_by_type(F_FILE)
        self.assertEquals(len(_file), 1)

    def test_file_analysis_002_archive_001_rar(self):

        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.initialize_storage()
        shutil.copy('test_data/rar/test.r07', root.storage_dir)
        _file = root.add_observable(F_FILE, 'test.r07')
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_archive', 'test_groups')
        engine.enable_module('analysis_module_file_type', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root.load()
        _file = root.get_observable(_file.id)
        
        from saq.modules.file_analysis import ArchiveAnalysis
        analysis = _file.get_analysis(ArchiveAnalysis)
        self.assertIsNotNone(analysis)
        self.assertEquals(analysis.file_count, 1)
        _file = analysis.get_observables_by_type(F_FILE)
        self.assertEquals(len(_file), 1)

    def test_file_analysis_archive_7z_under(self):

        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.initialize_storage()
        shutil.copy('test_data/7z/under.7z', root.storage_dir)
        _file = root.add_observable(F_FILE, 'under.7z')
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_archive', 'test_groups')
        engine.enable_module('analysis_module_file_type', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root.load()
        _file = root.get_observable(_file.id)
        
        from saq.modules.file_analysis import ArchiveAnalysis
        analysis = _file.get_analysis(ArchiveAnalysis)
        self.assertIsNotNone(analysis)
        self.assertEquals(analysis.file_count, 1)
        _file = analysis.get_observables_by_type(F_FILE)
        self.assertEquals(len(_file), 1)

    @unittest.skip("test data modified -- revisit soon")
    def test_file_analysis_archive_7z_over(self):

        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.initialize_storage()
        shutil.copy('test_data/7z/over.7z', root.storage_dir)
        _file = root.add_observable(F_FILE, 'over.7z')
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_archive', 'test_groups')
        engine.enable_module('analysis_module_file_type', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root.load()
        _file = root.get_observable(_file.id)
        
        from saq.modules.file_analysis import ArchiveAnalysis
        analysis = _file.get_analysis(ArchiveAnalysis)
        self.assertIsNotNone(analysis)
        self.assertFalse(analysis)

    def test_file_analysis_002_archive_002_ace(self):

        if not os.path.exists('test_data/ace/dhl_report.ace'):
            self.skipTest("missing test data")

        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.initialize_storage()
        shutil.copy('test_data/ace/dhl_report.ace', root.storage_dir)
        _file = root.add_observable(F_FILE, 'dhl_report.ace')
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_archive', 'test_groups')
        engine.enable_module('analysis_module_file_type', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root.load()
        _file = root.get_observable(_file.id)
        
        from saq.modules.file_analysis import ArchiveAnalysis
        analysis = _file.get_analysis(ArchiveAnalysis)
        self.assertIsNotNone(analysis)
        self.assertEquals(analysis.file_count, 1)
        _file = analysis.get_observables_by_type(F_FILE)
        self.assertEquals(len(_file), 1)

    def test_file_analysis_002_archive_003_jar(self):

        from saq.crypto import decrypt
        decrypt('test_data/jar/test.jar.e', 'test_data/jar/test.jar', password='ace')

        if not os.path.exists('test_data/jar/test.jar'):
            self.skipTest("missing test data")

        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.initialize_storage()
        shutil.copy('test_data/jar/test.jar', root.storage_dir)
        _file = root.add_observable(F_FILE, 'test.jar')
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_archive', 'test_groups')
        engine.enable_module('analysis_module_file_type', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root.load()
        _file = root.get_observable(_file.id)
        
        from saq.modules.file_analysis import ArchiveAnalysis
        analysis = _file.get_analysis(ArchiveAnalysis)
        self.assertIsNotNone(analysis)
        self.assertEquals(analysis.file_count, 42)

        os.remove('test_data/jar/test.jar')

    def test_file_analysis_002_archive_004_jar(self):

        if not os.path.exists('test_data/jar/too_many_files.jar'):
            self.skipTest("missing test data")

        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.initialize_storage()
        shutil.copy('test_data/jar/too_many_files.jar', root.storage_dir)
        _file = root.add_observable(F_FILE, 'too_many_files.jar')
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_archive', 'test_groups')
        engine.enable_module('analysis_module_file_type', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root.load()
        _file = root.get_observable(_file.id)
        
        from saq.modules.file_analysis import ArchiveAnalysis
        analysis = _file.get_analysis(ArchiveAnalysis)
        self.assertIsNotNone(analysis)
        self.assertFalse(analysis)
        
#     def test_file_analysis_003_xml_000_rels(self):

#         root = create_root_analysis(uuid=str(uuid.uuid4()))
#         root.initialize_storage()
#         shutil.copy('test_data/docx/xml_rel.docx', root.storage_dir)
#         _file = root.add_observable(F_FILE, 'xml_rel.docx')
#         root.save()
#         root.schedule()

#         engine = TestEngine()
#         engine.enable_module('analysis_module_archive', 'test_groups')
#         engine.enable_module('analysis_module_file_type', 'test_groups')
#         engine.enable_module('analysis_module_office_xml_rel', 'test_groups')
#         engine.controlled_stop()
#         engine.start()
#         engine.wait()

#         root.load()
#         _file = root.get_observable(_file.id)
        
#         from saq.modules.file_analysis import ArchiveAnalysis
#         analysis = _file.get_analysis(ArchiveAnalysis)
#         self.assertTrue(analysis)

#         # there should be one file called document.xml.rels
#         rel_file = None
#         for sub_file in analysis.get_observables_by_type(F_FILE):
#             if os.path.basename(sub_file.value) == 'document.xml.rels':
#                 rel_file = sub_file
#                 break

#         self.assertIsNotNone(rel_file)
        
#         from saq.modules.file_analysis import OfficeXMLRelationshipExternalURLAnalysis
#         analysis = rel_file.get_analysis(OfficeXMLRelationshipExternalURLAnalysis)
#         self.assertTrue(analysis)

#         url = analysis.get_observables_by_type(F_URL)
#         self.assertEquals(len(url), 1)

    def test_file_analysis_004_yara_000_basic_scan(self):

        self.initialize_yss()

        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.initialize_storage()
        shutil.copy('test_data/scan_targets/match', root.storage_dir)
        _file = root.add_observable(F_FILE, 'match')
        root.save()
        root.schedule()
        
        engine = TestEngine()
        engine.enable_module('analysis_module_yara_scanner_v3_4', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        # scanned file /opt/saq/var/test/91b55d6f-fe82-4508-ac68-bbc519693d12/scan.target with yss (matches found: True)
        self.assertEquals(log_count('with yss (matches found: True)'), 1)

        root.load()
        _file = root.get_observable(_file.id)
        
        from saq.modules.file_analysis import YaraScanResults_v3_4
        analysis = _file.get_analysis(YaraScanResults_v3_4)
        self.assertTrue(analysis)

        # the file should be instructed to go to the sandbox
        self.assertTrue(_file.has_directive(DIRECTIVE_SANDBOX))
        # and should have a single tag
        self.assertEquals(len(_file.tags), 1)
        # the analysis should have a yara_rule observable
        yara_rule = analysis.get_observables_by_type(F_YARA_RULE)
        self.assertEquals(len(yara_rule), 1)
        yara_rule = yara_rule[0]
        # the yara rule should have detections
        self.assertTrue(yara_rule.detections)

    def test_file_analysis_004_yara_001_local_scan(self):
        
        # we do not initalize the local yss scanner so it should not be available for scanning

        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.initialize_storage()
        shutil.copy('test_data/scan_targets/match', root.storage_dir)
        _file = root.add_observable(F_FILE, 'match')
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_yara_scanner_v3_4', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        self.assertEquals(log_count('with yss (matches found: True)'), 0)
        self.assertEquals(log_count('failed to connect to yara socket server'), 1)
        self.assertEquals(log_count('initializing local yara scanner'), 1)
        self.assertEquals(log_count('got yara results for'), 1)

        root.load()
        _file = root.get_observable(_file.id)
        
        from saq.modules.file_analysis import YaraScanResults_v3_4
        analysis = _file.get_analysis(YaraScanResults_v3_4)
        self.assertTrue(analysis)

        # the file should be instructed to go to the sandbox
        self.assertTrue(_file.has_directive(DIRECTIVE_SANDBOX))
        # and should have a single tag
        self.assertEquals(len(_file.tags), 1)
        # the analysis should have a yara_rule observable
        yara_rule = analysis.get_observables_by_type(F_YARA_RULE)
        self.assertEquals(len(yara_rule), 1)
        yara_rule = yara_rule[0]
        # the yara rule should have detections
        self.assertTrue(yara_rule.detections)

    def test_file_analysis_004_yara_002_no_alert(self):
        
        self.initialize_yss()

        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.initialize_storage()
        shutil.copy('test_data/scan_targets/no_alert', root.storage_dir)
        _file = root.add_observable(F_FILE, 'no_alert')
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_yara_scanner_v3_4', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        self.assertEquals(log_count('with yss (matches found: True)'), 1)

        root.load()
        _file = root.get_observable(_file.id)
        
        from saq.modules.file_analysis import YaraScanResults_v3_4
        analysis = _file.get_analysis(YaraScanResults_v3_4)
        self.assertTrue(analysis)

        # the file should NOT be instructed to go to the sandbox
        self.assertFalse(_file.has_directive(DIRECTIVE_SANDBOX))
        # the analysis should have a yara_rule observable
        yara_rule = analysis.get_observables_by_type(F_YARA_RULE)
        self.assertEquals(len(yara_rule), 1)
        yara_rule = yara_rule[0]
        # the yara rule should NOT have detections
        self.assertFalse(yara_rule.detections)

    def test_file_analysis_004_yara_003_directives(self):
        
        self.initialize_yss()

        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.initialize_storage()
        shutil.copy('test_data/scan_targets/add_directive', root.storage_dir)
        _file = root.add_observable(F_FILE, 'add_directive')
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_yara_scanner_v3_4', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        self.assertEquals(log_count('with yss (matches found: True)'), 1)

        root.load()
        _file = root.get_observable(_file.id)
        
        from saq.modules.file_analysis import YaraScanResults_v3_4
        analysis = _file.get_analysis(YaraScanResults_v3_4)
        self.assertTrue(analysis)

        # the file should be instructed to go to the sandbox
        self.assertTrue(_file.has_directive(DIRECTIVE_SANDBOX))
        # the analysis should have a yara_rule observable
        yara_rule = analysis.get_observables_by_type(F_YARA_RULE)
        self.assertEquals(len(yara_rule), 1)
        yara_rule = yara_rule[0]
        # the yara rule should have detections
        self.assertTrue(yara_rule.detections)

        # and we should have an extra directive
        self.assertTrue(_file.has_directive(DIRECTIVE_EXTRACT_URLS))

    def test_file_analysis_004_yara_004_directives_redirection(self):
        
        self.initialize_yss()

        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.initialize_storage()
        shutil.copy('test_data/scan_targets/add_directive', root.storage_dir)
        shutil.copy('test_data/scan_targets/parent_file', root.storage_dir)
        parent_file = root.add_observable(F_FILE, 'parent_file')
        child_file = root.add_observable(F_FILE, 'add_directive')
        child_file.redirection = parent_file
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_yara_scanner_v3_4', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        self.assertEquals(log_count('with yss (matches found: True)'), 1)

        root.load()
        child_file_observable = root.get_observable(child_file.id)
        parent_file_observable = root.get_observable(parent_file.id)
        
        from saq.modules.file_analysis import YaraScanResults_v3_4
        analysis = child_file_observable.get_analysis(YaraScanResults_v3_4)
        self.assertTrue(analysis)

        # the parent file should be instructed to go to the sandbox
        self.assertTrue(parent_file_observable.has_directive(DIRECTIVE_SANDBOX))
        # the child file analysis should have a yara_rule observable
        yara_rule = analysis.get_observables_by_type(F_YARA_RULE)
        self.assertEquals(len(yara_rule), 1)
        yara_rule = yara_rule[0]
        # the yara rule should have detections
        self.assertTrue(yara_rule.detections)

    def test_file_analysis_004_yara_005_crits(self):
        
        self.initialize_yss()

        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.initialize_storage()
        shutil.copy('test_data/scan_targets/crits', root.storage_dir)
        _file = root.add_observable(F_FILE, 'crits')
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_yara_scanner_v3_4', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        self.assertEquals(log_count('with yss (matches found: True)'), 1)

        root.load()
        _file = root.get_observable(_file.id)
        
        from saq.modules.file_analysis import YaraScanResults_v3_4
        analysis = _file.get_analysis(YaraScanResults_v3_4)
        self.assertTrue(analysis)

        # the file should be instructed to go to the sandbox
        self.assertTrue(_file.has_directive(DIRECTIVE_SANDBOX))
        # the analysis should have a yara_rule observable
        yara_rule = analysis.get_observables_by_type(F_YARA_RULE)
        self.assertEquals(len(yara_rule), 1)
        yara_rule = yara_rule[0]
        # the yara rule should have detections
        self.assertTrue(yara_rule.detections)

        # we should have a single crits observable
        crits_id = analysis.get_observables_by_type(F_INDICATOR)
        self.assertEquals(len(crits_id), 1)

    def test_file_analysis_004_yara_006_whitelist(self):

        self.initialize_yss()

        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.initialize_storage()
        shutil.copy('test_data/scan_targets/whitelist', root.storage_dir)
        _file = root.add_observable(F_FILE, 'whitelist')
        root.save()
        root.schedule()
        
        engine = TestEngine()
        engine.enable_module('analysis_module_yara_scanner_v3_4', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        # scanned file /opt/saq/var/test/91b55d6f-fe82-4508-ac68-bbc519693d12/scan.target with yss (matches found: True)
        self.assertEquals(log_count('with yss (matches found: True)'), 1)

        root.load()
        _file = root.get_observable(_file.id)
        
        from saq.modules.file_analysis import YaraScanResults_v3_4
        analysis = _file.get_analysis(YaraScanResults_v3_4)
        self.assertTrue(analysis)

        # the file should have a single tag
        self.assertEquals(len(_file.tags), 1)
        # the tag should be "whitelisted"
        self.assertEquals(_file.tags[0].name, "whitelisted")
        # the root analysis object should be whitelisted
        self.assertTrue(root.whitelisted)

    def test_file_analysis_004_yara_007_qa_modifier(self):

        self.initialize_yss()

        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.initialize_storage()
        shutil.copy('test_data/scan_targets/qa_modifier_target', root.storage_dir)
        _file = root.add_observable(F_FILE, 'qa_modifier_target')
        root.save()
        root.schedule()
        
        engine = TestEngine()
        engine.enable_module('analysis_module_yara_scanner_v3_4', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        # scanned file /opt/saq/var/test/91b55d6f-fe82-4508-ac68-bbc519693d12/scan.target with yss (matches found: True)
        self.assertEquals(log_count('with yss (matches found: True)'), 1)

        root.load()
        _file = root.get_observable(_file.id)
        
        from saq.modules.file_analysis import YaraScanResults_v3_4
        analysis = _file.get_analysis(YaraScanResults_v3_4)
        self.assertTrue(analysis)

        # the file should *not* have any detection points

        # the yara rule should NOT have detections
        self.assertTrue(len(root.all_detection_points) == 0)
        # there should be a file named after the md5 of the file
        target_dir = os.path.join(saq.DATA_DIR, saq.CONFIG['analysis_module_yara_scanner_v3_4']['qa_dir'])
        target_path = os.path.join(target_dir, 'test_qa_modifier', _file.md5_hash)
        self.assertTrue(os.path.exists(target_path))
        self.assertTrue(os.path.exists(f'{target_path}.json'))

    def test_file_analysis_005_pcode_000_extract_pcode(self):

        if not os.path.exists('test_data/ole_files/word2013_macro_stripped.doc'):
            self.skipTest("missing test data")

        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.initialize_storage()
        shutil.copy('test_data/ole_files/word2013_macro_stripped.doc', root.storage_dir)
        _file = root.add_observable(F_FILE, 'word2013_macro_stripped.doc')
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_pcodedmp', 'test_groups')
        engine.enable_module('analysis_module_file_type', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root.load()
        _file = root.get_observable(_file.id)
        self.assertIsNotNone(_file)

        from saq.modules.file_analysis import PCodeAnalysis
        analysis = _file.get_analysis(PCodeAnalysis)
        self.assertTrue(analysis)
        # we should have extracted 11 lines of macro
        self.assertEquals(analysis.details, 11)
        # and we should have a file with the macros
        _file = analysis.get_observables_by_type(F_FILE)
        self.assertEquals(len(_file), 1)
        _file = _file[0]
        # and that should have a redirection
        self.assertIsNotNone(_file.redirection)

    def test_file_analysis_005_office_file_archiver_000_archive(self):

        from saq.crypto import decrypt
        decrypt('test_data/ole_files/Paid Invoice.doc.e', 'test_data/ole_files/Paid Invoice.doc', password='ace')

        if not os.path.exists('test_data/ole_files/Paid Invoice.doc'):
            self.skipTest("missing test data")

        # clear existing archive dir
        target_dir = os.path.join(saq.DATA_DIR, saq.CONFIG['analysis_module_office_file_archiver']['office_archive_dir'])
        try:
            if os.path.isdir(target_dir):
                shutil.rmtree(target_dir)

            os.mkdir(target_dir)

        except Exception as e:
            logging.error("unable to reset {}: {}".format(target_dir, e))

        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.initialize_storage()
        shutil.copy('test_data/ole_files/Paid Invoice.doc', root.storage_dir)
        _file = root.add_observable(F_FILE, 'Paid Invoice.doc')
        sha256 = _file.sha256_hash
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_office_file_archiver', 'test_groups')
        engine.enable_module('analysis_module_file_type', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root.load()
        _file = root.get_observable(_file.id)
        self.assertIsNotNone(_file)

        from saq.modules.file_analysis import OfficeFileArchiveAction
        analysis = _file.get_analysis(OfficeFileArchiveAction)
        self.assertTrue(analysis)
        
        # the details of the analysis should be the FULL path to the archived file
        self.assertTrue(analysis.details)
        self.assertTrue(os.path.exists(analysis.details))

        # make sure we can decrypt it
        target_dir = tempfile.mkdtemp(dir=saq.TEMP_DIR)
        target_path = os.path.join(target_dir, _file.value)
        decrypt(analysis.details, target_path)
        h = hashlib.sha256()
        with open(target_path, 'rb') as fp:
            h.update(fp.read())

        self.assertTrue(h.hexdigest().lower() == sha256.lower())

        root = create_root_analysis(uuid=str(uuid.uuid4()))
        root.initialize_storage()
        shutil.copy('test_data/ole_files/Paid Invoice.doc', root.storage_dir)
        _file = root.add_observable(F_FILE, 'Paid Invoice.doc')
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_office_file_archiver', 'test_groups')
        engine.enable_module('analysis_module_file_type', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root.load()
        _file = root.get_observable(_file.id)
        self.assertIsNotNone(_file)

        from saq.modules.file_analysis import OfficeFileArchiveAction
        analysis = _file.get_analysis(OfficeFileArchiveAction)
        self.assertTrue(analysis)
        
        # the details of the analysis should be the FULL path to the archived file
        self.assertTrue(analysis.details)
        self.assertTrue(os.path.exists(analysis.details))

        # but it should also be a duplicate so the name should have the number prefix
        self.assertTrue(os.path.basename(analysis.details).startswith('000000_'))

        os.remove('test_data/ole_files/Paid Invoice.doc')
    
    def test_file_analysis_006_extracted_ole_000_js(self):

        from saq.crypto import decrypt
        decrypt('test_data/docx/js_ole_obj.docx.e', 'test_data/docx/js_ole_obj.docx', password='ace')

        if not os.path.exists('test_data/docx/js_ole_obj.docx'):
            self.skipTest("missing test data")

        root = create_root_analysis()
        root.initialize_storage()
        shutil.copy('test_data/docx/js_ole_obj.docx', root.storage_dir)
        _file = root.add_observable(F_FILE, 'js_ole_obj.docx')
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_archive', 'test_groups')
        engine.enable_module('analysis_module_extracted_ole_analyzer', 'test_groups')
        engine.enable_module('analysis_module_officeparser_v1_0', 'test_groups')
        engine.enable_module('analysis_module_file_type', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root.load()
        _file = root.get_observable(_file.id)
        self.assertIsNotNone(_file)
        self.assertTrue(any([d for d in root.all_detection_points if 'compiles as JavaScript' in d.description]))

        os.remove('test_data/docx/js_ole_obj.docx')

    def test_open_office_extraction(self):

        from saq.crypto import decrypt
        decrypt('test_data/openoffice/demo.odt.e', 'test_data/openoffice/demo.odt', password='ace')

        root = create_root_analysis()
        root.initialize_storage()
        shutil.copy('test_data/openoffice/demo.odt', root.storage_dir)
        _file = root.add_observable(F_FILE, 'demo.odt')
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_archive', 'test_groups')
        engine.enable_module('analysis_module_file_type', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root = RootAnalysis(storage_dir=root.storage_dir)
        root.load()
        _file = root.get_observable(_file.id)
        self.assertIsNotNone(_file)

        analysis = _file.get_analysis('ArchiveAnalysis')
        self.assertIsNotNone(analysis)
        self.assertEquals(len(analysis.find_observables(F_FILE)), 12)

        os.remove('test_data/openoffice/demo.odt')

    def test_crawl_extracted_urls(self):

        self.initialize_yss()

        root = create_root_analysis()
        root.initialize_storage()
        shutil.copy('test_data/url_extraction/simple.txt', root.storage_dir)
        _file = root.add_observable(F_FILE, 'simple.txt')
        _file.add_directive(DIRECTIVE_EXTRACT_URLS)
        _file.add_directive(DIRECTIVE_CRAWL_EXTRACTED_URLS)
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_file_type', 'test_groups')
        engine.enable_module('analysis_module_yara_scanner_v3_4', 'test_groups')
        engine.enable_module('analysis_module_url_extraction', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root = RootAnalysis(storage_dir=root.storage_dir)
        root.load()
        _file = root.get_observable(_file.id)
        self.assertIsNotNone(_file)

        analysis = _file.get_analysis('URLExtractionAnalysis')
        self.assertIsNotNone(analysis)

        # since the DIRECTIVE_CRAWL_EXTRACTED_URLS is on the file the all the URLs should be crawled
        self.assertTrue(len(analysis.observables) == 2)
        for observable in analysis.observables:
            self.assertTrue(observable.has_directive(DIRECTIVE_CRAWL))

    @unittest.skip("Missing test data.")
    def test_correlated_tag(self):

        from saq.database import Alert

        self.initialize_yss()
        
        root = create_root_analysis(analysis_mode='test_groups')
        root.initialize_storage()
        shutil.copy(os.path.join('test_data', 'ppt', 'Payment_Details.ppsx'), root.storage_dir)
        file_observable = root.add_observable(F_FILE, 'Payment_Details.ppsx')
        root.save()
        root.schedule()
    
        engine = TestEngine(pool_size_limit=1)
        engine.enable_alerting()
        engine.enable_module('analysis_module_correlated_tag_analyzer', 'test_groups')
        engine.enable_module('analysis_module_archive', 'test_groups')
        engine.enable_module('analysis_module_file_type', 'test_groups')
        engine.enable_module('analysis_module_yara_scanner_v3_4', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        # we should have an alert
        alert = saq.db.query(Alert).first()
        self.assertIsNotNone(alert)

    @unittest.skip("Missin test data.")
    def test_mhtml_analysis(self):

        root = create_root_analysis(analysis_mode='test_groups')
        root.initialize_storage()
        shutil.copy(os.path.join('test_data', 'mhtml', 'Invoice_PDF.mht'), root.storage_dir)
        file_observable = root.add_observable(F_FILE, 'Invoice_PDF.mht')
        root.save()
        root.schedule()
    
        engine = TestEngine(pool_size_limit=1)
        engine.enable_alerting()
        engine.enable_module('analysis_module_mhtml', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root = RootAnalysis(storage_dir=root.storage_dir)
        root.load()
        file_observable = root.get_observable(file_observable.id)
        self.assertIsNotNone(file_observable)

        from saq.modules.file_analysis import MHTMLAnalysis
        analysis = file_observable.get_analysis(MHTMLAnalysis)
        self.assertIsNotNone(analysis)
        # should have extracted a single file
        self.assertEquals(len(analysis.details), 1)
        self.assertEquals(len(analysis.get_observables_by_type(F_FILE)), 1)
