# vim: sw=4:ts=4:et:cc=120

from saq.constants import *
from saq.test import *

class TestCase(ACEModuleTestCase):
    def test_command_line_analyzer(self):
        from saq.modules.command_line import CommandLineAnalysis

        root = create_root_analysis()
        root.initialize_storage()

        command_line_observable = root.add_observable(F_COMMAND_LINE, "\"C:\\WINDOWS\\system32\\cmd.exe\" /c COPY \"\\\\some_domain.some_host.com\\Shares\\Database.lnk\" \"C:\\Users\\john\\Desktop\\Database.lnk\"")
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_command_line_analyzer', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root.load()
        command_line_observable = root.get_observable(command_line_observable.id)
        self.assertIsNotNone(command_line_observable)
        analysis = command_line_observable.get_analysis(CommandLineAnalysis)
        self.assertIsNotNone(analysis)
        self.assertEquals(len(analysis.file_paths), 3)
        self.assertTrue(r'C:\WINDOWS\system32\cmd.exe' in analysis.file_paths)
        self.assertTrue(r'C:\Users\john\Desktop\Database.lnk' in analysis.file_paths)
        self.assertTrue(r'\\some_domain.some_host.com\Shares\Database.lnk' in analysis.file_paths)

        self.assertIsNotNone(
                analysis.find_observable(lambda o: o.type == F_FILE_PATH and o.value == r'C:\WINDOWS\system32\cmd.exe'))
        self.assertIsNotNone(
                analysis.find_observable(lambda o: o.type == F_FILE_PATH and o.value == r'C:\Users\john\Desktop\Database.lnk'))
        self.assertIsNotNone(
                analysis.find_observable(lambda o: o.type == F_FILE_PATH and o.value == r'\\some_domain.some_host.com\Shares\Database.lnk'))
