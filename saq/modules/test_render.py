import saq.test
from saq.test import *

web_server = None


class TestCase(ACEModuleTestCase):
    def test_render_url(self):
        saq.CONFIG['analysis_module_render']['session_type'] = 'test'

        from saq.modules.render import RenderAnalysis

        root = create_root_analysis()
        root.initialize_storage()
        url = root.add_observable(F_URL, 'http://www.google.com')
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_render', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root.load()
        url = root.get_observable(url.id)
        analysis = url.get_analysis(RenderAnalysis)

        # there should be a single F_FILE observable
        file_observables = analysis.get_observables_by_type(F_FILE)
        self.assertEquals(len(file_observables), 1)
        file_observable = file_observables[0]
        self.assertTrue(file_observable.has_directive(DIRECTIVE_EXCLUDE_ALL))


    def test_render_html(self):
        saq.CONFIG['analysis_module_render']['session_type'] = 'test'

        from saq.modules.render import RenderAnalysis

        root = create_root_analysis()
        root.initialize_storage()

        shutil.copy('test_data/render/test.html', root.storage_dir)
        target_file = 'test.html'

        file_observable = root.add_observable(F_FILE, target_file)
        root.save()
        root.schedule()

        engine = TestEngine()
        engine.enable_module('analysis_module_file_type', 'test_groups')
        engine.enable_module('analysis_module_render', 'test_groups')
        engine.controlled_stop()
        engine.start()
        engine.wait()

        root.load()
        original_file = root.get_observable(file_observable.id)
        analysis = original_file.get_analysis(RenderAnalysis)

        # there should be a single F_FILE observable
        file_observables = analysis.get_observables_by_type(F_FILE)
        self.assertEquals(len(file_observables), 1)
        file_observable = file_observables[0]
        self.assertTrue(file_observable.has_directive(DIRECTIVE_EXCLUDE_ALL))
