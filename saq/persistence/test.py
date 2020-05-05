# vim: sw=4:ts=4:et

import time

import saq
from saq.database import Persistence, func
from saq.persistence import *
from saq.test import *

class TestCase(ACEBasicTestCase):
    def test_register_source(self):
        obj = Persistable()
        persistence_source = obj.register_persistence_source('test')
        self.assertIsNotNone(persistence_source)

    def test_register_key(self):
        @persistant_property('test_key')
        class MyClass(Persistable):
            pass

        obj = MyClass()
        persistence_source = obj.register_persistence_source('test_source')
        self.assertTrue(hasattr(obj, '_test_key'))
        self.assertTrue(hasattr(obj, 'test_key'))
        self.assertTrue(obj.test_key is None)
        obj.test_key = 'test_value'
        self.assertTrue(obj.test_key == 'test_value')
        persistence = saq.db.query(Persistence).filter(Persistence.id == obj.persistence_key_mapping['test_key']).first()
        self.assertIsNotNone(persistence)
        self.assertTrue(persistence.value, 'test_value')
        saq.db.close()
        obj.test_key = 'modified_value'
        self.assertTrue(obj.test_key == 'modified_value')
        persistence = saq.db.query(Persistence).filter(Persistence.id == obj.persistence_key_mapping['test_key']).first()
        self.assertIsNotNone(persistence)
        self.assertTrue(persistence.value, 'modified_value')

    def test_register_multi_key(self):
        @persistant_property('test_key_1', 'test_key_2')
        class MyClass(Persistable):
            pass

        obj = MyClass()
        persistence_source = obj.register_persistence_source('test_source')
        self.assertTrue(hasattr(obj, '_test_key_1'))
        self.assertTrue(hasattr(obj, 'test_key_1'))
        self.assertTrue(obj.test_key_1 is None)
        self.assertTrue(hasattr(obj, '_test_key_2'))
        self.assertTrue(hasattr(obj, 'test_key_2'))
        self.assertTrue(obj.test_key_2 is None)

        obj.test_key_1 = 'test_value_1'
        self.assertTrue(obj.test_key_1 == 'test_value_1')
        persistence = saq.db.query(Persistence).filter(Persistence.id == obj.persistence_key_mapping['test_key_1']).first()
        self.assertIsNotNone(persistence)
        self.assertTrue(persistence.value, 'test_value_1')

        obj.test_key_2 = 'test_value_2'
        self.assertTrue(obj.test_key_2 == 'test_value_2')
        persistence = saq.db.query(Persistence).filter(Persistence.id == obj.persistence_key_mapping['test_key_2']).first()
        self.assertIsNotNone(persistence)
        self.assertTrue(persistence.value, 'test_value_2')

        self.assertTrue(obj.test_key_1 == 'test_value_1')
        persistence = saq.db.query(Persistence).filter(Persistence.id == obj.persistence_key_mapping['test_key_1']).first()
        self.assertIsNotNone(persistence)
        self.assertTrue(persistence.value, 'test_value_1')

    def test_load_key(self):
        @persistant_property('test_key')
        class MyClass(Persistable):
            pass

        obj = MyClass()
        persistence_source = obj.register_persistence_source('test_source')
        obj.test_key = 'test_value'

        obj = MyClass()
        persistence_source = obj.register_persistence_source('test_source')
        self.assertTrue(obj.test_key, 'test_value')

    def test_key_types(self):
        @persistant_property('test_key')
        class MyClass(Persistable):
            pass

        obj = MyClass()
        persistence_source = obj.register_persistence_source('test_source')
        obj.test_key = 'test_string'

        obj = MyClass()
        persistence_source = obj.register_persistence_source('test_source')
        self.assertTrue(obj.test_key == 'test_string')
        obj.test_key = 1

        obj = MyClass()
        persistence_source = obj.register_persistence_source('test_source')
        self.assertTrue(obj.test_key == 1)
        obj.test_key = True

        obj = MyClass()
        persistence_source = obj.register_persistence_source('test_source')
        self.assertTrue(obj.test_key)
        obj.test_key = b'1234'

        obj = MyClass()
        persistence_source = obj.register_persistence_source('test_source')
        self.assertTrue(obj.test_key == b'1234')
        obj.test_key = None

        obj = MyClass()
        persistence_source = obj.register_persistence_source('test_source')
        self.assertIsNone(obj.test_key)

    def test_persistent_value(self):
        obj = Persistable()
        obj.register_persistence_source('test_source')
        obj.save_persistent_data('test_key', 'test_data')
        saq.db.close()
        self.assertTrue(obj.load_persistent_data('test_key') == 'test_data')
        self.assertTrue(obj.persistent_data_exists('test_key'))

    def test_persistant_value_update(self):
        obj = Persistable()
        obj.register_persistence_source('test_source')
        obj.save_persistent_key('test_key')
        saq.db.close()
        old_persistence = saq.db.query(Persistence).filter(Persistence.uuid == 'test_key').first()
        self.assertIsNotNone(old_persistence)
        time.sleep(1)
        obj.save_persistent_key('test_key')
        saq.db.close()
        self.assertEquals(saq.db.query(func.count(Persistence.id)).scalar(), 1)
        new_persistence = saq.db.query(Persistence).filter(Persistence.uuid == 'test_key').first()
        self.assertTrue(old_persistence.last_update < new_persistence.last_update)
