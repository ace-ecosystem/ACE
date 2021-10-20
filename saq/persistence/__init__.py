# vim: sw=4:ts=4:et
#
# Persistence
# Functionality to store data in long term storage external to the system.
#

from datetime import datetime
import functools
import logging
import pickle

import saq
from saq.database import ( 
    Persistence, 
    PersistenceSource, 
    execute_with_retry, 
    get_db_connection,
    retry
)

from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy import and_, or_

def persistant_property(*key_args):
    """Utility decorator for Persistable-based objects. Adds any arguments as properties
       that automatically loads and stores the value in the persistence table in the database.
       These arguments are created as permanent persistent properties."""
    def _decorator(cls):
        @functools.wraps(cls)
        def wrapper(*args, **kwargs):
            for key in key_args:
                # this _closure function is required since we're using a for loop and a closure
                # see http://www.discoversdk.com/blog/closures-in-python-3
                def _closure(key=key):
                    internal_key = f'_{key}' # internal value
                    internal_key_loaded = f'_{key}_loaded' # boolean set to True after it's loaded
                    def _getter(self):
                        try:
                            self.load_persistent_property(key)
                        except Exception as e:
                            logging.error(f"unable to load persistence key {key}: {e}")
                        return getattr(self, internal_key)
                    def _setter(self, value):
                        try:
                            retry(self.save_persistent_property(key, value))
                        except Exception as e:
                            logging.error(f"unable to save persistence key {key}: {e}")
                        setattr(self, internal_key, value)
                    setattr(cls, internal_key, None)
                    setattr(cls, internal_key_loaded, False)
                    setattr(cls, key, property(_getter, _setter))
                _closure(key)
            return cls(*args, **kwargs)
        return wrapper
    return _decorator

class Persistable(object):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.persistence_source = None
        self.persistence_key_mapping = {}

    def register_persistence_source(self, source_name):
        persistence_source = saq.db.query(PersistenceSource).filter(
            PersistenceSource.name == source_name).first()
        
        if persistence_source is None:
            logging.info(f"registering persistence source {source_name}")
            saq.db.add(PersistenceSource(name=source_name))
            saq.db.commit()

            persistence_source = saq.db.query(PersistenceSource).filter(
                PersistenceSource.name == source_name).first()

            if persistence_source is None:
                logging.critical(f"unable to create persistence source for {source_name}")
                return None

        saq.db.expunge(persistence_source)
        self.persistence_source = persistence_source
        return self.persistence_source

    def load_persistent_property(self, key_name):
        if self.persistence_source is None:
            raise RuntimeError(f"a request to load a persistence key on {self} before register_persistence_source was called")

        internal_key = f'_{key_name}'
        internal_key_loaded = f'_{key_name}_loaded'

        # have we already loaded it?
        if getattr(self, internal_key_loaded):
            return

        persistence = saq.db.query(Persistence).filter(Persistence.source_id == self.persistence_source.id, 
                                                       Persistence.uuid == key_name).first()

        key_value = None
        if persistence is not None:
            key_value = pickle.loads(persistence.value)

        setattr(self, internal_key, key_value)
        setattr(self, internal_key_loaded, True)
        
    def save_persistent_property(self, key_name, key_value=None):
        if self.persistence_source is None:
            raise RuntimeError(f"a request to set a persistence key on {self} before register_persistence_source was called")

        # are we already tracking it?
        if key_name in self.persistence_key_mapping:
            # update the value
            saq.db.execute(Persistence.__table__.update().values(value=pickle.dumps(key_value))\
                  .where(Persistence.id == self.persistence_key_mapping[key_name]))
            saq.db.commit()
            return True
            
        # get the tracking information
        persistence = saq.db.query(Persistence).filter(Persistence.source_id == self.persistence_source.id, 
                                                       Persistence.uuid == key_name).first()

        if persistence is not None:
            # and then update the value
            self.persistence_key_mapping[key_name] = persistence.id
            saq.db.execute(Persistence.__table__.update().values(value=pickle.dumps(key_value))\
                  .where(Persistence.id == self.persistence_key_mapping[key_name]))
            saq.db.commit()
            return True
            
        # otherwise we're creating a new persistence key
        logging.debug(f"registering persistence key {key_name}")
        persistence = Persistence(source_id=self.persistence_source.id, 
                                  permanent=True, 
                                  uuid=key_name, 
                                  value=pickle.dumps(key_value))
        saq.db.add(persistence)
        saq.db.commit()
        self.persistence_key_mapping[key_name] = persistence.id
        return True

    def save_persistent_key(self, key_name):
        """Creates a new persistent key with no value recorded. The key must not already exist."""
        self.save_persistent_data(key_name)

    def save_persistent_data(self, key_name, key_value=None):
        """Creates a new persistent key with the given value recorded. The key must not already exist."""
        if key_value is not None:
            key_value = pickle.dumps(key_value)

        with get_db_connection() as db:
            c = db.cursor()
            execute_with_retry(db, c, """
INSERT INTO persistence ( 
    source_id, 
    uuid,
    value
) VALUES ( %s, %s, %s )
ON DUPLICATE KEY UPDATE last_update = CURRENT_TIMESTAMP""", (self.persistence_source.id, key_name, key_value),
            commit=True)

    def load_persistent_data(self, key_name):
        """Returns the value of the persistent key by name. Raises an exception if the key does not exist."""
        try:
            persistence = saq.db.query(Persistence).filter(Persistence.source_id == self.persistence_source.id,
                                                           Persistence.uuid == key_name).one()
        except NoResultFound:
            raise KeyError(key_name)

        if persistence.value is None:
            return None

        return pickle.loads(persistence.value)

    def persistent_data_exists(self, key_name):
        """Returns True if the given key exists, False otherwise."""
        persistence = saq.db.query(Persistence).filter(Persistence.source_id == self.persistence_source.id,
                                                       Persistence.uuid == key_name).first()
        return persistence is not None

    def delete_persistent_key(self, key_name):
        """Deletes the given persistence key."""
        saq.db.execute(Persistence.__table__.delete().where(and_(Persistence.source_id == self.persistence_source.id,
                                                            Persistence.uuid == key_name)))
        saq.db.commit()

    def delete_expired_persistent_keys(self, expiration_timedelta, unmodified_expiration_timedelta):
        """Deletes all expired persistence keys."""
        expiration_date = datetime.now() - expiration_timedelta
        unmodified_expiration_date = datetime.now() - unmodified_expiration_timedelta
        saq.db.execute(Persistence.__table__.delete().where(and_(Persistence.source_id == self.persistence_source.id,
                                                            Persistence.permanent == 0,
                                                            or_(Persistence.created_at < expiration_date, Persistence.last_update < unmodified_expiration_date)
                                                            )))
        saq.db.commit()
