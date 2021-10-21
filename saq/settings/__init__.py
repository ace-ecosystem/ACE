from .settings import *

root = None

def load():
    global root
    import saq
    saq.db.expire_all()
    query = saq.db.query(Setting)
    query = query.filter(Setting.parent_id.is_(None))
    query = query.filter(Setting.key == 'root')
    query = query.order_by(Setting.id.asc())
    root = query.first()

def get(id):
    import saq
    return saq.db.query(Setting).filter(Setting.id == id).one()

def delete(id):
    import saq
    setting = saq.db.query(Setting).filter(Setting.id == id).one()
    saq.db.delete(setting)
    try:
        saq.db.commit()
        return setting
    except Exception as e:
        saq.db.rollback()
        raise e

# add new setting from parent's default child
def new_child(parent_id, key, value, children):
    import saq
    parent = saq.db.query(Setting).filter(Setting.id == parent_id).one()
    setting = parent.new_child()
    setting.key = key
    setting._value = value
    for key in children:
        setting.children[key]._value = children[key]
    saq.db.add(setting)
    try:
        saq.db.commit()
        return setting
    except Exception as e:
        saq.db.rollback()
        raise e

# update existing setting
def update(id, key, value, children):
    import saq
    setting = saq.db.query(Setting).filter(Setting.id == id).one()
    setting.key = key
    setting._value = value
    for key in children:
        setting.children[key]._value = children[key]
    try:
        saq.db.commit()
        return setting
    except Exception as e:
        saq.db.rollback()
        raise e

def import_settings(root_setting):
    import saq
    load()
    try:
        saq.db.delete(root)
        saq.db.add(Setting.from_dict(root_setting))
        saq.db.commit()
    except Exception as e:
        saq.db.rollback()
        raise e
