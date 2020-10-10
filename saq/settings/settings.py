import json
from saq.database.meta import Base
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.orm import relationship, class_mapper, backref
from sqlalchemy.orm.collections import attribute_mapped_collection
from sqlalchemy.schema import UniqueConstraint

class Setting(Base):
    __tablename__ = 'settings'
    id = Column(Integer, primary_key=True)
    key = Column(String(60), index=True)
    type = Column(String(40), nullable=True, default=None)
    _value = Column('value', String, nullable=True, default=None)
    tooltip = Column(String, nullable=True, default=None)
    parent_id = Column(
        Integer,
        ForeignKey('settings.id', ondelete='CASCADE', onupdate='CASCADE'),
        index=True,
        nullable=True,
        default=None,
    )
    default_parent_id = Column(
        Integer,
        ForeignKey('settings.id', ondelete='CASCADE', onupdate='CASCADE'),
        index=True,
        nullable=True,
        default=None,
    )
    children = relationship(
        'Setting',
        collection_class = attribute_mapped_collection('key'),
        order_by = 'asc(Setting.key)',
        foreign_keys = 'Setting.parent_id',
        remote_side = 'Setting.parent_id',
        backref = backref('parent', remote_side='Setting.id'),
    )
    default_child = relationship(
        'Setting',
        foreign_keys = 'Setting.default_parent_id',
        remote_side = 'Setting.default_parent_id',
        uselist = False,
    )
    __table_args__ = (
        UniqueConstraint('parent_id', 'key', name='setting_id'),
        UniqueConstraint('default_parent_id', name='map_default_child'),
    )
    __mapper_args__ = {'polymorphic_on': type, 'polymorphic_identity': 'String'}

    editable = True
    pattern = None

    @property
    def appendable(self):
        return self.default_child is not None

    @property
    def collapsible(self):
        return len(self.children) > 0

    @property
    def options(self):
        return None

    @property
    def value(self):
        return self._value

    @property
    def path(self):
        path = f'/{self.key}'
        if self.parent is not None:
            path = f'{self.parent.path}{path}'
        return path

    def __iter__(self):
        return iter(self.children)

    def __contains__(self, key):
        return key in self.children

    def __getitem__(self, key):
        return self.children[key].value

    def copy(self):
        copy = self.__class__(
            key = self.key,
            type = self.type,
            _value = self._value,
            tooltip = self.tooltip,
        )
        for key in self.children:
            copy.children[key] = self.children[key].copy()
        return copy

    def new_child(self):
        setting = self.default_child.copy()
        setting.parent = self
        setting.parent_id = self.id
        return setting

    def to_dict(self):
        d = {'key':self.key, 'type':self.type, '_value':self._value, 'tooltip':self.tooltip, 'children': {}}
        if self.default_child is not None:
            d['default_child'] = self.default_child.to_dict()
        for key in self.children:
            d['children'][key] = self.children[key].to_dict()
        return d

    @staticmethod
    def from_dict(d):
        cls = class_mapper(Setting).polymorphic_map[d['type']].class_
        setting = cls(key=d['key'], _value=d['_value'], tooltip=d['tooltip'])
        if 'default_child' in d:
            setting.default_child = Setting.from_dict(d['default_child'])
        for key in d['children']:
            setting.children[key] = Setting.from_dict(d['children'][key])
        return setting

    def to_json(self, **kwargs):
        return json.dumps(self.to_dict(), **kwargs)

    @staticmethod
    def from_json(j):
        return Setting.from_dict(json.loads(j))

class DictionarySetting(Setting):
    __mapper_args__ = { 'polymorphic_identity': 'Dictionary' }
    editable = False

    @Setting.value.getter
    def value(self):
        return self

class NumericSetting(Setting):
    __mapper_args__ = { 'polymorphic_identity': 'Numeric' }
    pattern = r'-?\d+(\.\d+)?'

    @Setting.value.getter
    def value(self):
        return float(self._value)

class BooleanSetting(Setting):
    __mapper_args__ = { 'polymorphic_identity': 'Boolean' }

    @Setting.options.getter
    def options(self):
        return [True, False]

    @Setting.value.getter
    def value(self):
        return self._value == 'True'
