from app import db
import datetime
from flask_login import current_user
import pytz
from sqlalchemy import and_, or_
from sqlalchemy.orm import aliased

# exact match, provides text input
class Filter:
    def __init__(self, column):
        self.column = column

    def apply(self, query, values):
        conditions = []
        for value in values:
            conditions.append(self.column == value)
        return query.filter(or_(*conditions))

# case insensitive contains match, provides text input
class TextFilter(Filter):
    def apply(self, query, values):
        conditions = []
        for value in values:
            conditions.append(self.column.ilike(f"%{value}%"))
        return query.filter(or_(*conditions))

# range match, provides a date range picker
class DateRangeFilter(Filter):
    def apply(self, query, values):
        timezone = pytz.timezone(current_user.timezone) if current_user.timezone else pytz.utc
        timezone = datetime.datetime.now(timezone).strftime("%z")

        conditions = []
        for value in values:
            start, end = value.split(' - ')
            start = datetime.datetime.strptime(f"{start} {timezone}", '%m-%d-%Y %H:%M %z').astimezone(pytz.utc)
            end = datetime.datetime.strptime(f"{end} {timezone}", '%m-%d-%Y %H:%M %z').astimezone(pytz.utc)
            conditions.append(and_(self.column >= start, self.column <= end))
        return query.filter(or_(*conditions))

# exact match, provides drop down menu for value selection
class SelectFilter(Filter):
    def __init__(self, column, nullable=False, options=None):
        super().__init__(column)
        self.options = options if options else [r[0] for r in db.session.query(self.column).order_by(self.column.asc()).distinct()]
        if nullable and None not in self.options:
            self.options.insert(0, None)

# exact match, provides text input with choices in dropdown while typing
class AutoTextFilter(SelectFilter):
    pass

# exact match, allows shift/control use for selecting multipl options
class MultiSelectFilter(SelectFilter):
    pass

# exact match, provides type drop down menu with text input for value
class TypeValueFilter(SelectFilter):
    def __init__(self, column, value_column, options=None):
        super().__init__(column, options=options)
        self.value_column = value_column

    def apply(self, query, values):
        conditions = []
        for value in values:
            conditions.append(and_(self.column == value[0], self.value_column.like(f"%{value[1]}%".encode('utf8', errors='ignore'))))
        return query.filter(or_(*conditions))
