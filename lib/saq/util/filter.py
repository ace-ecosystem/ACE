# vim: sw=4:ts=4:et:cc=120
#
# utility functions for dealing with filters and filtering
#

import re

FILTER_TYPE_STRING_EQUALS = 'eq'
FILTER_TYPE_STRING_SUB = 'sub'
FILTER_TYPE_STRING_GLOB = 'glob'
FILTER_TYPE_STRING_REGEX = 're'
FILTER_TYPE_CIDR = 'cidr'
FILTER_TYPE_DOMAIN = 'domain'

class Filter(object):
    def __init__(self, filter_type=None, filter_value=None, ignore_case=False, inverted=False):
        self.filter_type = filter_type
        self.filter_value = filter_value
        self.ignore_case = ignore_case
        self.inverted = inverted

    def matches(self, target):
        """Returns True if this filter matches the target.
           Raises ValueError if target is None.
           Raises TypeError if target is not the data type the filter expects."""

        if self.inverted:
            return not self.execute_filter(target)
        else:
            return self.execute_filter(target)

    def execute_filter(self, target):
        """Implements the logic of the filter and returns the result."""
        raise NotImplementedError()

    def __str__(self):
        return f"Filter({self.filter_type},{self.filter_value}" \
               + ("(inverted)" if self.inverted else "") \
               + ("(ignore_case)" if self.ignore_case else "") \
               + ")"

class StringEqualsFilter(Filter):
    """Simple match filter."""
    def __init__(self, filter_value, *args, **kwargs):
        super().__init__(filter_type=FILTER_TYPE_STRING_EQUALS, 
                         filter_value=filter_value, 
                         *args, **kwargs)

    def execute_filter(self, target):
        if target is None:
            raise ValueError

        if not isinstance(target, str):
            raise TypeError

        if self.ignore_case:
            return self.filter_value.lower() == target.lower()
        else:
            return self.filter_value == target

class StringSubFilter(Filter):
    """Simple substring match filter."""
    def __init__(self, filter_value, *args, **kwargs):
        super().__init__(filter_type=FILTER_TYPE_STRING_SUB, 
                         filter_value=filter_value, 
                         *args, **kwargs)

    def execute_filter(self, target):
        if target is None:
            raise ValueError

        if not isinstance(target, str):
            raise TypeError

        if self.ignore_case:
            return self.filter_value.lower() in target.lower()
        else:
            return self.filter_value in target

class StringRegexFilter(Filter):
    """Filter that matches based on a regular expression."""
    def __init__(self, filter_value, *args, **kwargs):
        super().__init__(filter_type=FILTER_TYPE_STRING_REGEX, 
                         filter_value=filter_value,
                         *args, **kwargs)

        self.compiled_regex = re.compile(filter_value, flags=re.I if self.ignore_case else 0)

    def execute_filter(self, target):
        if target is None:
            raise ValueError

        if not isinstance(target, str):
            raise TypeError

        return self.compiled_regex.search(target)

# maps type to class
FILTER_TYPE_MAP = {
    FILTER_TYPE_STRING_EQUALS: StringEqualsFilter,
    FILTER_TYPE_STRING_SUB: StringSubFilter,
    FILTER_TYPE_STRING_REGEX: StringRegexFilter,
}

def load_filter(filter_type, filter_value, *args, **kwargs):
    try:
        return FILTER_TYPE_MAP[filter_type](filter_value=filter_value, *args, **kwargs)
    except KeyError:
        logging.error(f"invalid filter_type {filter_type}")
        raise

def parse_filter_spec(spec):
    """Parses a filter spec and returns the configured Filter object it defines.
       A filter spec is defined as follows:
       [!]type[_i]:value
       type: the type of the filter (see FILTER_TYPE_MAP for the list of possible values)
       value: the filter itself which depends on the type
       If the type starts with a ! then the result is inverted (logical NOT).
       If the type ends with _i then case is ignored (for string type filters only.)"""
    filter_type, filter_value = spec.split(':', 1)
    inverted = False
    if filter_type.startswith('!'):
        filter_type = filter_type[1:]
        inverted = True

    ignore_case = False
    if filter_type.endswith('_i'):
        filter_type = filter_type[:-2]
        ignore_case = True

    return load_filter(filter_type, filter_value, inverted=inverted, ignore_case=ignore_case)
