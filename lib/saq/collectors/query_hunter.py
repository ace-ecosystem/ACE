# vim: sw=4:ts=4:et:cc=120
#
# ACE Hunting System - query based hunting
#

import saq
from saq.collectors.hunter import Hunt

class QueryHunt(Hunt):
    """Abstract class that represents a hunt against a search system that queries data over a time range."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.earliest = None
        self.latest = None
        self.full_coverage = bool()
        self.group_by = None
        self.query = None

        self.observable_mapping = {} # key = field, value = observable type
        self.temporal_fields = [] # of fields
        self.directives = {} # key = field, value = [ directive ]
    
    def load_from_ini(self, path, *args, **kwargs):
        config = super().load_from_ini(path, *args, **kwargs)

        self.earliest = section_rule['earliest']
        self.latest = section_rule['latest']
        self.full_coverage = section_rule.getboolean('full_coverage')
        self.group_by = section_rule['group_by']
        self.search_query_path = section_rule['search']
        self.query = self.load_search_query(section_rule['search'])

        seciton_observable_mapping = config['observable_mapping']
        
        self.observable_mapping = {}
        for key, value in section_observable_mapping.items():
            if value not in VALID_OBSERVABLE_TYPES:
                raise ValueError(f"invalid observable type {value}")

            self.observable_mapping[key] = value

        section_temporal_fields = config['temporal_fields']
        self.temporal_fields = section_temporal_fields.options()

        section_directives = config['directives']
    
        self.directives = {}
        for key, value in section_directives.items():
            self.directives[key] = []
            directives = [_.strip() for _ in value.split(',')]
            for directive in directives:
                if directive not in VALID_DIRECTIVES:
                    raise ValueError(f"invalid directive {directive}")

                self.directives[key].append(directive)

        return config

    def load_search_query(self, path):
        """Loads the query to be used by this hunt from the given path.
           Returns the query if it was loaded correctly, None otherwise."""
        raise NotImplementedError()
