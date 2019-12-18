# vim: sw=4:ts=4:et:cc=120
#
# ACE Splunk Hunting System
#

from saq.hunter import Hunt

class SplunkHunt(QueryHunt):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.use_index_time = bool()
        self.earliest = None
        self.latest = None
    
    def load_from_ini(self, *args, **kwargs):
        config = super().load_from_ini(*args, **kwargs)

        section_rule = config['rule']
        self.use_index_time = section_rule.getboolean('use_index_time')

        # earliest and latest are deprecated
        self.earliest = section_rule['earliest']
        self.latest = section_rule['latest']

    def load_search_query(self, path):
        with open(path, 'r') as fp:
            query = fp.read()

        # comments in the search files are lines that start with #
        query = re.sub(r'^\s*#.*$', '', query, count=0, flags=re.MULTILINE)
        # make sure the time spec formatter is available
        # this should really be done at load time...
        if '{time_spec}' not in query:
            logging.error(f"missing {{time_spec}} formatter in rule {self.name}")
            return None
        else:
            query = query.format(time_spec=time_spec)

        # run the includes you might have
        while True:
            m = re.search(r'<include:([^>]+)>', query)
            if not m:
                break
            
            include_path = m.group(1)
            if not os.path.exists(include_path):
                logging.fatal(f"rule {self.name} included file {include_path} does not exist")
                return None

            with open(include_path, 'r') as fp:
                included_text = re.sub(r'^\s*#.*$', '', fp.read().strip(), count=0, flags=re.MULTILINE)
                query = query.replace(m.group(0), included_text)

        return query
