Development Guide
=================

A guide to help with ACE development.

Collectors
----------

### Parsing Data

ACE has a couple built in classes that can aid you in parsing and
transforming data into a format that can be used to submit an alert to
your collector.

**RegexObservableParserGroup**

The `RegexObservableParserGroup` can be used to add various regular
expressions

``` {.sourceCode .python}
from saq.constants import (
    F_URL,
    F_IPV4,
    F_IPV4_CONVERSATION,
    F_IPV4_FULL_CONVERSATION,
    DIRECTIVE_CRAWL,
)
from saq.util import RegexObservableParserGroup

sample_log = "dst_ip: 10.0.0.2, port: 8080, src_ip: 10.0.0.1, port: 5555, url: https://hello.local/malicious/payload.exe\n"

# Tags you add here will be applied to all observables you find unless
#    you override the tags value at the individual parser being added.
parser_group = RegexObservableParserGroup(tags=['my_custom_parser'])

# This will capture ALL matching strings. If any are duplicates,
#    they will be filtered out when you generate the observables.
parser_group.add(r'ip: ([0-9\.]+)', F_IPV4)

# You can also add multiple capture groups and determine in which
# Order the items are extracted.
# For example, the source IP comes second in our test string, but the
#    F_IPV4_CONVERSATION is in this format: src-ip_dst-ip.
#    Note the capture groups are in reverse order to accomodate:
parser_group.add(r'ip: ([0-9\.]+).*ip: ([0-9\.]+)', F_IPV4_CONVERSATION, capture_groups=[2, 1])

# You can also change the delimiter for how all the capture groups
#    are joined together. For example, the F_IPV4_FULL_CONVERSATION
#    is delimited by colons.
parser_group.add(
    r'dst_ip: ([0-9\.]+), port: ([0-9]+), src_ip: ([0-9\.]+), port: ([0-9]+)',
    F_IPV4_FULL_CONVERSATION,
    delimiter=':',
    capture_groups=[3, 4, 1, 2]
)

# You can also add directives to control analysis/actions taken on your
#    observable.
parser_group.add(r'url: ([^\n]+)', F_URL, directives=[DIRECTIVE_CRAWL])
```

Once you've added your parsers, you can parse the data:

``` {.sourceCode .python}
parser_group.parse_content(sample_log)
```

Then you can access the observables:

``` {.sourceCode .python}
observables = parser_group.observables
```

The extractions from this example would create the following list of
dictionairies which are in an appropriate format to be submitted to the
collector:

``` {.sourceCode .python}
[
    {
        "type": "ipv4",
        "value": "10.0.0.2",
        "tags": [
            "my_custom_parser"
        ],
        "directives": []
    },
    {
        "type": "ipv4",
        "value": "10.0.0.1",
        "tags": [
            "my_custom_parser"
        ],
        "directives": []
    },
    {
        "type": "ipv4_conversation",
        "value": "10.0.0.1_10.0.0.2",
        "tags": [
            "my_custom_parser"
        ],
        "directives": []
    },
    {
        "type": "ipv4_full_conversation",
        "value": "10.0.0.1:5555:10.0.0.2:8080",
        "tags": [
            "my_custom_parser"
        ],
        "directives": []
    },
    {
        "type": "url",
        "value": "https://hello.local/malicious/payload.exe",
        "tags": [
            "my_custom_parser"
        ],
        "directives": [
            "crawl"
        ]
    }
]
```

What if you've created your own observable type? Or maybe you want to
change the way the parser groups work.

You can make subclass the `saq.util.RegexObservableParser`, override the
parsing logic, and then pass it into the parser group:

``` {.sourceCode .python}
from saq.constants import F_CUSTOM_TYPE
from saq.util import RegexObservableParserGroup, RegexObservableParser

class MyParser(RegexObservableParser):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
    # override the `RegexObservableParser.parse()` method
    def parse(self, text):
        # My custom parsing logic
        pass

parser_group = RegexObservableParserGroup()

parser_group.add(r'ip: ([0-9\.]+)', override_class=MyParser)

parser_group.parse_content(my_log)
```

When you're ready to submit to the collector:

``` {.sourceCode .python}
observables = parser_group.observables

from saq.collectors import Submission
from saq.constanants import ANALYSIS_MODE_CORRELATION

submission = Submission(
    description="My custom alert",
    analysis_mode=ANALYSIS_MODE_CORRELATION,
    tool = 'my custom tool',
    tool_instance = 'my custom tool instance',
    type = 'custom_type',
    event_time = 'datetime_from_alert',
    details = [],
    observables = observables,
    tags=[],
    files=[],
)
```
