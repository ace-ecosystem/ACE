import logging

import saq

from saq.constants import *
from saq.tip.base import GenericTIP, TIP
from saq.tip.misp import MISP


def tip_factory() -> TIP:
    try:
        if saq.CONFIG['tip']['enabled']:
            if saq.CONFIG['tip']['enabled'].lower() == 'misp':
                return MISP()
    except KeyError:
        logging.error('Missing [tip] "enabled" configuration value')

    return GenericTIP()
