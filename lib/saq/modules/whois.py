"""Module for whois analysis of domain names.

A few outcomes can be expected and must be handled.

**Note that although some of these whois_results do not tell an analyst the
'creation time' of the domain, the lack of creation time might
say 'something' to the analyst about that domain/zone. Some things to
consider:

    - The TLD is unknown/unsupported by the whois package.
    - The whois_result is an object of Nonetype -- no whois_result found.
    - The whois whois_result for the TLD doesn't include
        a creation time.
    - Whois linux program is not installed in the OS of the
        analysis server.
    - There were actual whois_results.
"""

import logging
from datetime import datetime

from saq.analysis import Analysis, Observable
from saq.constants import F_FQDN, F_URL
from saq.modules import AnalysisModule

KEY_AGE_CREATED_IN_DAYS = "age_created_in_days"
KEY_AGE_LAST_UPDATED_IN_DAYS = "age_last_updated_in_days"
KEY_DATETIME_CREATED = "datetime_created"
KEY_DATETIME_EXPIRATION = "datetime_expiration"
KEY_DATETIME_OF_ANALYSIS = "datetime_of_analysis"
KEY_DATETIME_OF_LAST_UPDATE = "datetime_of_last_update"
KEY_NAME_SERVERS = "nameservers"
KEY_REGISTRAR = "registrar"
KEY_DOMAIN_NAME = "domain_name"
KEY_WHOIS_TEXT = "whois_text"

NOT_IMPLEMENTED = "not_implemented"


class WhoisAnalysis(Analysis):
    """How long ago was the domain registered?"""

    def initialize_details(self):
        self.details = {
            KEY_AGE_CREATED_IN_DAYS: None,
            KEY_AGE_LAST_UPDATED_IN_DAYS: None,
            KEY_DATETIME_CREATED: None,
            KEY_DATETIME_OF_ANALYSIS: None,
            KEY_DATETIME_OF_LAST_UPDATE: None,
            KEY_NAME_SERVERS: None,
            KEY_REGISTRAR: None,
            KEY_DOMAIN_NAME: None,
            KEY_WHOIS_TEXT: None,
        }
        self.datetime_created_missing_or_invalid = False
        self.datetime_updated_missing_or_invalid = False
        self.py_whois_error = False
        self.whois_python_import_error = False

    @property
    def jinja_template_path(self):
        return "analysis/whois.html"

    # How many days ago the domain was registered.
    @property
    def age_created_in_days(self):
        return self.details[KEY_AGE_CREATED_IN_DAYS]

    @age_created_in_days.setter
    def age_created_in_days(self, value):
        self.details[KEY_AGE_CREATED_IN_DAYS] = value

    # How many days ago the domain was updated.
    @property
    def age_last_updated_in_days(self):
        return self.details[KEY_AGE_LAST_UPDATED_IN_DAYS]

    @age_last_updated_in_days.setter
    def age_last_updated_in_days(self, value):
        self.details[KEY_AGE_LAST_UPDATED_IN_DAYS] = value

    # The date/time the domain was registered.
    @property
    def datetime_created(self):
        return self.details[KEY_DATETIME_CREATED]

    @datetime_created.setter
    def datetime_created(self, value):
        self.details[KEY_DATETIME_CREATED] = value

    # The date/time the analysis was performed.
    @property
    def datetime_of_analysis(self):
        return self.details[KEY_DATETIME_OF_ANALYSIS]

    @datetime_of_analysis.setter
    def datetime_of_analysis(self, value):
        self.details[KEY_DATETIME_OF_ANALYSIS] = value

    # The date/time the domain was last updated.
    @property
    def datetime_of_last_update(self):
        return self.details[KEY_DATETIME_OF_LAST_UPDATE]

    @datetime_of_last_update.setter
    def datetime_of_last_update(self, value):
        self.details[KEY_DATETIME_OF_LAST_UPDATE] = value

    # The name servers associated with the domain
    @property
    def nameservers(self):
        return self.details[KEY_NAME_SERVERS]

    @nameservers.setter
    def nameservers(self, value):
        self.details[KEY_NAME_SERVERS] = value

    # The registrar for the domain.
    @property
    def registrar(self):
        return self.details[KEY_REGISTRAR]

    @registrar.setter
    def registrar(self, value):
        self.details[KEY_REGISTRAR] = value

    # The root zone name.
    @property
    def domain_name(self):
        return self.details[KEY_DOMAIN_NAME]

    @domain_name.setter
    def domain_name(self, value):
        self.details[KEY_DOMAIN_NAME] = value

    @property
    def whois_text(self):
        return self.details[KEY_WHOIS_TEXT]

    @whois_text.setter
    def whois_text(self, value):
        self.details[KEY_WHOIS_TEXT] = value

    def generate_summary(self):
        """Return analysis whois_result string for alert analysis page."""

        _prepend = "Whois Analysis"
        _created = "CREATED"
        _updated = "LAST UPDATED"
        message = None
        created = None
        updated = None

        # Conditions affecting both Created and Last Updated:
        if self.whois_python_import_error or self.py_whois_error:
            message = f"{_prepend} - error when using python whois module. See debug logs."

        # Conditions affecting one or both created/last updated datetimes.
        if self.datetime_created_missing_or_invalid:
            created = f"{_created}: missing or invalid whois response."

        if self.datetime_updated_missing_or_invalid:
            updated = f"{_updated}: missing or invalid whois response."

        # If no major issues, create the final message
        # Whois Analysis - MYDOMAIN.COM - CREATED: __ day(s) ago - LAST UPDATED: __ days(s) ago.
        if message is None:

            if created is None:
                created = f"{_created}: {self.age_created_in_days} day(s) ago."

            if updated is None:
                updated = f"{_updated}: {self.age_last_updated_in_days} day(s) ago."

            message = f"{_prepend} - {self.domain_name} - {created} - {updated}"

        return message


class WhoisAnalyzer(AnalysisModule):
    """AnalysisModule subclass for analyzing whois data about a domain."""

    @property
    def generated_analysis_type(self):
        return WhoisAnalysis

    @property
    def valid_observable_types(self):
        # python-whois module can pull domain from a URL and perform
        # whois query on it.
        return F_FQDN, F_URL

    def execute_analysis(self, _observable):
        """Executes analysis for Whois analysis of domains/zones."""

        analysis = self.create_analysis(_observable)
        # analysis.logs = self.json()

        _value = _observable.value

        logging.debug(f"Beginning whois analysis of {_value}")

        # Check to see if the whois python module is installed or not.
        try:
            import whois
            from whois.parser import PywhoisError
        except ModuleNotFoundError as _error:
            analysis.whois_python_import_error= True
            logging.debug(f"Error importing or using whois python module: {_error}")
            return True

        # Make the whois query.
        try:
            whois_result = whois.whois(_value)

        except PywhoisError as _error:
            analysis.py_whois_error = True
            logging.debug(f"Error when running pywhois module: {_error}")
            return True

        else:

            analysis.domain_name = whois_result.get("domain_name", [None])[0]
            analysis.registrar = whois_result.get("registrar", None)
            analysis.name_servers = whois_result.get("name_servers", [])

            # Get the full whois result
            analysis.whois_text = whois_result.text

            # creation date validation
            _creation_date = whois_result.get("creation_date", [None])[0]
            if not isinstance(_creation_date, datetime):
                analysis.datetime_created_missing_or_invalid = True
                logging.debug(f"Whois result contains unexpected creation date format/contents.")

            # last updated date validation
            _updated_date = whois_result.get("updated_date", [None])[0]
            if not isinstance(_updated_date, datetime):
                analysis.datetime_updated_missing_or_invalid = True
                logging.debug(f"Whois result contains unexpected updated date format/contents.")

            _now = datetime.now()

            analysis.datetime_of_analysis = _now.isoformat(' ')

            def age_in_days_as_string(past, present):
                _delta = present - past
                # Days are negative if past is actually after the
                # present. Probably an indication of time zone issues so
                # assume it's less than a day.
                if _delta.days < 0:
                    return "0"
                return str(_delta.days)

            if not analysis.datetime_created_missing_or_invalid:
                analysis.datetime_created = _creation_date.isoformat(' ')
                analysis.age_created_in_days = age_in_days_as_string(_creation_date, _now)

            if not analysis.datetime_updated_missing_or_invalid:
                analysis.datetime_of_last_update = _updated_date.isoformat(' ')
                analysis.age_last_updated_in_days = age_in_days_as_string(_updated_date, _now)

            return True
