"""Modules related to the analysis of Binaries."""

import os
import json
import datetime
import logging

import collections
import tabulate

import capa.main
import capa.rules
import capa.render
import capa.render.utils as rutils

import saq

from saq.analysis import Analysis, Observable
from saq.constants import *
from saq.error import report_exception
from saq.modules import AnalysisModule
from saq.util import abs_path

# XXX NOTE, look at a global pre-loaded Capa ruleset to exist in memory
# and only reload the ruleset if a difference/update is detected?

def custom_capa_file_limitations_check(rules, capabilities):
    """Return an identified limitation or None."""
    file_limitations = {
        # capa will likely detect installer specific functionality.
        # this is probably not what the user wants.
        "executable/installer": [
            " This sample appears to be an installer.",
            " ",
            " capa cannot handle installers well. This means the results may be misleading or incomplete."
            " You should try to understand the install mechanism and analyze created files with capa.",
        ],
        # capa won't detect much in .NET samples.
        # it might match some file-level things.
        # for consistency, bail on things that we don't support.
        "runtime/dotnet": [
            " This sample appears to be a .NET module.",
            " ",
            " .NET is a cross-platform framework for running managed applications.",
            " capa cannot handle non-native files. This means that the results may be misleading or incomplete.",
            " You may have to analyze the file manually, using a tool like the .NET decompiler dnSpy.",
        ],
        # capa will detect dozens of capabilities for AutoIt samples,
        # but these are due to the AutoIt runtime, not the payload script.
        # so, don't confuse the user with FP matches - bail instead
        "compiler/autoit": [
            " This sample appears to be compiled with AutoIt.",
            " ",
            " AutoIt is a freeware BASIC-like scripting language designed for automating the Windows GUI.",
            " capa cannot handle AutoIt scripts. This means that the results will be misleading or incomplete.",
            " You may have to analyze the file manually, using a tool like the AutoIt decompiler MyAut2Exe.",
        ],
        # capa won't detect much in packed samples
        "anti-analysis/packer/": [
            " This sample appears to be packed.",
            " ",
            " Packed samples have often been obfuscated to hide their logic.",
            " capa cannot handle obfuscation well. This means the results may be misleading or incomplete.",
            " If possible, you should try to unpack this input file before analyzing it with capa.",
        ],
    }
    for category, dialogue in file_limitations.items():
        if not capa.main.has_rule_with_namespace(rules, capabilities, category):
            continue
        return {"result": category,
                "message": '/n'.join(dialogue)}

    return None


def get_mbc_objectives(doc):
    """Return dict of MBC results."""
    objectives = collections.defaultdict(set)
    for rule in rutils.capability_rules(doc):
        if not rule["meta"].get("mbc"):
            continue

        mbcs = rule["meta"]["mbc"]
        if not isinstance(mbcs, list):
            raise ValueError("invalid rule: MBC mapping is not a list")

        for mbc in mbcs:
            objective, _, rest = mbc.partition("::")
            if "::" in rest:
                behavior, _, rest = rest.partition("::")
                method, _, id = rest.rpartition(" ")
                objectives[objective].add((behavior, method, id))
            else:
                behavior, _, id = rest.rpartition(" ")
                objectives[objective].add((behavior, id))
    return objectives


def get_mbc_id_dict(doc):
    """Return dict of MBC results with ID as key."""
    objectives = {}
    for rule in rutils.capability_rules(doc):
        if not rule["meta"].get("mbc"):
            continue

        mbcs = rule["meta"]["mbc"]
        if not isinstance(mbcs, list):
            raise ValueError("invalid rule: MBC mapping is not a list")

        for mbc in mbcs:
            objective, _, rest = mbc.partition("::")
            if "::" in rest:
                behavior, _, rest = rest.partition("::")
                method, _, id = rest.rpartition(" ")
                id = id.replace("[","").replace("]","")
                if id not in objectives:
                    objectives[id] = []
                objectives[id].append(mbc)
            else:
                behavior, _, id = rest.rpartition(" ")
                id = id.replace("[","").replace("]","")
                if id not in objectives:
                    objectives[id] = []
                objectives[id].append(mbc)

    return objectives


def custom_render_mbc_table(doc):
    """
    example::

        +--------------------------+------------------------------------------------------------+
        | MBC Objective            | MBC Behavior                                               |
        |--------------------------+------------------------------------------------------------|
        | ANTI-BEHAVIORAL ANALYSIS | Virtual Machine Detection::Instruction Testing [B0009.029] |
        | COLLECTION               | Keylogging::Polling [F0002.002]                            |
        | COMMUNICATION            | Interprocess Communication::Create Pipe [C0003.001]        |
        |                          | Interprocess Communication::Write Pipe [C0003.004]         |
        | IMPACT                   | Remote Access::Reverse Shell [B0022.001]                   |
        +--------------------------+------------------------------------------------------------+
    """

    objectives = get_mbc_objectives(doc)
    rows = []
    for objective, behaviors in sorted(objectives.items()):
        inner_rows = []
        for spec in sorted(behaviors):
            if len(spec) == 2:
                behavior, id = spec
                inner_rows.append("%s %s" % (behavior, id))
            elif len(spec) == 3:
                behavior, method, id = spec
                inner_rows.append("%s::%s %s" % (behavior, method, id))
            else:
                raise RuntimeError("unexpected MBC spec format")
        rows.append(
            (
                objective.upper(),
                "\n".join(inner_rows),
            )
        )

    if rows:
        return tabulate.tabulate(rows, headers=["MBC Objective", "MBC Behavior"], tablefmt="psql")


def custom_render_capabilities_table(doc):
    """
    example::

        +-------------------------------------------------------+-------------------------------------------------+
        | CAPABILITY                                            | NAMESPACE                                       |
        |-------------------------------------------------------+-------------------------------------------------|
        | check for OutputDebugString error (2 matches)         | anti-analysis/anti-debugging/debugger-detection |
        | read and send data from client to server              | c2/file-transfer                                |
        | ...                                                   | ...                                             |
        +-------------------------------------------------------+-------------------------------------------------+
    """
    from capa.render.default import find_subrule_matches
    subrule_matches = find_subrule_matches(doc)

    rows = []
    for rule in rutils.capability_rules(doc):
        if rule["meta"]["name"] in subrule_matches:
            # rules that are also matched by other rules should not get rendered by default.
            # this cuts down on the amount of output while giving approx the same detail.
            # see #224
            continue

        count = len(rule["matches"])
        if count == 1:
            capability = rule["meta"]["name"]
        else:
            capability = "%s (%d matches)" % (rule["meta"]["name"], count)
        rows.append((capability, rule["meta"]["namespace"]))

    if rows:
        return tabulate.tabulate(rows, headers=["CAPABILITY", "NAMESPACE"], tablefmt="psql")
    else:
        return "no capabilities found"


def custom_render_attack_table(doc):
    """
    example::

        +------------------------+----------------------------------------------------------------------+
        | ATT&CK Tactic          | ATT&CK Technique                                                     |
        |------------------------+----------------------------------------------------------------------|
        | DEFENSE EVASION        | Obfuscated Files or Information [T1027]                              |
        | DISCOVERY              | Query Registry [T1012]                                               |
        |                        | System Information Discovery [T1082]                                 |
        | EXECUTION              | Command and Scripting Interpreter::Windows Command Shell [T1059.003] |
        |                        | Shared Modules [T1129]                                               |
        | EXFILTRATION           | Exfiltration Over C2 Channel [T1041]                                 |
        | PERSISTENCE            | Create or Modify System Process::Windows Service [T1543.003]         |
        +------------------------+----------------------------------------------------------------------+
    """
    tactics = collections.defaultdict(set)
    for rule in rutils.capability_rules(doc):
        if not rule["meta"].get("att&ck"):
            continue

        for attack in rule["meta"]["att&ck"]:
            tactic, _, rest = attack.partition("::")
            if "::" in rest:
                technique, _, rest = rest.partition("::")
                subtechnique, _, id = rest.rpartition(" ")
                tactics[tactic].add((technique, subtechnique, id))
            else:
                technique, _, id = rest.rpartition(" ")
                tactics[tactic].add((technique, id))

    rows = []
    for tactic, techniques in sorted(tactics.items()):
        inner_rows = []
        for spec in sorted(techniques):
            if len(spec) == 2:
                technique, id = spec
                inner_rows.append("%s %s" % (technique, id))
            elif len(spec) == 3:
                technique, subtechnique, id = spec
                inner_rows.append("%s::%s %s" % (technique, subtechnique, id))
            else:
                raise RuntimeError("unexpected ATT&CK spec format")
        rows.append(
            (
                tactic.upper(),
                "\n".join(inner_rows),
            )
        )

    if rows:
        return tabulate.tabulate(rows, headers=["ATT&CK Tactic", "ATT&CK Technique"], tablefmt="psql")


class CapaAnalysis(Analysis):
    """What does capa say about this binaries capabilities?"""
    def initialize_details(self):
        self.details = {}

    #@property
    #def jinja_template_path(self):
    #    return "analysis/carbon_black.html"

    @property
    def jinja_template_path(self):
        return "analysis/generic_summary_tables.html"

    def generate_summary_tables(self):
        if not self.details:
            return None

        tables = {}
        tables["Malware Behavior Catalog"] = custom_render_mbc_table(self.details)
        tables["ATT&CK"] = custom_render_attack_table(self.details)
        tables["Capabilities"] = custom_render_capabilities_table(self.details)
        return tables

    def generate_summary(self):
        return 'CapaAnalysis: Windows Binary Capability Identification'

class CapaAnalyzer(AnalysisModule):
    def verify_environment(self):
        if not self.capa_rule_dir:
            raise ValueError(f"missing capa rules dir for {self}.")
        if not os.path.exists(self.capa_rule_dir):
            raise ValueError(f"{self.capa_rule_dir} does not exist for {self}.")
        return True

    @property
    def capa_rule_dir(self):
        rules_dir = self.config.get('capa_rule_dir')
        if not rules_dir:
            return None
        return abs_path(rules_dir)

    @property
    def behavior_blacklist(self):
        """A list of noisy behaviors not to use as detection points."""
        return self.config.get('behavior_blacklist', "").split(',')

    @property
    def behavior_combo_detection_map(self):
        """Yield any combination detection points."""
        combo_detection_map = {}
        for key,value in self.config.items():
            if not key.startswith('behavior_combo_detection_'):
                continue
            item = key.split('behavior_combo_detection_')[1].split('_')[0]
            if item not in combo_detection_map:
                combo_detection_map[item] = {}
            if key.endswith('_rule'):
                # comma sep list
                combo_detection_map[item]['rule'] = value
            if key.endswith('_text'):
                # detection point description
                combo_detection_map[item]['text'] = value

        # there must be a rule and txt
        for item_key,detection_map in combo_detection_map.copy().items():
            if 'text' not in detection_map or 'rule' not in detection_map:
                logging.warning(f"missing rule or text for capa detection combo item #{item_key}: {detection_map}")
                del combo_detection_map[item_key]

        return combo_detection_map

    @property
    def generated_analysis_type(self):
        return CapaAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def custom_requirement(self, observable):
        # TODO: Are there more mime types to check for?
        if observable.mime_type != 'application/x-dosexec':
            logging.debug(f"{self} only works on windows binary files.")
            return False

        # does this file even exist?
        local_path = os.path.join(self.root.storage_dir, observable.value)
        if not os.path.exists(local_path):
            logging.warning("{local_path} does not exist.")
            return False

        return True

    def execute_analysis(self, observable):
        # turn down logging noise
        logging.getLogger("capa").setLevel(logging.ERROR)
        capa.main.set_vivisect_log_level(logging.CRITICAL)

        file_path = os.path.join(self.root.storage_dir, observable.value)

        # get rules
        try:
            rules = capa.main.get_rules(self.capa_rule_dir, disable_progress=True)
            rules = capa.rules.RuleSet(rules)
        except Exception as e:
            logging.error(f"failed to load capa rules: {e}")
            return False

        # build extractor
        try:
            extractor = capa.main.get_extractor(file_path, "auto", capa.main.BACKEND_VIV, disable_progress=True)
        except capa.main.UnsupportedFormatError: # ValueError
            logging.warning(f"{observable} file does not appear to be a supported PE file type.")
            return False
        except Exception as e:
            logging.error(f"could not create capa extractor: {e}")
            return False

        # do it
        meta = capa.main.collect_metadata("ACE:CapaAnalyzer", file_path, self.capa_rule_dir, "auto", extractor)

        capabilities, counts = capa.main.find_capabilities(rules, extractor, disable_progress=True)
        meta["analysis"].update(counts)

        limitation = custom_capa_file_limitations_check(rules, capabilities)
        if limitation:
            observable.add_tag(limitation['result'])
            logging.info(f"{observable} has limitation: {limitation}")
            if "packer" in limitation['result']:
                observable.add_detection_point(f"capa detected packed binary")
            # other than a packer, do not alert on any further results as this limitation
            # means the capability information shouldn't be considered.

        analysis = self.create_analysis(observable)
        # XXX redundant but filters through their json decoder
        analysis.details = json.loads(capa.render.render_json(meta, rules, capabilities))

        mbc_analysis = get_mbc_id_dict(analysis.details)
        if mbc_analysis:
            for key, values in mbc_analysis.items():
                if key.startswith("B"):
                    observable.add_tag(key)
                    if key in self.behavior_blacklist:
                        continue
                    for detection in values:
                        observable.add_detection_point(f"MBC Behavior: {detection}")

            for key,detection_map in self.behavior_combo_detection_map.items():
                behaviors = detection_map['rule'].split(',')
                if all(b in mbc_analysis.keys() for b in behaviors):
                    observable.add_detection_point(detection_map['text'])

        return True