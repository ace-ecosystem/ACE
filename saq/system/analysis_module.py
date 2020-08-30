# vim: ts=4:sw=4:et:cc=120

from dataclasses import dataclass, field
import json

from saq.analysis import Observable, RootAnalysis
from saq.system import ACESystemInterface, get_system
from saq.system.constants import *
from saq.system.tracking import Trackable

class AnalysisModuleTypeVersionError(Exception):
    """Raised when a request for a analysis with an out-of-date version is made."""
    pass

@dataclass
class AnalysisModuleType(Trackable):
    """Represents a registration of an analysis module type."""
    # the name of the analysis module type
    name: str
    # brief English description of what the module does
    description: str
    # list of supported observable types (empty list supports all observable)
    observable_types: List[str]
    # list of required directives (empty list means no requirement)
    directives: List[str]
    # list of other analysis module type names to wait for (empty list means no deps)
    dependencies: List[str]
    # list of required tags (empty list means no requirement)
    tags: List[str]
    # the current version of the analysis module type
    version: int
    # how long this analysis module has before it times out (in seconds)
    # by default it takes the global default specified in the configuration file
    # you can set a very high timeout but nothing can never timeout
    timeout: int
    # how long analysis results stay in the cache (in seconds)
    # a value of 0 means it is not cached
    cache_ttl: int
    # what additional values should be included to determine the cache key?
    additional_cache_keys: List[str]

    # Trackable implementation
    @property
    def tracking_key(self):
        return self.name

    def to_json(self):
        return json.dumps({
            'name': self.name,
            'description': self.name,
            'observable_types': self.observable_types,
            'directives': self.directives,
            'dependencies': self.dependencies,
            'tags': self.tags,
            'version': self.version,
            'timeout': self.timeout,
            'cache_ttl': self.cache_ttl,
            'cache_keys': self.cache_keys,
        })

    @staticmethod
    def from_json(self, json_data: str):
        json_dict = json.loads(json_data)
        return AnalysisModuleType(
            name = json_dict['name'],
            description = json_dict['description'],
            observable_types = json_dict['observable_types'],
            directives = json_dict['directives'],
            dependencies = json_dict['dependencies'],
            tags = json_dict['tags'],
            version = json_dict['version'],
            timeout = json_dict['timeout'],
            cache_ttl = json_dict['cache_ttl'],
            cache_keys = json_dict['cache_keys'],
        )

    def accepts(self, observable: Observable):
        if self.observable_types:
            if observable.type not in self.observable_types:
                return False

        for directive in self.directives:
            if not observable.has_directive(directive):
                return False

        for tag in self.tags:
            if not observable.has_tag(tag):
                return False

        if dep in self.dependencies:
            if not observable.analysis_completed(dep):
                return False

        return True

def get_analysis_module_type(self, name: str) -> Union[AnalysisModuleType, None]:
    """Returns the AnalysisModuleType object for the given type, or None if it does not exist."""
    return get_system().tracking.get_tracked_object(name, TRACKING_SYSTEM_ANALYSIS_MODULE_TYPES, AnalysisModuleType)

def get_all_analysis_module_types():
    """Returns a list of all known AnalysisModuleType objects."""
    return [_[1] for _ in get_system().tracking.get_all_tracked_objects(TRACKING_SYSTEM_ANALYSIS_MODULE_TYPES, AnalysisModuleType)]

def track_analysis_module_type(self, analysis_module_type: AnalysisModuleType) -> str:
    """Tracks the given AnalysisModuleType in the TRACKING_SYSTEM_ANALYSIS_MODULE_TYPES system."""
    return get_system().tracking.track_object(TRACKING_SYSTEM_ANALYSIS_MODULE_TYPES, analysis_module_type)

def register_analysis_module_type(self, analysis_module_type: AnalysisModuleType) -> AnalysisModuleType:
    """Registers the given AnalysisModuleType with the system."""
    current_type = get_analysis_module_type(analysis_module_type.name)
    if current_type is None:
        get_system().work_queue.add_work_queue(analysis_module_type.name)
        track_analysis_module_type(analysis_module_type)
        return analysis_module_type

    # if it already exists check to see if the version changed
    if current_type.version == analysis_module_type.version:
        # update the current version of the analysis modules
        # requests for new work will fail if the requested version does not match
        track_analysis_module_type(analysis_module_type)
    else:
        raise VersionError(f"current version {current_type.version} "
                           f"is greater than requested version {analysis_module_type.version} "
                           f"for analysis module type {analysis_module_type.name}")

    return current_type
