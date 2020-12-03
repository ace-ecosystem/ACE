# vim: ts=4:sw=4:et:cc=120

import json
import logging

from dataclasses import dataclass, field
from typing import List, Union, Optional

from saq.analysis import Observable, RootAnalysis, AnalysisModuleType
from saq.system import ACESystemInterface, get_system

class UnknownAnalysisModuleTypeError(Exception):
    """Raised when a request is made for an unknown (unregistered analysis module type.)"""
    def __init__(self, amt: Union[AnalysisModuleType, str]):
        super().__init__(f"unknown AnalysisModuleType {amt}")

class CircularDependencyError(Exception):
    """Raised when there is an attempt to register a type that would cause a circular dependency."""
    def __init__(self, chain: List[AnalysisModuleType]):
        super().__init__("circular dependency error: {}".format(' -> '.join([_.name for _ in chain])))

class AnalysisModuleTypeVersionError(Exception):
    """Raised when a request for a analysis with an out-of-date version is made."""
    pass

class AnalysisModuleTrackingInterface(ACESystemInterface):
    def track_analysis_module_type(self, amt: AnalysisModuleType):
        raise NotImplementedError()

    def get_analysis_module_type(self, name: str) -> Union[AnalysisModuleType, None]:
        raise NotImplementedError()

    def get_all_analysis_module_types(self) -> List[AnalysisModuleType]:
        raise NotImplementedError()

    def get_dependencies(self, amt: AnalysisModuleType) -> List[AnalysisModuleType]:
        """Returns a list of analysis modules that depend on the given analysis module."""
        raise NotImplementedError()

def _circ_dep_check(source_amt: AnalysisModuleType, target_amt: Optional[AnalysisModuleType]=None, chain: list[AnalysisModuleType] = []):
    chain = chain[:]

    if target_amt is None:
        target_amt = source_amt

    chain.append(target_amt)

    for dep in target_amt.dependencies:
        if source_amt.name == dep:
            raise CircularDependencyError(chain)

        _circ_dep_check(source_amt, get_analysis_module_type(dep), chain)

def register_analysis_module_type(amt: AnalysisModuleType) -> AnalysisModuleType:
    """Registers the given AnalysisModuleType with the system."""

    # make sure all the dependencies exist
    for dep in amt.dependencies:
        if get_analysis_module_type(dep) is None:
            logging.error(f"registration for {amt} failed: dependency on unknown type {dep}")
            raise UnknownAnalysisModuleTypeError(amt)

    # make sure there are no circular (or self) dependencies
    _circ_dep_check(amt)

    current_type = get_analysis_module_type(amt.name)
    if current_type is None:
        get_system().work_queue.add_work_queue(amt.name)

    # regardless we take this to be the new registration for this analysis module
    # any updates to version or cache keys would be saved here
    track_analysis_module_type(amt)
    return amt

def track_analysis_module_type(amt: AnalysisModuleType):
    assert isinstance(amt, AnalysisModuleType)
    return get_system().module_tracking.track_analysis_module_type(amt)

def get_analysis_module_type(name: str) -> Union[AnalysisModuleType, None]:
    assert isinstance(name, str)
    return get_system().module_tracking.get_analysis_module_type(name)

def get_all_analysis_module_types() -> List[AnalysisModuleType]:
    return get_system().module_tracking.get_all_analysis_module_types()

def get_dependencies(self, amt: AnalysisModuleType) -> List[AnalysisModuleType]:
    assert isinstance(amt, AnalysisModuleType)
    return get_system().module_tracking.get_dependencies(amt)
