# vim: ts=4:sw=4:et:cc=120
#

import logging

from saq.system import ACESystemInterface, get_system
from saq.system.analysis_tracking import (
    get_root_analysis,
    track_root_analysis,
)
from saq.system.analysis_request import (
        AnalysisRequest, 
        delete_analysis_request,
        get_analysis_request,
        get_analysis_request_by_observable,
        submit_analysis_request,
        track_analysis_request,
)
from saq.system.analysis_module import get_all_analysis_module_types
from saq.system.caching import cache_analysis_result, get_cached_analysis_result
from saq.system.exceptions import (
    UnknownAnalysisRequest,
    ExpiredAnalysisRequest,
    UnknownObservableError,
    UnknownRootAnalysisError,
)

def process_analysis_request(ar: AnalysisRequest):
    # need to lock this at the beginning so that nothing else modifies it
    # while we're processing it
    try:
        # TODO how long do we wait?
        with ar.lock(): # NOTE since AnalysisRequest.lock_id returns RootAnalysis.uuid this also locks the root obj
            target_root = None
            # did we complete a request?
            if ar.is_observable_analysis_result:
                existing_ar = get_analysis_request(ar.id)
                
                # is this analysis request gone?
                if not existing_ar:
                    raise UnknownAnalysisRequest(ar)

                # did the ownership change?
                if existing_ar.owner != ar.owner:
                    raise ExpiredAnalysisRequest(ar)

                # get the existing root analysis
                target_root = get_root_analysis(ar.root)
                if not target_root:
                    raise UnknownRootAnalysisError(ar)

                # should we cache these results?
                if ar.is_cachable:
                    cache_analysis_result(ar)

                # NOTE
                # when applying the diff merge it is super important to use the data from the analysis request
                # and *not* the current data

                # apply any modifications to the root
                target_root.apply_diff_merge(ar.root, ar.result.root)

                # and apply any modifications to the observable
                target_observable = target_root.get_observable(ar.observable)
                if not target_observable:
                    raise UnknownObservableError(observable)

                target_observable.apply_diff_merge(ar.observable, ar.result.observable)
                target_root.save() 

            elif ar.is_root_analysis_request:
                # are we updating an existing root analysis?
                target_root = get_root_analysis(ar.root)
                if target_root:
                    target_root.merge(ar.root)
                else:
                    # otherwise we just save the new one
                    target_root = ar.root

                target_root.save()

            # this should never fire
            if target_root is None:
                raise RuntimeError("target_root is None")

            # for each observable that needs to be analyzed
            for observable in ar.observables:
                for amt in get_all_analysis_module_types():
                    # does this analysis module accept this observable?
                    if not amt.accepts(observable):
                        continue

                    # is this analysis request already completed?
                    if target_root.analysis_completed(observable, amt):
                        continue

                    # is this analysis request for this RootAnalysis already being tracked?
                    if target_root.analysis_tracked(observable, amt):
                        continue

                    # is this observable being analyzed by another root analysis?
                    # NOTE if the analysis module does not support caching
                    # then get_analysis_request_by_observable always returns None
                    tracked_ar = get_analysis_request_by_observable(observable, amt)
                    if tracked_ar and tracked_ar != ar:
                        try:
                            with tracked_ar.lock():
                                if get_analysis_request(tracked_ar.id):
                                    # if we can get the AR and lock it it means it's still in a queue waiting
                                    # so we can tell that AR to update the details of this analysis as well when it's done
                                    tracked_ar.append_root(target_root)
                                    track_analysis_request(tracked_ar)
                                    # now this observable is tracked to the analysis request for the other observable
                                    observable.track_analysis_request(tracked_ar)
                                    continue

                            # the AR was completed before we could lock it
                            # oh well -- it could be in the cache

                        except Exception as e: # TODO what can be thrown here?
                            logging.fatal(f"unknown error: {e}")
                            continue

                    # is this analysis in the cache?
                    cached_result = get_cached_analysis_result(observable, amt)
                    if cached_result:
                        logging.debug(f"using cached result {cached_result} for {observable} type {amt} in {target_root}")
                        target_root.apply_diff_merge(cached_result.root, cached_result.result.root)
                        target_observable = target_root.get_observable(observable).apply_diff_merge(cached_result.observable, cached_result.result.observable)
                        target_root.save()
                        continue

                    # otherwise we need to request it
                    new_ar = observable.create_analysis_request(amt)
                    # (we also track the request inside the RootAnalysis object)
                    observable.track_analysis_request(new_ar)
                    track_analysis_request(new_ar)
                    target_root.save() 
                    submit_analysis_request(new_ar)
                    continue

    finally:
        # at this point this AnalysisRequest is no longer needed
        delete_analysis_request(ar)

    # if there were any other RootAnalysis objects waiting for this one, go ahead and process those now
    for root_uuid in ar.additional_roots:
        new_ar = ar.duplicate()
        new_ar.root = get_root_analysis(root_uuid)
        new_ar.additional_roots = []
        track_analysis_request(new_ar)
        process_analysis_request(new_ar)
