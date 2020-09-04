# vim: ts=4:sw=4:et:cc=120
#

from saq.system import ACESystemInterface, get_system
from saq.system.analysis_request import (
        AnalysisRequest, 
        delete_analysis_request,
        find_analysis_request, 
)
from saq.system.analysis_module import get_all_analysis_module_types
from saq.system.caching import cache_analysis, get_cached_analysis

class AnalysisRequestError(Exception):
    pass

class UnknownAnalysisRequest(AnalysisRequestError):
    pass

class ExpiredAnalysisRequest(AnalysisRequestError):
    pass

class RootAnalysisMissing(AnalysisRequestError):
    pass

def process_analysis_request(ar: AnalysisRequest):
    # need to lock this at the beginning so that nothing else modifies it
    # while we're processing it
    try:
        with ar.lock():
            root = ar.root
            # did we complete a request?
            if ar.is_observable_analysis_result:
                existing_ar = get_analysis_request(ar.id)
                
                # is this analysis reqeust gone?
                if not existing_ar:
                    raise UnknownAnalysisRequest(ar)

                # did the ownership change?
                if existing_ar.owner != ar.owner:
                    raise ExpiredAnalysisRequest(ar)

                # if we don't already have the RootAnalysis then go get it
                if isinstance(root, str):
                    root = get_root_analysis(root)
                    # is it gone?
                    if not root:
                        raise RootAnalysisMissing(ar)

                # should we cache these results?
                if ar.is_cachable:
                    cache_analysis(ar.observable, 
                        ar.analysis_module_type, 
                        ar.result)

                # save the analysis results!
                root.set_analysis(
                        ar.observable, 
                        ar.analysis_module_type, 
                        ar.result)

            # for each observable that needs to be analyzed
            for observable in ar.observables:
                for analysis_module_type in get_all_analysis_module_types():
                    # does this analysis module accept this observable?
                    if not analysis_module_type.accepts(observable, root):
                        continue

                    # is this analysis request already completed?
                    if root.analysis_completed(observable, analysis_module_type):
                        continue

                    # is this request for this RootAnalysis already being tracked?
                    if root.analysis_tracked(observable, analysis_module_type):
                        continue

                    # is this observable being analyzed for another root analysis?
                    # this could be in another root analysis as well
                    # NOTE if the analysis module does not support caching
                    # then find_analysis_request always returns None
                    tracked_ar = find_analysis_request(observable, analysis_module_type)
                    if tracked_ar:
                        try:
                            with tracked_ar.lock():
                                if get_analysis_request(tracked_ar.tracking_key):
                                    # if we can get the AR and lock it it means it's still in a queue waiting
                                    # so we can tell that AR to update the details of this analysis as well when it's done
                                    tracked_ar.additional_roots.append(root)
                                    tracked_ar.update()
                                    # now this observable is tracked to the other observable
                                    root.track_analysis(observable, analysis_module_type, tracked_ar)
                                    continue

                            # the AR was completed before we could lock it
                            # oh well -- it could be in the cache

                        except: # TODO what can be thrown here?
                            pass

                        finally:
                            if tracked_ar:
                                tracked_ar.unlock()

                    # is this analysis in the cache?
                    cached_result = get_cached_analysis(observable, analysis_module_type)
                    if cached_result:
                        root.set_analysis(
                                ar.observable, 
                                ar.analysis_module_type, 
                                ar.result)
                        continue

                    # otherwise we need to request it
                    new_ar = AnalysisRequest(
                        observable,
                        analysis_module_type,
                        root)

                    # fill out any requested dependency data
                    for dep in analysis_module_type.dependencies:
                        new_ar[dep] = root.get_analysis(observable, dep)

                    # send it out
                    root.track_analysis(observable, analysis_module_type, new_ar)
                    submit_analysis_request(new_ar)
                    continue
        finally:
            # at this point this AnalysisRequest is no longer needed
            delete_analysis_request(ar)

    # if there were any other RootAnalysis objects waiting for this one, go ahead and process those now
    for other_root in ar.additional_roots:
        new_ar = ar.duplicate()
        new_ar.root = other_root
        new_ar.additional_roots = []
        process_analysis_request(new_ar)
