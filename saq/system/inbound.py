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

# XXX there is an issue with needing to also reload the RootAnalysis object
# XXX at this point it assumes analysis_request.root is a RootAnalysis object
def process_analysis_request(analysis_request: AnalysisRequest):
    with analysis_request.lock():
        # did we complete a request?
        if analysis_request.is_observable_analysis_result:
            # should we cache these results?
            if analysis_request.is_cachable:
                cache_analysis(analysis_request.observable, 
                    analysis_request.analysis_module_type, 
                    analysis_request.result)

            # save the analysis results!
            self.root.set_analysis(
                    analysis_request.observable, 
                    analysis_request.analysis_module_type, 
                    analysis_request.result)

        # for each observable that needs to be analyzed
        for observable in analysis_request.observables:
            for analysis_module_type in get_all_analysis_module_types():
                # does this analysis module accept this observable?
                if not analysis_module_type.accepts(observable):
                    continue

                # is this analysis request already completed?
                if analysis_request.root.analysis_completed(observable, analysis_module_type):
                    continue

                # is this request for this RootAnalysis already being tracked?
                if analysis_request.root.analysis_tracked(observable, analysis_module_type):
                    continue

                # is this observable being analyzed for another root analysis?
                # this could be in another root analysis as well
                tracked_ar = find_analysis_request(observable, analysis_module)
                if tracked_ar:
                    try:
                        with tracked_ar.lock():
                            if get_analysis_request(tracked_ar.tracking_key):
                                # if we can get the AR and lock it it means it's still in a queue waiting
                                # so we can tell that AR to update the details of this analysis as well when it's done
                                # TODO I AM HERE!
                                update_additional_root()??
                                #tracked_ar.append_root(analysis.root) # NOTE-A
                                get_system().tracking.set_analysis_tracking(analysis, tracked_ar)
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
                    self.root.set_analysis(
                            analysis_request.observable, 
                            analysis_request.analysis_module_type, 
                            analysis_request.result)
                    continue

                # otherwise we need to request it
                new_ar = AnalysisRequest(
                    observable,
                    analysis_module_type,
                    analysis_request.root)

                # fill out any requested dependency data
                for dep in analysis_module_type.dependencies:
                    new_ar[dep] = analysis_request.root.get_analysis(observable, dep)

                # send it out
                submit_analysis_request(new_ar)
                continue

        # at this point this AnalysisRequest is no longer needed
        delete_analysis_request(analysis_request)

    # if there were any other RootAnalysis objects waiting for this one, go ahead and process those now
    for root in analysis_request.additional_roots:
        new_ar = analysis_request.copy()
        new_ar.root = root
        process_analysis_request(new_ar)
