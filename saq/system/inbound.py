# vim: ts=4:sw=4:et:cc=120
#

from saq.analysis import RootAnalysis, Analysis, Observable
from saq.system import ACESystemInterface, get_system

class InboundRequestInterface(ACESystemInterface):
    def process_analysis_request(self, analysis_request: AnalysisRequest):
        with analysis_request.lock():
            target_observables = analysis.observables[:] # analyze all the observables it created
            target_observables.append(analysis.observable) # and the observable that was analyzed
            for observable in target_observables:
                for analysis_module in get_system().tracking.get_analysis_modules():
                    # is this analysis request already completed?
                    if analysis.root.analysis_completed(observable, analysis_module):
                        continue

                    # is this analysis request already tracked?
                    if analysis.root.analysis_tracked(observable, analysis_module):
                        continue

                    # does this analysis module accept this observable?
                    if not analysis_module.accept(observable):
                        continue

                    # is this observable being analyzed in another analysis?
                    # this could be in another root analysis as well
                    tracked_ar = get_system().tracking.get_analysis_request(get_cache_id(observable, analysis_module))
                    if tracked_ar:
                        try:
                            tracked_ar.lock()
                            tracked_ar = get_system().tracking.get_analysis_request(get_cache_id(observable, analysis_module))
                            if tracked_ar is not None: 
                                # if we can get the AR and lock it it means it's still in a queue waiting
                                # so we can tell that AR to update the details of this analysis as well when it's done
                                tracked_ar.append_root(analysis.root) # NOTE-A
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
                    cached_result = get_system().cache.get_cached_result(observable, analysis_module)
                    if cached_result:
                        get_system().tracking.set_analysis_result(root, observable, analysis_module, cached_result)
                        continue

                    new_ar = get_system().tracking.create_analysis_request(observable, analysis_module, analysis.root)
                    get_system().work_queue.submit(new_ar)
                    continue
