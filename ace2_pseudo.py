# ACE2 pseudo code
# 8/26/2020

class AnalysisResult:
    request: AnalysisRequest # the original request
    observable: Observable # the observable that was analyzed
    analysis_module: AnalysisModule # the analysis module that executed
    result: Analysis # the result of the analysis
    root: RootAnalysis # the RootAnalysis object this belongs to

class AnalysisRequest:
    observable: Observable # the observable to be analyzed
    analysis_module: AnalysisModule # the analysis module to execute
    dep_analysis_requests: List[AnalysisRequest] # other AnalysisRequests that are waiting for this one
    roots: List[RootAnalysis] # the list of RootAnalysis objects that want the result to this

def get_analysis_modules():
    # so if A depends on B then the order is [B, A]
    return analysis_modules_sorted_by_dependencies

def process_analysis_result(ar: AnalysisResult):
    with ar.lock():
        # see NOTE-A below
        for root in ar.request.roots:
            with root.lock():
                root.set_analysis_result(ar.observable, ar.analysis_module, ar.result)

        # see NOTE-B below
        # was anything depending on this request?
        for dep_analysis_request in ar.request.dep_analysis_requests:
            dep_analysis_request.set_dependency_result(ar.analysis_module, ar.result)
            # is this request finally ready?
            if dep_analysis_request.all_dependencies_resolved()
                # submit it to the analysis module queue
                dep_analysis_request.submit()

    process_analysis(ar.result)

def process_analysis_request(ar: AnalysisRequest):
    pass

def process_analysis(analysis: Analysis):
    with analysis.lock():
        for observable in analysis.observables:
            for analysis_module in get_analysis_modules():
                # is this analysis already completed?
                if analysis.root.analysis_completed(observable, analysis_module):
                    continue

                # does this analysis module accept this observable?
                if not analysis_module.accept(observable):
                    continue

                # is this observable being analyzed in another analysis?
                # this could be in another root analysis as well
                tracked_ar = get_tracked_ar(observable, analysis_module)
                if tracked_ar:
                    try:
                        tracked_ar.lock()
                        # if we can get the AR and lock it it means it's still in a queue waiting
                        # so we can tell that AR to update the details of this analysis as well when it's done
                        tracked_ar.append_root(analysis.root) # NOTE-A
                    except AnalysisRequestDoesNotExistException:
                        # the AR was completed before we could lock it
                        # oh well -- it could be in the cache
                        pass
                    finally:
                        if tracked_ar:
                            tracked_ar.unlock()

                # is this analysis in the cache?
                cached_result = get_cached_result(observable, analysis_module)
                if cached_result:
                    analysis.root.set_analysis_result(observable, analysis_module, cached_result)
                    continue

                # at this point we know we need to request analysis
                # so we'll go ahead and set up that request
                analysis_request = AnalysisRequest(observable, analysis_module, analysis.root)

                for dep in analysis_module.dependencies:
                    # has the analysis for this dependency completed yet?
                    if analysis.root.analysis_completed(observable, dep.analysis_module):
                        # record the details of the dependency analysis into the request
                        new_ar.set_dependency_result(dep.analysis_module, analysis.root.get_analysis(observable, dep.analysis_module))
                        continue
                    else:
                        # get the tracked AR that satisfies the dependency
                        tracked_ar = get_tracked_ar(observable, dep.analysis_module, analysis.root)
                        if tracked_ar:
                            try:
                                tracked_ar.lock()
                                # if we can get the AR and lock it it means it's still in a queue waiting
                                # so we tell that AR to process our new AR when it's done
                                tracked_ar.append_ar(new_ar) # NOTE-B
                                new_ar.set_dependency_waiting(dep.analysis_module)
                                continue
                            except AnalysisRequestDoesNotExistException:
                                # the AR was completed before we could lock it
                                pass
                            finally:
                                if tracked_ar:
                                    tracked_ar.unlock()

                        # if we get here then we can expect to get the analysis result
                        if analysis.root.analysis_completed(observable, dep.analysis_module):
                            # record the details of the dependency analysis into the request
                            new_ar.set_dependency_result(dep.analysis_module, analysis.root.get_analysis(observable, dep.analysis_module))
                            continue
                        else:
                            # something went wrong
                            new_ar.set_dependency_lost(dep.analysis_module)

                # are there any outstanding dependencies?
                if not new_ar.all_dependencies_resolved():
                    # at this point our new_ar is attached to one or more tracked_ars
                    # so when those complete that will kick off process_ar(new_ar)
                    # so we move on to the next analysis module
                    continue

                # there is nothing yet so we need to submit this AnalysisRequest
                # this sends the AnalysisRequest(observable, analysis_module, root, dependency analysis)
                # to the queue for analysis_module
                new_ar.submit()
                continue


# NOTES

# DEADLOCK DETECTION AND HANDLING
# ar.lock() is held
# asking for tracked_ar.lock()
# something else has tracked_ar already locked
# that something else has a lock chain of [ tracked_ar ] and waiting for ar
# so tracked_ar.lock() fires a DEADLOCK which kicks you out of the whole process_ar() function
# releasing all the locks and then reprocesses the request
# this is going to require some transactional stuff maybe

# OBSERVABLE STORAGE
# use the CACHE_KEY to reference observables inside of the RootAnalysis instead of a random uuid
