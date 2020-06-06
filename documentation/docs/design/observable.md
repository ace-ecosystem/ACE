# Observables

An *observable* represents an observation made during the course of analysis. It always has a **type** and a **value**, and optionally has a time at which the observation was made. If the observable is missing the time then the time is assumed to be the time of the entire event that is being analyzed.

Observables are *always* children of [analysis](analysis.md) based objects.

Observables are analyzed by [analysis modules](analysis_module.md) which generate [analysis](analysis.md) as output. The newly created analysis can also contain more observables.

Observables are unique according to their type, value and time. If an observable with the same type, value and time as another existing observable is added, it references the existing observable instead of creating a new one.

Note that observables are unique by time. You can optionally [group them together by time](link) if you need to.

## Tagging

An observable can have zero or more [tags](tags.md). Tagging is used to tie some concept, idea or grouping property to the observables. Tagging can also be used to automatically add [detection points](detection_points.md).

## Directives

An observable can have zero or more [directives](directives.md). Directives are used to give [analysis modules](analysis_module.md) some additional instructions on how to handle the observable.

## Redirection

An observable can include a *redirection* which points to another observable. Redirections are often used when extracting artifacts from files. They give ACE the ability to say "This file actually came from this other file."

A common example usage of this feature is determining which file to send to a sandboxing system. If a file was generated as part of an analysis, redirection can be used to point to the original file, giving the sandbox [analysis module](analysis_module.md) the correct file to analyze.

By default redirection points to itself.

## Linking

An observable can be *linked to* another observable. Any tags applied to the original observable are also applied to the linked observable.

## Limited Analysis

An observable can **limit** what [analysis modules](analysis_module.md) are executed against it by specifying one or more analysis modules as the *limited analysis* for the observable. Only modules in the list will be executed against it, and only if the module accepts it.

## Excluded Analysis

An observable can **restrict** what [analysis modules](analysis_module.md) are executed against it by specifying one or more analysis modules that will be *excluded* from analysis. These modules will **not** execute against the observable regardless of any other condition.

## Relationships

An observable can have a *relationship* to another observable. This has meaning only to [analysis modules](analysis_module.md) that work with relationships.

A current list of valid relationships can be found in `saq/constants.py` in the `# relationships` section.

## Grouping by Time

Observables can be grouped together for analysis purposes by time. This allows multiple observations over some time period to be treated as a single observation. For example, if the same IP address was observed 50 times over 5 seconds, they can be grouped into a single observation over that 5 second time period.

This works in conjunction with the `observation_grouping_time_range` configuration option of [analysis modules](analysis_modules#observation_grouping).

## Analysis

An observable can have zero or more [analysis](analysis.md) objects attached to it. These represent the analysis performed by [analysis modules](analysis_module.md).
