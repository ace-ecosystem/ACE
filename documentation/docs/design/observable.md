# Observables

An *observable* represents an observation made during the course of analysis. It always has a **type** and a **value**, and optionally has a time at which the observation was made. If the observable is missing the time then the time is assumed to be the time of the entire event that is being analyzed.

Observables are *always* children of [analysis](analysis.md) based objects.

Observables are analyzed by [analysis modules](analysis_module.md) which generate [analysis](analysis.md) as output. The newly created analysis can also contain more observables.

Observables are unique according to their type, value and time. If an observable with the same type, value and time as another existing observable is added, it references the existing observable instead of creating a new one.

Note that observables are unique by time. You can optionally [group them together by time](link) if you need to.

## Tagging

An observable can have zero or more [tags](tags.md). Tagging is used to tie some concept, idea or grouping property to the observables. Tagging can also be used to automatically add [detection points](detection_points.md).
