# Detection Points

A *detection point* represents something determined to be suspcious enough to warrent investigation. Only [observables](observable.md) and [analysis](analysis) objects can have detection points, and in practice observables are usually the best place to put them.

A [entire analysis](root_analysis.md) that has one or more detection points is considered by ACE to be an [alert](alerts.md) and thus has the [analysis mode](analysis_modes.md) changed to `correlation` during analysis.
