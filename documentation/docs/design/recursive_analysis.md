# Recursive Analysis

Analysis is performed on [observables](observable.md) by [analysis modules](analysis_module.md) generating an output called [analysis](analysis.md). The analysis output can contain zero or more [observables](observable.md). These new [observables](observable.md) are then analyzed in the same way.

This type of data is best represented as a tree showing the parent-child relationships between the data elements. The tree is **self-referencing**. If an [observable](observable.md) is added that already exists somewhere in the existing analysis tree, then the existing [observable](observable.md) is used instead of adding a new one.

