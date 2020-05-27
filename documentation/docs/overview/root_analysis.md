# Root Analysis

The *root analysis* object is the root of all analysis and thus the root of all parent-child relationships. A root analysis is an [analysis](analysis.md) object. Thus is can contain zero or more [observables](obserable.md) and zero or more [tags](tags.md).

During analysis by an [engine](engine.md) the root analysis is always available by reference to the [analysis modules](analysis_module.md).

A root analysis can automically become an [alert](alerts.md) if one or more [detection points](detection_points.md) are added during the course of analysis.

An [alert](alert.md) is also considered a root analysis object.
