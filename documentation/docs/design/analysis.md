# Analysis

An *analysis* is the output of the analysis of an [observable](observable.md). It consists of

- zero or more observables.
- a free form JSON formatted analysis output.

The relationship between analysis and observable is always parent-child.

## Analysis Details

The *details* of the analysis are stored as a free-form JSON-compatible blob of data. This can be any value. The interpretation of this value is up to the python classes that implement the [analysis modules](analysis_module.md) and analysis objects.

These details are stored separately from the JSON of the main [root analysis](root_analysis.md) object. They are loaded as needed. A brief summary of the details are stored instead.

## Instances

An analysis has an *instance* that matches the *instance* of the [analysis module](analysis_module.md) that created it. See [instanced analysis modules](analysis_module.md#instanced-analysis-modules).

