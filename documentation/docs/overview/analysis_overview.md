# Analysis Overview

ACE analyzes [Observables](observable.md) which generates [Analysis](analysis.md) output which can in turn contain more [Observables](observable.md).

## Observable

An [Observable](observable.md) is an *observation* made during analysis. It has

- a type.
- a value.
- an optional time at which it was observed.

## Analysis

An [Analysis](analysis.md) is the output of analysis of an observable. It has

- zero or more observables.
- free form analysis data.

## Analysis Module

An [Analysis Module](analysis_module.md5) is what is responsible for taking an observable and generating analysis. Analysis modules are loaded and executed by [Engines](engine.md).
