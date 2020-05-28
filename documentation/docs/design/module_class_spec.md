# Module-Class Specification

ACE uses a design pattern called **module-class specification** in the configuration settings that allows you to specify a python class to load.

Typically there is a `module` and a `class` configuration option. The `module` option refers to the python module that contains the `class` to load.

How this is actually used depends on what is implementing it (such as how additional configuration options are passed to the class.) However, this pattern occurs enough to warrant documentation.
