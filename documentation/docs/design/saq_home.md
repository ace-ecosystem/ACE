# SAQ_HOME

SAQ_HOME refers to the installation directory of ACE. Typically this is `/opt/ace` but any directory can be used.

ACE determines SAQ_HOME by

- loading it from the environment variable SAQ_HOME.
- obtaining it from a command line option.
- defaulting directory that contains the `ace` command.

This value must be an absolute path.

Most functionality makes relative directory paths absolute by prefixing them with SAQ_HOME.