# ACE Command Tooling

ACE uses a single command to manage the entire system: the `ace` command, which sits in the [installation directory](saq_home.md) of ACE.

The command uses the sub-command pattern. The format of most commands is

```bash
ace [options] sub-command [options]
```

Every command supports the `--help` option.