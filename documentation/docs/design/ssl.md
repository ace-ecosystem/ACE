# SSL

ACE has a number of uses for SSL.

- GUI encryption
- API encryption
- [database](../database/index.md#configuration) encryption

The `[SSL]` [configuration](configuration.md) section defines a `ca_chain_path` setting that points to a file relative to [SAQ_HOME](saq_home.md) that contains the chain of certificate authorities used to sign the certificates used by ACE.