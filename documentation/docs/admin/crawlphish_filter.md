# Crawlphish Filtering

The [crawlphish](link) analysis module has a custom filterting system designed to minimize the amount of URLs ACE automatically crawls, while also ensuring that suspect URL content is downloaded and analyzed.

The system consists of the following components

- A list of patterns of URLs that should be *whitelisted*.
- A list of patterns of URLs that should be *blacklisted*.
- Criteria to force download of certain types of URLs.
- A database of visited URLs.
- An intelligence indicator cache.

In this design we define *whitelisted* to mean URLs we want to analyze and *blacklisted* to mean URLs we do **not** want to analyze.

## Configuration

The location of the files that contain the filtering patterns is stored in the `[analysis_module_crawlphish]` section of the [configuration](../design/configuration.md). All file paths are relative to the [installation directory](../design/saq_home.md).

```ini
; path to whitelisted netloc
whitelist_path = etc/crawlphish.whitelist
; path to whitelisted path regexes
regex_path = etc/crawlphish.path_regex
; path to blacklisted netloc
blacklist_path = etc/crawlphish.blacklist
```

The `whitelist_path` file contains a list of domain names that should be *whitelisted*. Any URL that has a hostname that matches anything in this list will always be analyzed by ACE.

The `blacklist_path` file contains a list of domain names that should **never** be analyzed.

The `regex_path` file contains a list of python-compatible regular expressions. Each expression is applied to the full URL. A URL that matches any of these regular expressions will be analyzed by ACE.

ACE monitors these files for changes and automatically reloads them when they are modified.
