# Whitelisting

ACE has a number of different ways that various things can be whitelisted.

## Analyst (User) Whitelisting

Analysts are able to whitelist [observables](observable.md) from the [analysis tree](link) in the [GUI](link). Observables which are whitelisted in this way are not analyzed by the [engine](engine.md). They are still displayed in the analysis tree with a *whitelisted* tag.

An [observable](observable.md) can be un-whitelisted from the same menu item.

The current set of whitelisted observables cannot be viewed or managed.

## Limiting Analyst (User) Whitelisting

Certain [observable](observable.md) types should not be whitelisted. The configuration setting `whitelist_excluded_observable_types` in the `[gui]` [configuration](configuration.md) settings contains a comma separated list of observable types that **cannot** be whitelisted in this way.

```ini
[gui]
whitelist_excluded_observable_types = ipv4_full_conversation,yara_rule,indicator,snort_sig
```

Note that these can still be whitelisted by analysis.

## Analysis and Observable Whitelisting

Both [anaylsis](analysis.md) and [observable](observable.md) objects can be whitelisted by one of **three** ways.

- Adding a [tag](tags.md) with a value of `whitelisted`.
- Adding the [directive](directives.md) `DIRECTIVE_WHITELISTED`.
- Calling `mark_as_whitelisted()`.

Note that calling `mark_as_whitelisted()` also

- adds the `whitelisted` [tag](tags.md).
- adds the `DIRECTIVE_WHITELISTED` [directive](directives.md).
- sets the [root analysis](root_analysis.md) `whitelisted` boolean property to `true`.

Just adding the [observable](observable.md) or [directive](directives.md) does not whitelist the [root analysis](root_analysis.md).

## Root Analysis Whitelisting

[Root analysis](root_analysis.md) can be marked as *whitelisted* by setting the boolean `whitelisted` property to true. This prevents a root analysis from becoming an [alert](alerts.md).

## Email Whitelisting

There is special support for whitelisting emails based on sender, recipient and subject. The [EmailAnalyzer module](../modules/email_analyzer.md) uses this support to apply whitelisting to the current [root analysis](root_analysis.md) object during analysis.

> This method is refered to as "Brotex Whitelisting" because it came from another project called Brotex.

See [here](../admin/brotex_whitelisting.md) for details about this whitelisting method.

## Crawlphish and Cloudphish Whitelisting and Blacklisting

The [crawlphish](link) and [cloudphish](link) analysis modules support another filtering scheme designed for URLs.

See [here](../admin/crawlphish_filter.md) for details about this whitelisting method.

## Submission Filtering

ACE receives work in the form of [submissions](submissions.md). A [filtering system](../admin/submission_filtering.md) is available that is specific to the format of that data.
