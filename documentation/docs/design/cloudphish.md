# Cloudphish

ACE supports downloading and analyzing the content of a URL using the [crawlphish](../modules/crawlphish.md) analysis module. This capability can be leveraged as a detection tool by using the *cloudphish* system.

## Overview

API requests are made to ACE to analyze a given URL. The request is managed as a normal analysis request. Once the URL has been analyzed ACE caches the results. Any further requests for the same URL pattern returns the same results.

ACE can also generate [alerts](alerts.md) if a [detection point](detection_points.md) is identified during the analysis of URL content.

## API

ACE has API calls that are specific to cloudphish. See the [api documentation](../api/cloudphish.md) for details.
