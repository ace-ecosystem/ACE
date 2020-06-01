# Analysis Correlation Engine

![image](assets/images/analyst_on_ace.png)

ACE is a detection system and automation framework. The [analysis engine](design/engine.md) analyzes data and presents the output to analysts in a manner that attempts to reduce the time to [disposition](design/disposition.md) to as close to zero as possible. ACE adheres to a defined [design philosophy](design/index.md) in an attempt to achieve this goal.

ACE was designed to handle the ordinary, manual, redundant,
and repetitive tasks of collecting, combining, and relating data. A contextual and intuitive presentation of all the important data is used to allow for a quick high confidence determination.

![Recursive Analysis;
Presentation](assets/images/recursive-analysis-and-contextual-presentation.png)

Tools (some included in ACE) send [analysis requests](design/submissions.md) to ACE which then takes whatever is given and [recursively analyzes](design/recursive_analysis.md) the data. These requests may already be [alerts](design/alerts.md) that require additional correlation, or they may be something that could correlate into becoming an [alert](design/alerts.md).

ACE is the implementation of a proven detection strategy, a framework for automating analysis, a central platform to launch and manage incident response activates, an email scanner, and more.

Base functionality provides the following:

- [Email Scanning](design/email_scanning.md)
- [Recursive File Scanning](design/file_analysis.md)
- [URL Crawling and Content Caching](design/crawlphish.md)
- [Intuitive Alert Presentation](design/gui.md)
- [Recursive Data Analysis & Correlation](design/recursive_analysis.md)
- Central Analyst Interface
- Event/Incident management
- Intel Ingestion
- [Modular Design for extending automation](design/analysis_module.md)
