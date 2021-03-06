# Email Logging Analyzer

This modules takes the analysis generated by the [Email Analyzer](email_analyzer.md) and generates logging suitable for various log consumption tools.

It currently supports splunk and elastic search.

This module also updates the `smtplog` table of the [brocess](../design/brocess.md) [database table](../database/brocess.md).

## Configuration

```ini
[analysis_module_email_logger]
module = saq.modules.email
class = EmailLoggingAnalyzer
enabled = yes

; set this to yes to enable log formatted for splunk
splunk_log_enabled = yes

; the subdirectory inside of splunk_log_dir (see [splunk_logging]) that contains the logs
splunk_log_subdir = smtp
; set this to yes to update the smtplog table of the brocess database
update_brocess = yes

; elasticsearch JSON logging
json_log_enabled = yes

; relative file path of the generated JSON logs
; the file name is passed through strftime
; https://docs.python.org/3/library/datetime.html#strftime-strptime-behavior
; {pid} is replaced with the process ID of the current executing process
; so that we don't have multiple processes writing to the same file
json_log_path_format = email/email-{pid}-%%Y%%m%%d.json
```