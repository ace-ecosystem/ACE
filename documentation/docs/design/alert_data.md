# Alert Data Structure

[Alert](alerts.md) data is stored in the [storage defined for alerts](alert_storage.md) and is composed of three types of data.

1. The main [alert](alerts.md) data.
2. [Analysis](analysis.md) data.
3. File observable data.

## Alert Data JSON

Both [Alerts](alerts.md) and [root analysis](root_analysis.md) objects are stored as JSON formatted files named `data.json` inside the [storage directory](alert_storage.md) of the object.

This JSON contains everything associated to the alert or root analysis except for analysis data and file observable data. The JSON contains references to the locations of these other types of data.

This is done because analysis data can become very large. This allows ACE to load a [root analysis](root_analysis.md)-based object without having to load all the individual analysis JSON data.

## Analysis Data JSON

[Analysis](analysis.md) data is stored in individual files inside of a hidden `.ace` subdirectory inside of the storage directory of the [root analysis](root_analysis.md)-based object.

This analysis data is only loaded when it is requested.

## File Observable Data

File observables represent file data. File data is stored in the storage directory of the [root analysis](root_analysis.md)-based object. The exact location of the data is stored as the value of the observable.
