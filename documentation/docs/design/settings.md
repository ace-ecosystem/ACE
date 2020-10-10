# Settings
The settings modules allows you to get settings that are added an modified from the GUI.

## Exposing Settings
Before you can use a setting you must add it to the database. This is done via the sql schema/patch files.
Setting Types:
* Dictionary - collapsible list of settings
* String - setting that contains a string value
* Numeric - setting that contains a numeric value
* Boolean - setting that contains a boolean value

Examples:
```sql
/* store the id of the root dictionary in @root */;
SELECT id INTO @root FROM settings WHERE parent_id IS NULL AND `key`='root';

/* add a dictionary to the root dictionary and save the id of the new dictionary in @dict */;
INSERT INTO `settings` (`parent_id`, `key`, `type`) VALUES (@root, 'MyDictionary', 'Dictionary');
SET @dict = LAST_INSERT_ID();

/* add a numeric, boolean and string setting to the new dictionary */;
INSERT INTO `settings` (`parent_id`, `key`, `type`, `value`, `tooltip`) VALUES
    (@dict, 'MyNumber', 'Numeric', '123', 'GUI tooltip'),
    (@dict, 'MyBoolean', 'Boolean', 'True', 'GUI tooltip'),
    (@dict, 'MyString', 'String', 'Hello World!', 'GUI tooltip');

/* add a user appendable dictionary */;
INSERT INTO `settings` (`parent_id`, `key`, `type`, `value`, `tooltip`) VALUES
    (@dict, 'MyAppendableDictionary', 'Dictionary', NULL, 'GUI tooltip for child key');

/* create a default child for the new dictionary, this is used when appending to the dictionary in the GUI */;
SELECT id INTO @dict FROM settings WHERE parent_id=@root AND `key`='MyAppendableDictionary';
INSERT INTO `settings` (`default_parent_id`, `key`, `type`) VALUES (@dict, 'MyDefaultChild', 'Dictionary');

/* add fields to the default child object setting */;
SET @default_child = LAST_INSERT_ID();
INSERT INTO `settings` (`parent_id`, `key`, `type`, `value`, `tooltip`) VALUES
    (@default_child, 'MyBoolean', 'Boolean', 'True', 'GUI tooltip'),
    (@default_child, 'always_alert', 'Boolean', 'False', 'GUI tooltip');
```

## Usage
Analysis Modules and Collectors automatically loads settings before each run.
You can manually load settings with the following:
```python
import saq.settings
saq.settings.load()
```

Get the value of a setting.
Settings return values of the appropriate type (e.g. Numerics return float, Booleans return bool, Strings return str)
```python
import saq.settings
print(saq.settings.root['MyDirectory']['MyNumber'])
print(saq.settings.root['MyDirectory']['MyBoolean'])
print(saq.settings.root['MyDirectory']['MyString'])

> 123
> True
> Hello World!
```

Check if setting exists:
```python
import saq.settings
print('MyNumber' in saq.settings.root['MyDirectory'])

> True
```

Iterate settings:
```python
import saq.settings
for key in saq.settings.root['MyDirectory']:
    print(saq.settings.root['MyDirectory'][key])

> 123
> True
> Hello World!
```
