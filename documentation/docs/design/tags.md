# Tags

Tagging is a way to add additional information or context to analysis data.

Only [observables](observable.md) and [analysis](analysis.md) can be tagged, and in practice observables are usually what get tagged.

Tagging shows up in the GUI as labels of varying colors.

The value of a tag is any UTF8 encoded string.

## Relationships

A tag adds a relationships between alerts. ACE keeps track of what tags [alerts](alerts.md) contain. So quick correlational queries can be performed from the database.

## Tag Severity Levels

Tags can be assigned severity levels in the configuration settings under the `[tags]` section. By assigning tags severity levels you can control

- the color of the tag in the GUI.
- adding [detection points](detection_points.md) to what got tagged.

The format of the keys in the `[tags]` are as follows.

```ini
[tags]
tag_name = value
```

`tag_name` is the value of the tag to assign the severity to.

`value` is one of the following values.

- `hidden` - hides the tags in the [GUI](gui.md).
- `special` - displayed as a black-on-white tag.
- `fp` - green
- `info` - gray
- `warning` - yellow and adds a [detection point](detection_points.md)
- `alert` - red and adds a [detection point](detection_points.md)
- `critical` - dark red and adds a [detection point](detection_points.md)

The visual display (color) of the tags is controlled by `[tag_css_class]` section which associates a tag severity level to a CSS class to use to display the tag.
