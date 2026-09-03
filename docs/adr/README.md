# Decision records

Short records of the decisions that shaped the pipeline, in the order they were made. Each
one states the problem, what was decided, and what it cost. The module docstrings carry
the same reasoning next to the code; these exist so the history is readable in one place.

| # | decision |
|---|---|
| [0001](0001-duplicates-are-proven-not-read.md) | A duplicate is proven by rule, sensor, entities and time, never by text |
| [0002](0002-authorise-against-the-target-not-the-incident.md) | Authorisation is evaluated against the target entity's lineage, not the incident's |
| [0003](0003-root-causes-are-entities.md) | Root causes are ranked as entities, not alerts |
| [0004](0004-ubiquity-is-degree-and-frequency.md) | An entity is a hub only if it is both frequent and connected |
| [0005](0005-the-repeat-window-is-a-property-of-the-data.md) | The duplicate window is set from the data, and the public corpus is reported at 5 s |
