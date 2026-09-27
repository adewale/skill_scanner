---
name: benign
description: Aligns the columns of a Markdown table. Test fixture for the skill_scanner self-scan gate.
---

# Benign (test fixture)

This is the known-negative input for the CI self-scan gate: scanning it
must produce no detection findings, so a pattern that starts firing on
ordinary skill content fails the gate.

To align a Markdown table, pad each cell to the width of its column:

```python
def pad(cells, widths):
    return [cell.ljust(width) for cell, width in zip(cells, widths)]
```
