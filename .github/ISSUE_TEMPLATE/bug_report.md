---

name: Bug report
about: Create a report to help us improve Guard Core
title: '[BUG] '
labels: bug
assignees: ''
---

Bug Description
===============

A clear and concise description of what the bug is.

___

Steps To Reproduce
------------------

Steps to reproduce the behavior:

1. Configure Guard Core with '...'
2. Make request to endpoint '....'
3. See error

___

Expected Behavior
-----------------

A clear and concise description of what you expected to happen.

___

Actual Behavior
---------------

What actually happened, including error messages, stack traces, or logs.

___

Environment
-----------

- Guard Core version: [e.g. 4.0.2]
- Python version: [e.g. 3.11.10]
- FastAPI version: [e.g. 0.115.0]
- OS: [e.g. Ubuntu 22.04, Windows 11, MacOS 15.4]
- Other relevant dependencies:

___

Configuration
-------------

```python
from fastapi import FastAPI
from guard_core.middleware import SecurityMiddleware
from guard_core.models import SecurityConfig

app = FastAPI()

security_config = SecurityConfig(
)

app.add_middleware(SecurityMiddleware, config=security_config)
```

___

Additional Context
------------------

Add any other context about the problem here. For example:

- Is this happening in production or development?
- Does it happen consistently or intermittently?
- Have you tried any workarounds?
