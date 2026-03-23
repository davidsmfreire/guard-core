---

title: Release Notes - Guard Core
description: Release notes for Guard Core, detailing new features, improvements, and bug fixes
keywords: release notes, guard-core, security library, api security
---

Release Notes
=============

___

v0.1.0 (2026-03-23)
-------------------

New Features (v0.1.0)
------------

- **Initial release**: Guard Core extracted as a framework-agnostic security library for Python web applications.
- **Protocol-based architecture**: Uses `GuardRequest` and `GuardResponse` protocols for framework independence.
- **Full feature parity**: All security features available through framework-agnostic APIs.
- **IP Management**: Whitelisting, blacklisting, geolocation, cloud provider blocking.
- **Rate Limiting**: Sliding window algorithm with in-memory and Redis backends.
- **Penetration Detection**: Enhanced detection engine with pattern matching, semantic analysis, and performance monitoring.
- **Security Decorators**: Route-level security controls for access control, authentication, rate limiting, behavioral analysis, content filtering, and advanced features.
- **Security Headers**: Comprehensive HTTP security header management following OWASP best practices.
- **Redis Integration**: Distributed state management for multi-instance deployments.
- **Behavioral Analysis**: Usage monitoring, return pattern detection, and frequency analysis.
