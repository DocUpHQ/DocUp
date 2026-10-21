# app/Serving

🛑 **PHPStan level 9 applies here**, not the repository-wide level 8 (SPEC 9.4).

This is one of the four namespaces where a type error is a security bug rather
than a crash: request resolution, authorisation, artifact handling and
configuration parsing. `phpstan-strict.neon` raises the level for these paths
specifically, and the directory exists from Phase 01 so the higher bar applies
the moment the first file lands here instead of being remembered later.

Owner phases: Serving → P04, Auth → P21, Artifacts → P03, Config → P09.
