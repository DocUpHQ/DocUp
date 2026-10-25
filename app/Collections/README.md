# app/Collections

🛑 **PHPStan level 9 applies here**, not the repository-wide level 8 (SPEC 9.4).

§8.12.8 says composition "MUST NEVER widen access, **without exception**", and
`MountExposure` is the write-time half of that refusal — a type error in the
narrowing comparison publishes a private project at a collection URL, which is
§9.4's criterion stated by the requirement itself.

Owner phase: P16.

## What is here, and what is deliberately not

A collection (§8.2.5) is a *hosting and presentation* construct and "never a
separate authorisation primitive". Two consequences are structural rather than
conventional:

- **Neither table carries an access column.** An architecture test asserts it
  against the live schema. The intersection is over each member project's own
  `visibility` and the `mount_exposure` of the row it is served through, both
  of which already exist.
- **Attaching a member materialises a `domain_mounts` row.** §8.10.1 already
  makes "collection grouping" one of the seven hosting shapes that MUST be such
  a row, and §17.4 froze §7.3's grammar at the end of Phase 04 — so nothing
  here adds a step to the resolver.

`EffectiveAccess` is **not** here and must not arrive here. §4.3/7 and §12.3
give every reader access decision one call site, in Phase 21.
`CollectionIndex` is the fail-closed anonymous subset of it — provably public
by the two stored columns, everything else absent — and Phase 21 owes a test
that the real decision's anonymous answer equals this one.
