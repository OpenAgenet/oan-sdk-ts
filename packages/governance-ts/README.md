<!-- Copyright (c) 2026 OpenAgenet contributors -->
<!--
Initial author: JINLIANG XU
Email: jlxufly@gmail.com
-->

# governance-ts

TypeScript governance-facing helpers for OAN.

Current scope:

- trust-indexer read access
- governance-visible subject-state inspection
- subject-role to subject-type-code helpers

This package currently models chain-visible governance state only. It does not
collapse that state into Root-issued runtime authorization.
