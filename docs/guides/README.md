# Leakwatch Supplemental Guides

> **Document Version:** 1.0
> **Date:** 2026-08-11
> **Status:** Approved

---

The English pages under [`docs/user-manuals/en`](../user-manuals/en/) are the
authoritative source for current Leakwatch product behavior. Their Turkish
counterparts under [`docs/user-manuals/tr`](../user-manuals/tr/) are reviewed
translations, and `tools/site-build` compiles both trees into the generated
`site/js/manuals/*.js` bundles.

Files in this directory are supplemental deep dives. They may provide longer
operational examples, implementation rationale, or contributor-oriented detail,
but they do not own CLI flags, defaults, exit codes, detector/verifier capability
claims, or other product contracts. Each guide links to the relevant canonical
manual page; when behavior changes, update EN, TR, the supplemental guide where
useful, and the generated site output in the same commit.

Do not edit `site/js/manuals/*.js` by hand. Regenerate and validate them with:

```bash
cd tools/site-build
go run . -strict
```
