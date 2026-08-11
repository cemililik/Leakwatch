# Synthetic appsettings fixture

`appsettings.synthetic.json` is a deterministic test fixture created from
scratch. Its values were not copied, sanitized, hashed, prefixed, suffixed, or
otherwise derived from a production or user credential.

The file intentionally contains credential-shaped strings so detector tests can
exercise realistic JSON structure, repeated-value location handling, entropy
boundaries, and hard-negative fields. Secret-scanning exclusions are scoped to
that exact JSON file; this README and any future fixture remain scanned unless
they receive their own reviewed exception.
