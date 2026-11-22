# swift-rfc-2104

Use this package to compute or check an HMAC, the keyed message authentication code of RFC 2104. Pick a hash with `IETF.RFC.`2104`.Hash` (SHA-1, SHA-256, SHA-384 or SHA-512 from FIPS 180-4, or one of your own), wrap it in `IETF.RFC.`2104`.HMAC`, and call `code(for:key:)` or `verify(_:for:key:)`.

## Laws

- Codes match the test cases of RFC 2202 for HMAC-SHA-1 and RFC 4231 for HMAC-SHA-256, -384 and -512.
- A key longer than the hash's block length is hashed first; a shorter key is padded with zero bytes. An empty key is allowed.
- `verify(_:for:key:)` accepts the full code or its leftmost bytes, as RFC 2104 section 5 allows, but never fewer than half the output length or 10 bytes. The comparison does not stop at the first difference.
- A custom `IETF.RFC.`2104`.Hash` must return exactly `outputLength` bytes for every input; its block length must be at least its output length.
