extension IETF.RFC.`2104` {

    /// HMAC over one hash function (RFC 2104, section 2):
    /// `H(K XOR opad, H(K XOR ipad, text))`.
    public struct HMAC: Sendable {

        /// The hash `H`.
        public let hash: Hash

        public init(_ hash: Hash) {
            self.hash = hash
        }
    }
}

extension IETF.RFC.`2104`.HMAC {

    /// The authentication code of `message` under `key`, `hash.outputLength` bytes long.
    ///
    /// A key longer than the block length is hashed first; a shorter one is padded with zeros (section 2).
    public func code(for message: [UInt8], key: [UInt8]) -> [UInt8] {
        let block = hash.blockLength
        var padded = key.count > block ? hash(key) : key
        padded += [UInt8](repeating: 0, count: block - padded.count)
        let inner = hash(padded.map { $0 ^ 0x36 } + message)
        return hash(padded.map { $0 ^ 0x5c } + inner)
    }

    /// Whether `code` is the authentication code of `message` under `key`, or its leftmost `code.count` bytes when
    /// `code` is truncated (section 5).
    ///
    /// The comparison takes the same time wherever the first difference is. A code shorter than half the output
    /// length, or shorter than 10 bytes, is refused, as section 5 recommends.
    public func verify(_ code: [UInt8], for message: [UInt8], key: [UInt8]) -> Bool {
        let expected = self.code(for: message, key: key)
        guard code.count <= expected.count,
            code.count >= max(expected.count / 2, 10)
        else { return false }
        var difference: UInt8 = 0
        for index in code.indices {
            difference |= code[index] ^ expected[index]
        }
        return difference == 0
    }
}
