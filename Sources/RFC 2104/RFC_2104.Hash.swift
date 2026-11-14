extension RFC_2104 {

    /// The iterated hash function `H` that HMAC is built on (RFC 2104, section 2): its input block length `B` and
    /// output length `L` in bytes, and the function itself.
    public struct Hash: Sendable {

        /// `B`: the byte length of one input block.
        public let blockLength: Int

        /// `L`: the byte length of one output.
        public let outputLength: Int

        @usableFromInline
        let function: @Sendable ([UInt8]) -> [UInt8]

        /// A hash with block length `B` and output length `L`; `function` must always return `outputLength` bytes.
        public init(
            blockLength: Int,
            outputLength: Int,
            _ function: @escaping @Sendable ([UInt8]) -> [UInt8]
        ) {
            precondition(blockLength > 0 && outputLength > 0 && outputLength <= blockLength)
            self.blockLength = blockLength
            self.outputLength = outputLength
            self.function = function
        }

        /// The hash of `bytes`.
        @inlinable
        public func callAsFunction(_ bytes: [UInt8]) -> [UInt8] {
            function(bytes)
        }
    }
}
