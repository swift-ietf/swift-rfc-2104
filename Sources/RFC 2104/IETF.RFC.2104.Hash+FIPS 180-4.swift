internal import Byte
internal import FIPS_180_4

extension IETF.RFC.`2104`.Hash {

    /// SHA-1 (FIPS 180-4): `B` = 64, `L` = 20.
    public static let sha1 = IETF.RFC.`2104`.Hash(blockLength: 64, outputLength: 20) { bytes in
        FIPS_180_4.SHA1.digest(bytes.map(Byte.init(_:))).bytes.map(\.underlying)
    }

    /// SHA-256 (FIPS 180-4): `B` = 64, `L` = 32.
    public static let sha256 = IETF.RFC.`2104`.Hash(blockLength: 64, outputLength: 32) { bytes in
        FIPS_180_4.SHA256.digest(bytes.map(Byte.init(_:))).bytes.map(\.underlying)
    }

    /// SHA-384 (FIPS 180-4): `B` = 128, `L` = 48.
    public static let sha384 = IETF.RFC.`2104`.Hash(blockLength: 128, outputLength: 48) { bytes in
        FIPS_180_4.SHA384.digest(bytes.map(Byte.init(_:))).bytes.map(\.underlying)
    }

    /// SHA-512 (FIPS 180-4): `B` = 128, `L` = 64.
    public static let sha512 = IETF.RFC.`2104`.Hash(blockLength: 128, outputLength: 64) { bytes in
        FIPS_180_4.SHA512.digest(bytes.map(Byte.init(_:))).bytes.map(\.underlying)
    }
}
