import Testing

import RFC_2104

@Suite
struct `RFC 2104 Tests` {

    @Test
    func `RFC 2202 HMAC-SHA-1 test cases`() {
        let hmac = RFC_2104.HMAC(.sha1)
        #expect(hmac.code(for: Array("Hi There".utf8), key: [UInt8](repeating: 0x0b, count: 20)) == hex("b617318655057264e28bc0b6fb378c8ef146be00"))
        #expect(hmac.code(for: Array("what do ya want for nothing?".utf8), key: Array("Jefe".utf8)) == hex("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"))
        #expect(hmac.code(for: [UInt8](repeating: 0xdd, count: 50), key: [UInt8](repeating: 0xaa, count: 20)) == hex("125d7342b9ac11cd91a39af48aa17b4f63f175d3"))
        #expect(hmac.code(for: [UInt8](repeating: 0xcd, count: 50), key: hex("0102030405060708090a0b0c0d0e0f10111213141516171819")) == hex("4c9007f4026250c6bc8414f9bf50c86c2d7235da"))
        #expect(hmac.code(for: Array("Test With Truncation".utf8), key: [UInt8](repeating: 0x0c, count: 20)) == hex("4c1a03424b55e07fe7f27be1d58bb9324a9a5a04"))
        #expect(hmac.code(for: Array("Test Using Larger Than Block-Size Key - Hash Key First".utf8), key: [UInt8](repeating: 0xaa, count: 80)) == hex("aa4ae5e15272d00e95705637ce8a3b55ed402112"))
        #expect(hmac.code(for: Array("Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data".utf8), key: [UInt8](repeating: 0xaa, count: 80)) == hex("e8e99d0f45237d786d6bbaa7965c7808bbff1a91"))
    }

    @Test
    func `RFC 4231 HMAC-SHA-256 test cases`() {
        let hmac = RFC_2104.HMAC(.sha256)
        #expect(hmac.code(for: Array("Hi There".utf8), key: [UInt8](repeating: 0x0b, count: 20)) == hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"))
        #expect(hmac.code(for: Array("what do ya want for nothing?".utf8), key: Array("Jefe".utf8)) == hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"))
        #expect(hmac.code(for: [UInt8](repeating: 0xdd, count: 50), key: [UInt8](repeating: 0xaa, count: 20)) == hex("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"))
        #expect(hmac.code(for: [UInt8](repeating: 0xcd, count: 50), key: hex("0102030405060708090a0b0c0d0e0f10111213141516171819")) == hex("82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"))
        // Test case 5: the code truncated to 128 bits.
        #expect(Array(hmac.code(for: Array("Test With Truncation".utf8), key: [UInt8](repeating: 0x0c, count: 20)).prefix(16)) == hex("a3b6167473100ee06e0c796c2955552b"))
        #expect(hmac.code(for: Array("Test Using Larger Than Block-Size Key - Hash Key First".utf8), key: [UInt8](repeating: 0xaa, count: 131)) == hex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"))
        #expect(hmac.code(for: Array("This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.".utf8), key: [UInt8](repeating: 0xaa, count: 131)) == hex("9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"))
    }

    @Test
    func `RFC 4231 HMAC-SHA-384 test cases`() {
        let hmac = RFC_2104.HMAC(.sha384)
        #expect(hmac.code(for: Array("Hi There".utf8), key: [UInt8](repeating: 0x0b, count: 20)) == hex("afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6"))
        #expect(hmac.code(for: Array("what do ya want for nothing?".utf8), key: Array("Jefe".utf8)) == hex("af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649"))
        #expect(hmac.code(for: [UInt8](repeating: 0xdd, count: 50), key: [UInt8](repeating: 0xaa, count: 20)) == hex("88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27"))
        #expect(hmac.code(for: [UInt8](repeating: 0xcd, count: 50), key: hex("0102030405060708090a0b0c0d0e0f10111213141516171819")) == hex("3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb"))
        // Test case 5: the code truncated to 128 bits.
        #expect(Array(hmac.code(for: Array("Test With Truncation".utf8), key: [UInt8](repeating: 0x0c, count: 20)).prefix(16)) == hex("3abf34c3503b2a23a46efc619baef897"))
        #expect(hmac.code(for: Array("Test Using Larger Than Block-Size Key - Hash Key First".utf8), key: [UInt8](repeating: 0xaa, count: 131)) == hex("4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952"))
        #expect(hmac.code(for: Array("This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.".utf8), key: [UInt8](repeating: 0xaa, count: 131)) == hex("6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e"))
    }

    @Test
    func `RFC 4231 HMAC-SHA-512 test cases`() {
        let hmac = RFC_2104.HMAC(.sha512)
        #expect(hmac.code(for: Array("Hi There".utf8), key: [UInt8](repeating: 0x0b, count: 20)) == hex("87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"))
        #expect(hmac.code(for: Array("what do ya want for nothing?".utf8), key: Array("Jefe".utf8)) == hex("164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"))
        #expect(hmac.code(for: [UInt8](repeating: 0xdd, count: 50), key: [UInt8](repeating: 0xaa, count: 20)) == hex("fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb"))
        #expect(hmac.code(for: [UInt8](repeating: 0xcd, count: 50), key: hex("0102030405060708090a0b0c0d0e0f10111213141516171819")) == hex("b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd"))
        // Test case 5: the code truncated to 128 bits.
        #expect(Array(hmac.code(for: Array("Test With Truncation".utf8), key: [UInt8](repeating: 0x0c, count: 20)).prefix(16)) == hex("415fad6271580a531d4179bc891d87a6"))
        #expect(hmac.code(for: Array("Test Using Larger Than Block-Size Key - Hash Key First".utf8), key: [UInt8](repeating: 0xaa, count: 131)) == hex("80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"))
        #expect(hmac.code(for: Array("This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.".utf8), key: [UInt8](repeating: 0xaa, count: 131)) == hex("e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58"))
    }

    @Test
    func `verify accepts the code and a truncation of at least half its length`() {
        let hmac = RFC_2104.HMAC(.sha256)
        let key = Array("key".utf8)
        let message = Array("message".utf8)
        let code = hmac.code(for: message, key: key)
        #expect(hmac.verify(code, for: message, key: key))
        #expect(hmac.verify(Array(code.prefix(16)), for: message, key: key))
        #expect(!hmac.verify(Array(code.prefix(15)), for: message, key: key))
        #expect(!hmac.verify(code + [0], for: message, key: key))
    }

    @Test
    func `verify refuses a code that differs in any byte`() {
        let hmac = RFC_2104.HMAC(.sha1)
        let key = Array("Jefe".utf8)
        let message = Array("what do ya want for nothing?".utf8)
        let code = hmac.code(for: message, key: key)
        for index in code.indices {
            var altered = code
            altered[index] ^= 0x01
            #expect(!hmac.verify(altered, for: message, key: key))
        }
    }
}
