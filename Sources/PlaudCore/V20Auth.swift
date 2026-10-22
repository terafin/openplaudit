import Foundation
import CryptoKit

/// v20 authentication: the RSA pre-handshake and the ChaCha20-Poly1305 session
/// cipher used for every command after it.
///
/// `BLEKit` only implements the legacy plaintext handshake (token in the clear,
/// no pre-handshake), which a bound portVersion-20 device rejects with
/// TOKEN_NOT_MATCH. This is the missing half — pure logic, no BLE, so it can be
/// unit-tested off-device and driven from the iOS app's CoreBluetooth layer.
public enum V20Auth {
    public static let cmdPreHandshakeNew: UInt16 = 0xFE20
    public static let cmdPreHandshakeConfirm: UInt16 = 0xFE11
    public static let cmdSendRSAPubKey: UInt16 = 0xFE12
    public static let cmdHandshake: UInt16 = 0x01
    public static let chunkSize = 100
    /// Two bytes the device expects ahead of the port version in a handshake.
    public static let mtuIndicator = Data([0x02, 0x00])

    public enum AuthError: Error, LocalizedError {
        case noConfirm
        case incompleteKeyMaterial(Int, Int)
        case keyMaterialTooShort(Int)
        case verificationFailed
        case handshakeRejected(UInt8)

        public var errorDescription: String? {
            switch self {
            case .noConfirm: return "Pre-handshake: device did not confirm"
            case .incompleteKeyMaterial(let got, let want):
                return "Pre-handshake: got \(got)/\(want) key-material chunks"
            case .keyMaterialTooShort(let n):
                return "Pre-handshake: key material too short (\(n) bytes)"
            case .verificationFailed:
                return "Pre-handshake: PLAUD.AI verification failed — wrong session keys"
            case .handshakeRejected(let s):
                return "Handshake rejected by device (status \(s))"
            }
        }
    }

    // MARK: - Packet builders

    /// `[cmd:2LE][total:1][index:1][data]` — sent unencrypted, before the
    /// session cipher exists.
    public static func preHandshakeChunk(cmd: UInt16, total: Int, index: Int,
                                         data: Data) -> Data {
        var out = Data()
        out.append(UInt8(cmd & 0xff)); out.append(UInt8((cmd >> 8) & 0xff))
        out.append(UInt8(total & 0xff)); out.append(UInt8(index & 0xff))
        out.append(data)
        return out
    }

    /// `[proto:1][cmd:2LE][payload]`.
    public static func buildCmd(_ cmd: UInt16, payload: Data = Data()) -> Data {
        var out = Data([0x01, UInt8(cmd & 0xff), UInt8((cmd >> 8) & 0xff)])
        out.append(payload)
        return out
    }

    public static func handshakePayload(token: String, portVersion: UInt8,
                                        ssn: String? = nil) -> Data {
        var p = mtuIndicator
        p.append(portVersion)
        var t = Data(token.utf8).prefix(32)
        while t.count < 32 { t.append(0) }
        p.append(t)
        if let ssn {
            var s = Data(ssn.utf8).prefix(8)
            while s.count < 8 { s.append(0) }
            p.append(s)
        }
        return p
    }

    /// Split `data` into the chunked pre-handshake frames for `cmd`.
    public static func chunks(cmd: UInt16, data: Data, chunkSize: Int = chunkSize) -> [Data] {
        let total = max(1, (data.count + chunkSize - 1) / chunkSize)
        var out: [Data] = []
        out.reserveCapacity(total)
        for i in 0..<total {
            let start = i * chunkSize
            let end = min(start + chunkSize, data.count)
            let slice = start < data.count ? data.subdata(in: start..<end) : Data()
            out.append(preHandshakeChunk(cmd: cmd, total: total, index: i, data: slice))
        }
        return out
    }

    // MARK: - Session keys

    public struct SessionKeys {
        public let key: Data       // 32 bytes
        public let nonce: Data     // 12 bytes
        public let ad: Data        // 12 bytes
    }

    /// Reassemble the device's 0xFE12 chunks and unwrap the session keys.
    ///
    /// Each frame is `[cmd:2][total:1][index:1][data]`; the concatenated payload
    /// is one RSA blob of `key(32) | nonce(12) | ad(12) | sealed verification`.
    public static func sessionKeys(fromChunks frames: [Data],
                                   privateKeyPEM: String) throws -> SessionKeys {
        var expected: Int?
        var parts: [Int: Data] = [:]
        for f in frames {
            guard f.count >= 4 else { continue }
            guard UInt16(f[0]) | (UInt16(f[1]) << 8) == cmdSendRSAPubKey else { continue }
            let total = Int(f[2]), index = Int(f[3])
            if expected == nil { expected = total }
            guard total == expected else { continue }
            parts[index] = f.subdata(in: 4..<f.count)
        }
        let want = expected ?? 0
        guard want > 0, parts.count >= want else {
            throw AuthError.incompleteKeyMaterial(parts.count, want)
        }
        var blob = Data()
        for i in 0..<want { blob.append(parts[i] ?? Data()) }

        let rsa = try RSAKey(pem: privateKeyPEM)
        let dec = try rsa.decryptPKCS1(blob)
        guard dec.count >= 56 else { throw AuthError.keyMaterialTooShort(dec.count) }

        let keys = SessionKeys(
            key: dec.subdata(in: 0..<32),
            nonce: dec.subdata(in: 32..<44),
            ad: dec.subdata(in: 44..<56)
        )
        // The remainder is a sealed "PLAUD.AI" blob under the same keys — a
        // cheap proof that the unwrap succeeded.
        let sealedBlob = dec.subdata(in: 56..<dec.count)
        if sealedBlob.count > 16 {
            let ct = sealedBlob.subdata(in: 0..<(sealedBlob.count - 16))
            let tag = sealedBlob.subdata(in: (sealedBlob.count - 16)..<sealedBlob.count)
            if let plain = try? SessionCrypto.open(ciphertext: ct, tag: tag, keys: keys),
               let s = String(data: plain, encoding: .utf8), s.contains("PLAUD.AI") {
                return keys
            }
            throw AuthError.verificationFailed
        }
        return keys
    }
}

/// ChaCha20-Poly1305 session cipher, matching the device's counter scheme.
///
/// The nonce is FIXED for the whole session (that is the protocol); the 4-byte
/// little-endian counter is prepended to the plaintext inside the sealed blob.
/// `sendCounter` starts at 1 and is incremented BEFORE each encryption, so the
/// first packet goes out with counter 2.
public final class SessionCrypto {
    public private(set) var sendCounter: UInt32 = 1
    public private(set) var receiveCounter: UInt32 = 0
    private let keys: V20Auth.SessionKeys

    public init(keys: V20Auth.SessionKeys) {
        self.keys = keys
    }

    public func encrypt(_ plaintext: Data) throws -> Data {
        sendCounter &+= 1
        var pt = Data()
        pt.append(UInt8(sendCounter & 0xff)); pt.append(UInt8((sendCounter >> 8) & 0xff))
        pt.append(UInt8((sendCounter >> 16) & 0xff)); pt.append(UInt8((sendCounter >> 24) & 0xff))
        pt.append(plaintext)
        let box = try ChaChaPoly.seal(pt, using: SymmetricKey(data: keys.key),
                                      nonce: try ChaChaPoly.Nonce(data: keys.nonce),
                                      authenticating: keys.ad)
        var out = Data(box.ciphertext)
        out.append(box.tag)
        return out
    }

    public func decrypt(_ sealed: Data) throws -> Data {
        guard sealed.count > 16 else { return Data() }
        let ct = sealed.subdata(in: 0..<(sealed.count - 16))
        let tag = sealed.subdata(in: (sealed.count - 16)..<sealed.count)
        let plain = try SessionCrypto.open(ciphertext: ct, tag: tag, keys: keys)
        guard plain.count >= 4 else { return Data() }
        receiveCounter = UInt32(plain[0]) | (UInt32(plain[1]) << 8)
                       | (UInt32(plain[2]) << 16) | (UInt32(plain[3]) << 24)
        return plain.subdata(in: 4..<plain.count)
    }

    static func open(ciphertext: Data, tag: Data, keys: V20Auth.SessionKeys) throws -> Data {
        let box = try ChaChaPoly.SealedBox(nonce: try ChaChaPoly.Nonce(data: keys.nonce),
                                           ciphertext: ciphertext, tag: tag)
        return try ChaChaPoly.open(box, using: SymmetricKey(data: keys.key),
                                   authenticating: keys.ad)
    }
}

/// Device binding credentials, parsed from the same markdown file the CLI uses.
public struct DeviceCredentials: Sendable {
    public let snSignature: Data
    public let rsaPublicKeyPEM: String
    public let rsaPrivateKeyPEM: String
    /// Optional: the device binding token. When present the app does not need a
    /// separate field, which removes a hand-pasted 32-char hex from the setup.
    public let deviceToken: String?

    public enum ParseError: Error, LocalizedError {
        case missing(String)
        case badSignature
        public var errorDescription: String? {
            switch self {
            case .missing(let f): return "Credentials missing field: \(f)"
            case .badSignature: return "sn_signature is not valid base64"
            }
        }
    }

    public init(snSignature: Data, rsaPublicKeyPEM: String, rsaPrivateKeyPEM: String,
                deviceToken: String? = nil) {
        self.deviceToken = deviceToken
        self.snSignature = snSignature
        self.rsaPublicKeyPEM = rsaPublicKeyPEM
        self.rsaPrivateKeyPEM = rsaPrivateKeyPEM
    }

    /// Parse the `plaud-credentials.md` format:
    ///   - sn_signature: <base64>
    ///   - user_rsa_public_key: -----BEGIN PUBLIC KEY-----...
    ///   - user_rsa_private_key: -----BEGIN PRIVATE KEY-----...
    public static func parse(markdown: String) throws -> DeviceCredentials {
        func field(_ name: String) throws -> String {
            let pattern = "\(name):\\s*(\\S+)"
            guard let r = try? NSRegularExpression(pattern: pattern) else {
                throw ParseError.missing(name)
            }
            let ns = markdown as NSString
            guard let m = r.firstMatch(in: markdown, range: NSRange(location: 0, length: ns.length)),
                  m.numberOfRanges > 1 else { throw ParseError.missing(name) }
            return ns.substring(with: m.range(at: 1))
        }
        func pem(_ name: String, kind: String) throws -> String {
            let pattern = "\(name):\\s*(-----BEGIN \(kind)-----.*?-----END \(kind)-----)"
            guard let r = try? NSRegularExpression(pattern: pattern,
                                                  options: [.dotMatchesLineSeparators]) else {
                throw ParseError.missing(name)
            }
            let ns = markdown as NSString
            guard let m = r.firstMatch(in: markdown, range: NSRange(location: 0, length: ns.length)),
                  m.numberOfRanges > 1 else { throw ParseError.missing(name) }
            return ns.substring(with: m.range(at: 1))
        }

        let sigB64 = try field("sn_signature")
        guard let sig = Data(base64Encoded: sigB64) else { throw ParseError.badSignature }
        return DeviceCredentials(
            snSignature: sig,
            rsaPublicKeyPEM: try pem("user_rsa_public_key", kind: "PUBLIC KEY"),
            rsaPrivateKeyPEM: try pem("user_rsa_private_key", kind: "PRIVATE KEY"),
            deviceToken: (try? field("device_token")).map {
                $0.trimmingCharacters(in: .whitespacesAndNewlines)
            }
        )
    }

    public var asMarkdown: String {
        """
        # PLAUD self-bind credentials (generated by bind.py)
        - sn_signature: \(snSignature.base64EncodedString())
        - user_rsa_public_key: \(rsaPublicKeyPEM)
        - user_rsa_private_key: \(rsaPrivateKeyPEM)
        """
    }
}
