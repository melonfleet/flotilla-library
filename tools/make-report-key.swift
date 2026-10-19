// Prints a new Ed25519 report-signing key on one line: "<private seed, base64> <public key, base64>".
// Used only by make-report-key.sh, which pipes the seed away without showing it.
import CryptoKit
import Foundation

let key = Curve25519.Signing.PrivateKey()
print(key.rawRepresentation.base64EncodedString(), key.publicKey.rawRepresentation.base64EncodedString())
