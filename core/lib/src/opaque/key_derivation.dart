import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' as crypto;
import 'package:opaque/src/util.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/digests/sha384.dart';
import 'package:pointycastle/digests/sha512.dart';
import 'package:pointycastle/key_derivators/hkdf.dart';
import 'package:pointycastle/pointycastle.dart';

abstract class KeyDerivationFunction {
  factory KeyDerivationFunction.hkdfSha256() => _HkdfImpl.sha256();

  factory KeyDerivationFunction.hkdfSha384() => _HkdfImpl.sha384();

  factory KeyDerivationFunction.hkdfSha512() => _HkdfImpl.sha512();

  /// The output size of the Extract() function in bytes.
  int get outputSize;

  /// Extract a pseudorandom key of fixed length [outputSize] bytes from
  /// input keying material [inputMaterial] and an optional byte string [salt].
  Future<Bytes> extract({required Bytes inputMaterial, Bytes? salt});

  /// Expand a pseudorandom [key] using optional string [info] into
  /// l bytes of output keying material.
  Future<Bytes> expand({
    required Bytes key,
    Bytes? info,
    required int l,
  });
}

class _HkdfImpl implements KeyDerivationFunction {
  // We're exposing the cryptographic package's Hmac here, because
  // the pointycastle version of the interface is an excellent footgun.
  final crypto.Hmac mac;
  final Digest _pointySha;

  _HkdfImpl.sha256()
      : mac = crypto.Hmac.sha256(),
        _pointySha = SHA256Digest();

  _HkdfImpl.sha384()
      : mac = crypto.Hmac(crypto.Sha384()),
        _pointySha = SHA384Digest();

  _HkdfImpl.sha512()
      : mac = crypto.Hmac.sha512(),
        _pointySha = SHA512Digest();

  @override
  int get outputSize => _pointySha.digestSize;

  @override
  Future<Bytes> extract({required Bytes inputMaterial, Bytes? salt}) async {
    final hkdf = HKDFKeyDerivator(_pointySha);
    final keyParams = hkdf.extract(salt, inputMaterial);
    return keyParams.key;
  }

  @override
  Future<Bytes> expand({
    required Bytes key,
    Bytes? info,
    required int l,
  }) async {
    final hkdf = HKDFKeyDerivator(_pointySha);
    final params = HkdfParameters(key, l, null, info, true);
    hkdf.init(params);
    final output = Uint8List(hkdf.keySize);
    hkdf.deriveKey(null, 0, output, 0);
    return output;
  }
}
