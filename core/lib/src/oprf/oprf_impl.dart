import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' as crypto;
import 'package:opaque/src/oprf/data_conversion.dart';
import 'package:opaque/src/oprf/prime_order_group.dart';
import 'package:opaque/src/oprf/util.dart';
import 'package:pointycastle/ecc/api.dart';

import 'oprf.dart';

class OprfImpl extends Oprf {
  final PrimeOrderGroup group;
  final ByteBuffer contextString;

  OprfImpl(this.group) : contextString = _initContextString();

  static ByteBuffer _initContextString() {
    return concatBytes([
      'VOPRF08-'.asciiBytes(),
      // Mode 0 is "base mode", which we are implementing
      intToBytes(BigInt.zero, 1),
      // Only valid for p384, sha-384
      intToBytes(BigInt.from(4), 2),
    ]).buffer;
  }

  @override
  Future<BlindPair> blind(ByteBuffer input, {ByteBuffer? blind}) async {
    final ECFieldElement effectiveBlind;
    if (blind == null) {
      effectiveBlind = group.randomScalar();
    } else {
      effectiveBlind = group.deserializeScalar(blind);
    }

    final p = await group.hashToGroup(input, domainSeparator: contextString);
    final blinded = p * effectiveBlind.toBigInteger();
    final serializedBlinded = group.serializeElement(blinded!);
    return BlindPair(
      blind: blind ?? group.serializeScalar(effectiveBlind),
      blindedElement: serializedBlinded,
    );
  }

  Future<ByteBuffer> unblind({
    required ByteBuffer blind,
    required ByteBuffer blindedElement,
  }) async {
    final z = group.deserializeElement(blindedElement);
    final n = z * group.deserializeScalar(blind).invert().toBigInteger();
    return group.serializeElement(n!);
  }

  @override
  Future<KeyPair> deriveKeyPair(ByteBuffer seed) async {
    final secret = await group.hashToScalar(
      seed,
      domainSeparator: contextString,
    );
    final publicKey = group.scalarBaseMult(secret);
    return KeyPair(
      private: group.serializeScalar(secret),
      public: group.serializeElement(publicKey),
    );
  }

  /// https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-08.html#section-3.3.1.1
  @override
  Future<ByteBuffer> evaluate({
    required ByteBuffer privateKey,
    required ByteBuffer input,
    // TODO "currently set to nil" in OPAQUE
    required PublicInput info,
  }) async {
    final context = concatBytes([
      'Context-'.asciiBytes(),
      contextString.asUint8List(),
      smallIntToBytes(info.lengthInBytes, 2),
      info.asUint8List(),
    ]).buffer;

    final m = await group.hashToScalar(context, domainSeparator: contextString);
    final privateKeyScalar = group.deserializeScalar(privateKey);
    final t = privateKeyScalar + m;
    if (t.toBigInteger() == BigInt.zero) {
      // TODO: type this
      throw ArgumentError('InverseError');
    }
    final deserializedInput = group.deserializeElement(input);
    final z = (deserializedInput * t.invert().toBigInteger())!;

    return group.serializeElement(z);
  }

  /// https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-08.html#section-3.3.3.2
  @override
  Future<ByteBuffer> finalize({
    required ByteBuffer input,
    required ByteBuffer blind,
    required ByteBuffer evaluatedElement,
    // TODO "currently set to nil" in OPAQUE
    required PublicInput info,
  }) async {
    final unblindedElement = await unblind(
      blind: blind,
      blindedElement: evaluatedElement,
    );
    final dst = concatBuffers([
      'Finalize-'.asciiBytes().buffer,
      contextString,
    ]);
    final hashInput = concatBytes([
      smallIntToBytes(input.lengthInBytes, 2),
      input.asUint8List(),
      smallIntToBytes(info.lengthInBytes, 2),
      info.asUint8List(),
      smallIntToBytes(unblindedElement.lengthInBytes, 2),
      unblindedElement.asUint8List(),
      smallIntToBytes(dst.lengthInBytes, 2),
      dst.asUint8List(),
    ]);
    final digest = await crypto.Sha384().hash(hashInput);
    return Uint8List.fromList(digest.bytes).buffer;
  }
}
