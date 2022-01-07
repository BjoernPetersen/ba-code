import 'package:cryptography/cryptography.dart' as crypto;
import 'package:opaque/src/oprf/data_conversion.dart';
import 'package:opaque/src/oprf/prime_order_group.dart';
import 'package:opaque/src/oprf/util.dart';
import 'package:pointycastle/ecc/api.dart';

import 'oprf.dart';

class OprfImpl extends Oprf {
  final PrimeOrderGroup group;
  final Bytes contextString;

  OprfImpl(this.group) : contextString = _initContextString();

  static Bytes _initContextString() {
    return concatBytes([
      'VOPRF08-'.asciiBytes(),
      // Mode 0 is "base mode", which we are implementing
      smallIntToBytes(0, length: 1),
      // Only valid for p384, sha-384
      smallIntToBytes(4, length: 2),
    ]);
  }

  @override
  Future<BlindPair> blind({required Bytes input, Bytes? blind}) async {
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

  Future<Bytes> unblind({
    required Bytes blind,
    required Bytes blindedElement,
  }) async {
    final z = group.deserializeElement(blindedElement);
    final n = z * group.deserializeScalar(blind).invert().toBigInteger()!;
    return group.serializeElement(n!);
  }

  @override
  Future<KeyPair> deriveKeyPair(Bytes seed) async {
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
  Future<Bytes> evaluate({
    required Bytes privateKey,
    required Bytes blindedElement,
    // TODO "currently set to nil" in OPAQUE
    required PublicInput info,
  }) async {
    final context = concatBytes([
      'Context-'.asciiBytes(),
      contextString,
      smallIntToBytes(info.lengthInBytes, length: 2),
      info,
    ]);

    final m = await group.hashToScalar(context, domainSeparator: contextString);
    final privateKeyScalar = group.deserializeScalar(privateKey);
    final t = privateKeyScalar + m;
    if (t.toBigInteger() == BigInt.zero) {
      // TODO: type this
      throw ArgumentError('InverseError');
    }
    final deserializedInput = group.deserializeElement(blindedElement);
    final z = (deserializedInput * t.invert().toBigInteger())!;

    return group.serializeElement(z);
  }

  /// https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-08.html#section-3.3.3.2
  @override
  Future<Bytes> finalize({
    required Bytes input,
    required Bytes blind,
    required Bytes evaluatedElement,
    // TODO "currently set to nil" in OPAQUE
    required PublicInput info,
  }) async {
    final unblindedElement = await unblind(
      blind: blind,
      blindedElement: evaluatedElement,
    );
    final finalizeDst = concatBytes([
      'Finalize-'.asciiBytes(),
      contextString,
    ]);
    final hashInput = concatBytes([
      smallIntToBytes(input.lengthInBytes, length: 2),
      input,
      smallIntToBytes(info.lengthInBytes, length: 2),
      info,
      smallIntToBytes(unblindedElement.lengthInBytes, length: 2),
      unblindedElement,
      smallIntToBytes(finalizeDst.lengthInBytes, length: 2),
      finalizeDst,
    ]);
    final digest = await crypto.Sha384().hash(hashInput);
    return Bytes.fromList(digest.bytes);
  }
}
