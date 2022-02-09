import 'package:cryptography/cryptography.dart' as crypto;
import 'package:opaque/src/data_conversion.dart';
import 'package:opaque/src/oprf/prime_order_group.dart';
import 'package:opaque/src/util.dart';
import 'package:pointycastle/ecc/api.dart';

import 'oprf.dart';

class OprfImpl extends Oprf {
  final PrimeOrderGroup group;
  final Bytes contextString;
  final crypto.HashAlgorithm hash;

  OprfImpl.p256()
      : group = PrimeOrderGroupImpl.p256(),
        contextString = _initContextString(3),
        hash = crypto.Sha256();

  OprfImpl.p384()
      : group = PrimeOrderGroupImpl.p384(),
        contextString = _initContextString(4),
        hash = crypto.Sha384();

  static Bytes _initContextString(int id) {
    return concatBytes([
      'VOPRF08-'.asciiBytes(),
      // Mode 0 is "base mode", which we are implementing
      smallIntToBytes(0, length: 1),
      smallIntToBytes(id, length: 2),
    ]);
  }

  @override
  Future<Bytes> multiply({
    required Bytes serializedScalar,
    required Bytes serializedElement,
  }) async {
    final element = group.deserializeElement(serializedElement);
    final scalar = group.deserializeScalar(serializedScalar);
    final multiplied = element * scalar.toBigInteger();
    return group.serializeElement(multiplied!);
  }

  @override
  Future<BlindPair> blind({required Bytes input, Bytes? blind}) async {
    final ECFieldElement effectiveBlind;
    if (blind == null) {
      effectiveBlind = group.randomScalar();
    } else {
      effectiveBlind = group.deserializeScalar(blind);
    }

    final element = await group.hashToGroup(
      data: input,
      domainSeparator: concatBytes([
        'HashToGroup-'.asciiBytes(),
        contextString,
      ]),
    );
    final blinded = element * effectiveBlind.toBigInteger();
    return BlindPair(
      blind: blind ?? group.serializeScalar(effectiveBlind),
      blindedElement: group.serializeElement(blinded!),
    );
  }

  Future<Bytes> unblind({
    required Bytes blind,
    required Bytes blindedElement,
  }) async {
    final desBlinded = group.deserializeElement(blindedElement);
    final desBlind = group.deserializeScalar(blind);
    final element =
        desBlinded * desBlind.toBigInteger()!.modInverse(group.order);
    return group.serializeElement(element!);
  }

  @override
  Future<KeyPair> deriveKeyPair({
    required Bytes seed,
    Bytes? domainSeparator,
  }) async {
    final secret = await group.hashToScalar(
      data: seed,
      domainSeparator: domainSeparator ?? contextString,
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
    required PublicInput info,
  }) async {
    final context = concatBytes([
      'Context-'.asciiBytes(),
      contextString,
      smallIntToBytes(info.lengthInBytes, length: 2),
      info,
    ]);

    final m = await group.hashToScalar(
      data: context,
      domainSeparator: concatBytes([
        'HashToScalar-'.asciiBytes(),
        contextString,
      ]),
    );
    final privateKeyScalar =
        group.deserializeScalar(privateKey).toBigInteger()!;
    final t = (privateKeyScalar + m.toBigInteger()!).remainder(group.order);
    if (t == BigInt.zero) {
      // TODO: type this
      throw ArgumentError('InverseError');
    }
    final deserializedInput = group.deserializeElement(blindedElement);
    final z = (deserializedInput * t.modInverse(group.order))!;
    return group.serializeElement(z);
  }

  /// https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-08.html#section-3.3.3.2
  @override
  Future<Bytes> finalize({
    required Bytes input,
    required Bytes blind,
    required Bytes evaluatedElement,
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
    final digest = await hash.hash(hashInput);
    return Bytes.fromList(digest.bytes);
  }
}
