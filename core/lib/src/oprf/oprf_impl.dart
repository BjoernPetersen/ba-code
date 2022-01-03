import 'dart:convert';
import 'dart:typed_data';

import 'package:opaque/src/oprf/data_conversion.dart';
import 'package:opaque/src/oprf/prime_order_group.dart';
import 'package:pointycastle/ecc/api.dart';

import 'oprf.dart';

class OprfImpl extends Oprf {
  final PrimeOrderGroup group;
  final ByteBuffer contextString;

  OprfImpl(this.group) : contextString = _initContextString();

  static ByteBuffer _initContextString() {
    final builder = BytesBuilder(copy: false);

    builder.add(AsciiEncoder().convert('VOPRF08-'));
    // Mode 0 is "base mode", which we are implementing
    builder.add(intToBytes(BigInt.zero, 1));
    // Only valid for p384, sha-384
    builder.add(intToBytes(BigInt.from(4), 2));

    return builder
        .takeBytes()
        .buffer;
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
      blindedElement: serializedBlinded,);
  }

  @override
  Future<KeyPair> deriveKeyPair(ByteBuffer seed) async {
    final secret = await group.hashToScalar(
      seed,
      domainSeparator: contextString,
    );
    final publicKey = await group.scalarBaseMult(secret);
    return KeyPair(
      private: group.serializeScalar(secret),
      public: group.serializeElement(publicKey),
    );
  }

  @override
  Future<ByteBuffer> evaluate({
    required ByteBuffer privateKey,
    required ByteBuffer input,
    // TODO "currently set to nil" in OPAQUE
    required PublicInput info,
  }) {
    // TODO: implement evaluate
    throw UnimplementedError();
  }

  @override
  Future<ByteBuffer> finalize({
    required ByteBuffer input,
    required ByteBuffer blind,
    required ByteBuffer evaluatedElement,
    // TODO "currently set to nil" in OPAQUE
    required PublicInput info,
  }) {
    // TODO: implement finalize
    throw UnimplementedError();
  }
}
