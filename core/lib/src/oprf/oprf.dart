import 'dart:typed_data';

import 'package:opaque/src/oprf/oprf_impl.dart';
import 'package:opaque/src/oprf/prime_order_group.dart';

typedef PublicInput = ByteBuffer;

@Deprecated('May be unnecessary')
class Proof {
  final ByteBuffer c;
  final ByteBuffer s;

  Proof({required this.c, required this.s});
}

class KeyPair {
  final ByteBuffer private;
  final ByteBuffer public;

  KeyPair({required this.private, required this.public});
}

class BlindPair {
  final ByteBuffer blind;
  final ByteBuffer blindedElement;

  BlindPair({required this.blind, required this.blindedElement});
}

// Interface roughly defined by https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-07.html
abstract class Oprf {
  Oprf();

  factory Oprf.withGroup(PrimeOrderGroup group) => OprfImpl(group);

  Future<BlindPair> blind(ByteBuffer input);

  Future<ByteBuffer> evaluate({
    required ByteBuffer privateKey,
    required ByteBuffer input,
    // TODO "currently set to nil" in OPAQUE
    required PublicInput info,
  });

  Future<ByteBuffer> finalize({
    required ByteBuffer input,
    required ByteBuffer blind,
    required ByteBuffer evaluatedElement,
    // TODO "currently set to nil" in OPAQUE
    required PublicInput info,
  });

  Future<KeyPair> deriveKeyPair(ByteBuffer seed);
}
