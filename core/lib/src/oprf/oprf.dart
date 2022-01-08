import 'package:opaque/src/oprf/oprf_impl.dart';
import 'package:opaque/src/oprf/util.dart';

typedef PublicInput = Bytes;

class KeyPair {
  final Bytes private;
  final Bytes public;

  KeyPair({required this.private, required this.public});
}

class BlindPair {
  final Bytes blind;
  final Bytes blindedElement;

  BlindPair({required this.blind, required this.blindedElement});
}

// Interface roughly defined by https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-07.html
abstract class Oprf {
  Oprf();

  factory Oprf.p256() => OprfImpl.p256();

  factory Oprf.p384() => OprfImpl.p384();

  Future<BlindPair> blind({required Bytes input});

  Future<Bytes> evaluate({
    required Bytes privateKey,
    required Bytes blindedElement,
    // TODO "currently set to nil" in OPAQUE
    required PublicInput info,
  });

  Future<Bytes> finalize({
    required Bytes input,
    required Bytes blind,
    required Bytes evaluatedElement,
    // TODO "currently set to nil" in OPAQUE
    required PublicInput info,
  });

  Future<KeyPair> deriveKeyPair(Bytes seed);
}
