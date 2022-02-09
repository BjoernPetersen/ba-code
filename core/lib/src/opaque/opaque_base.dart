import 'package:opaque/src/opaque/suite.dart';
import 'package:opaque/src/oprf/oprf.dart';
import 'package:opaque/src/util.dart';

export 'package:opaque/src/opaque/suite.dart';
export 'package:opaque/src/oprf/oprf.dart' show KeyPair;

abstract class OpaqueBase {
  final Suite suite;

  OpaqueBase(this.suite);

  /// Generates a pseudorandom key pair.
  Future<KeyPair> generateAuthKeyPair() async {
    final seed = await randomSeed(suite.constants.Nok);
    return suite.oprf.deriveKeyPair(seed: seed);
  }

  // Deterministically derives a key pair from the given [seed].
  Future<KeyPair> deriveKeyPair(Bytes seed) async {
    return await suite.oprf.deriveKeyPair(
      seed: seed,
      domainSeparator: 'OPAQUE-DeriveKeyPair'.asciiBytes(),
    );
  }
}
