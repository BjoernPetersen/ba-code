import 'dart:math';

import 'package:opaque/src/opaque/suite.dart';
import 'package:opaque/src/oprf/oprf.dart';
import 'package:opaque/src/util.dart';

export 'package:opaque/src/opaque/suite.dart';
export 'package:opaque/src/oprf/oprf.dart' show KeyPair;

abstract class OpaqueBase {
  final Suite suite;

  OpaqueBase(this.suite);

  Future<Bytes> randomSeed(int length) async {
    final random = Random.secure();
    final result = Bytes(length);
    for (int i = 0; i < length; i += 1) {
      result[i] = random.nextInt(256);
    }
    return result;
  }

  Future<KeyPair> generateAuthKeyPair() async {
    final seed = await randomSeed(suite.constants.Nok);
    return suite.oprf.deriveKeyPair(seed: seed);
  }

  Future<KeyPair> deriveKeyPair(Bytes seed) async {
    return await suite.oprf.deriveKeyPair(
      seed: seed,
      domainSeparator: 'OPAQUE-DeriveKeyPair'.asciiBytes(),
    );
  }

  Future<KeyPair> deriveAuthKeyPair(Bytes seed) async {
    return await suite.oprf.deriveKeyPair(
      seed: seed,
      domainSeparator: 'OPAQUE-DeriveAuthKeyPair'.asciiBytes(),
    );
  }
}
