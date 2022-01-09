import 'dart:math';

import 'package:cryptography/cryptography.dart' as crypto;
import 'package:opaque/src/model/model.dart';
import 'package:opaque/src/opaque/key_derivation.dart';
import 'package:opaque/src/opaque/key_recovery.dart' show KeyRecovery;
import 'package:opaque/src/opaque/mhf.dart';
import 'package:opaque/src/oprf/oprf.dart';
import 'package:opaque/src/util.dart';

export 'package:opaque/src/opaque/key_recovery.dart' hide KeyRecoveryImpl;

class Opaque {
  final Suite suite;

  Opaque(this.suite);

  Future<Bytes> randomSeed(int length) async {
    final random = Random.secure();
    final result = Bytes(length);
    for (int i = 0; i < length; i += 1) {
      result[i] = random.nextInt(256);
    }
    return result;
  }

  Future<KeyPair> deriveAuthKeyPair(Bytes seed) async {
    return await suite.oprf.deriveKeyPair(
      seed: seed,
      domainSeparator: 'OPAQUE-DeriveAuthKeyPair'.asciiBytes(),
    );
  }

  KeyRecovery get keyRecovery => KeyRecoveryImpl(this);
}

class Suite {
  final Oprf oprf;
  final crypto.HashAlgorithm hash;
  final MemoryHardFunction mhf;
  final KeyDerivationFunction kdf;
  final Constants constants;

  Suite({
    required this.oprf,
    required this.hash,
    required this.mhf,
    required this.kdf,
    required this.constants,
  });

  factory Suite.sha256p256() {
    return Suite(
      oprf: Oprf.p256(),
      hash: crypto.Sha256(),
      mhf: MemoryHardFunction.identity(),
      kdf: KeyDerivationFunction.hkdfSha256(),
      constants: const Constants(
        Nh: 32,
        Npk: 33,
        Nsk: 32,
        Nm: 32,
        Nx: 32,
        Nok: 32,
      ),
    );
  }

  factory Suite.sha384p384() {
    return Suite(
      oprf: Oprf.p384(),
      hash: crypto.Sha384(),
      mhf: MemoryHardFunction.identity(),
      kdf: KeyDerivationFunction.hkdfSha384(),
      constants: const Constants(
        Nh: 48,
        // TODO: these two I'm not sure about
        Npk: 49,
        Nsk: 48,
        Nm: 48,
        Nx: 48,
        Nok: 48,
      ),
    );
  }
}
