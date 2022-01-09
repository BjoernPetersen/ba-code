import 'package:cryptography/cryptography.dart' as crypto;
import 'package:opaque/src/opaque/key_derivation.dart';
import 'package:opaque/src/opaque/mhf.dart';
import 'package:opaque/src/oprf/oprf.dart';
import 'package:opaque/src/util.dart';

class Opaque {
  final Suite suite;

  Opaque(this.suite);

  Future<KeyPair> deriveKeyPair(Bytes seed) async {
    return await suite.oprf.deriveKeyPair(
      seed: seed,
      domainSeparator: 'OPAQUE-DeriveKeyPair'.asciiBytes(),
    );
  }
}

class Suite {
  final Oprf oprf;
  final crypto.HashAlgorithm hash;
  final MemoryHardFunction mhf;
  final KeyDerivationFunction kdf;

  Suite({
    required this.oprf,
    required this.hash,
    required this.mhf,
    required this.kdf,
  });

  factory Suite.sha256p256() {
    return Suite(
      oprf: Oprf.p256(),
      hash: crypto.Sha256(),
      mhf: MemoryHardFunction.identity(),
      kdf: KeyDerivationFunction.hkdfSha256(),
    );
  }

  factory Suite.sha384p384() {
    return Suite(
      oprf: Oprf.p384(),
      hash: crypto.Sha384(),
      mhf: MemoryHardFunction.identity(),
      kdf: KeyDerivationFunction.hkdfSha384(),
    );
  }
}
