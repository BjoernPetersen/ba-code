import 'package:cryptography/cryptography.dart' as crypto;
import 'package:opaque/src/model/model.dart';
import 'package:opaque/src/opaque/key_derivation.dart';
import 'package:opaque/src/opaque/mhf.dart';
import 'package:opaque/src/oprf/oprf.dart';

export 'package:opaque/src/opaque/mhf.dart';

class Suite {
  final Oprf oprf;
  final Future<Bytes> Function(List<int>) hash;
  final MemoryHardFunction mhf;
  final KeyDerivationFunction kdf;
  final Constants constants;

  Suite({
    required this.oprf,
    required crypto.HashAlgorithm hash,
    required this.mhf,
    required this.kdf,
    required this.constants,
  }) : hash = _simpleHash(hash);

  factory Suite.sha256p256({
    required MemoryHardFunction mhf,
  }) {
    return Suite(
      oprf: Oprf.p256(),
      hash: crypto.Sha256(),
      mhf: mhf,
      kdf: KeyDerivationFunction.hkdfSha256(),
      constants: const Constants(
        Nh: 32,
        Npk: 33,
        Nsk: 32,
        Nm: 32,
        Nx: 32,
        Nok: 32,
        Noe: 33,
      ),
    );
  }

  factory Suite.sha384p384({
    required MemoryHardFunction mhf,
  }) {
    return Suite(
      oprf: Oprf.p384(),
      hash: crypto.Sha384(),
      mhf: mhf,
      kdf: KeyDerivationFunction.hkdfSha384(),
      constants: const Constants(
        Nh: 48,
        Npk: 49,
        Nsk: 48,
        Nm: 48,
        Nx: 48,
        Nok: 48,
        Noe: 49,
      ),
    );
  }
}

Future<Bytes> Function(List<int>) _simpleHash(crypto.HashAlgorithm cryptoHash) {
  return (input) async => Bytes.fromList((await cryptoHash.hash(input)).bytes);
}
