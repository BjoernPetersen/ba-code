import 'dart:math';

import 'package:cryptography/cryptography.dart' as crypto;
import 'package:cryptography/helpers.dart';
import 'package:opaque/src/opaque/key_derivation.dart';
import 'package:opaque/src/opaque/mhf.dart';
import 'package:opaque/src/opaque/model/model.dart';
import 'package:opaque/src/oprf/oprf.dart';
import 'package:opaque/src/util.dart';

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

  /// Clients create an Envelope at registration with the function Store.
  Future<StoreResult> store({
    required Bytes randomizedPassword,
    required Bytes serverPublicKey,
    Bytes? serverIdentity,
    Bytes? clientIdentity,
  }) async {
    final envelopeNonce = await randomSeed(suite.constants.Nn);

    final maskingKey = await suite.kdf.expand(
      key: randomizedPassword,
      info: 'MaskingKey'.asciiBytes(),
      l: suite.constants.Nh,
    );
    final authKey = await suite.kdf.expand(
      key: randomizedPassword,
      info: concatBytes([envelopeNonce, 'AuthKey'.asciiBytes()]),
      l: suite.constants.Nh,
    );
    final exportKey = await suite.kdf.expand(
      key: randomizedPassword,
      info: concatBytes([envelopeNonce, 'ExportKey'.asciiBytes()]),
      l: suite.constants.Nh,
    );
    final seed = await suite.kdf.expand(
      key: randomizedPassword,
      info: concatBytes([envelopeNonce, 'PrivateKey'.asciiBytes()]),
      l: suite.constants.Nseed,
    );

    final clientPublicKey = (await deriveAuthKeyPair(seed)).public;
    final cleartextCreds = CleartextCredentials.create(
      serverPublicKey: serverPublicKey,
      clientPublicKey: clientPublicKey,
      serverIdentity: serverIdentity,
      clientIdentity: clientIdentity,
    );
    final authTag = await suite.kdf.mac(
      key: authKey,
      msg: concatBytes([
        envelopeNonce,
        ...cleartextCreds.asBytesList(),
      ]),
    );
    final envelope = Envelope(
      nonce: envelopeNonce,
      authTag: authTag,
    );

    return StoreResult(
      envelope: envelope,
      clientPublicKey: clientPublicKey,
      maskingKey: maskingKey,
      exportKey: exportKey,
    );
  }

  /// Clients recover their Envelope during login with the Recover function.
  Future<RecoverResult> recover({
    required Bytes randomizedPassword,
    required Bytes serverPublicKey,
    required Envelope envelope,
    Bytes? serverIdentity,
    Bytes? clientIdentity,
  }) async {
    final authKey = await suite.kdf.expand(
      key: randomizedPassword,
      info: concatBytes([
        envelope.nonce,
        'AuthKey'.asciiBytes(),
      ]),
      l: suite.constants.Nh,
    );
    final exportKey = await suite.kdf.expand(
      key: randomizedPassword,
      info: concatBytes([
        envelope.nonce,
        'ExportKey'.asciiBytes(),
      ]),
      l: suite.constants.Nh,
    );
    final seed = await suite.kdf.expand(
      key: randomizedPassword,
      info: concatBytes([
        envelope.nonce,
        'PrivateKey'.asciiBytes(),
      ]),
      l: suite.constants.Nseed,
    );
    final clientKeyPair = await deriveAuthKeyPair(seed);
    final cleartextCreds = CleartextCredentials.create(
      serverPublicKey: serverPublicKey,
      clientPublicKey: clientKeyPair.public,
      serverIdentity: serverIdentity,
      clientIdentity: clientIdentity,
    );
    final expectedTag = await suite.kdf.mac(
      key: authKey,
      msg: concatBytes([
        envelope.nonce,
        ...cleartextCreds.asBytesList(),
      ]),
    );

    if (!constantTimeBytesEquality.equals(envelope.authTag, expectedTag)) {
      throw KeyRecoveryError();
    }
    return RecoverResult(
      clientPrivateKey: clientKeyPair.private,
      exportKey: exportKey,
    );
  }
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
