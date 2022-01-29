import 'package:cryptography/helpers.dart';
import 'package:opaque/src/model/model.dart';
import 'package:opaque/src/opaque/opaque_base.dart';
import 'package:opaque/src/util.dart';

class StoreResult {
  /// the client's [Envelope] structure.
  final Envelope envelope;

  /// the client's AKE public key.
  final Bytes clientPublicKey;

  /// a key used by the server to encrypt the envelope during login.
  final Bytes maskingKey;

  /// an additional client key.
  final Bytes exportKey;

  StoreResult({
    required this.envelope,
    required this.clientPublicKey,
    required this.maskingKey,
    required this.exportKey,
  });
}

class RecoverResult {
  /// The encoded client private key for the AKE protocol.
  final Bytes clientPrivateKey;

  /// an additional client key.
  final Bytes exportKey;

  RecoverResult({
    required this.clientPrivateKey,
    required this.exportKey,
  });
}

abstract class KeyRecovery {
  /// Clients create an Envelope at registration with the function Store.
  Future<StoreResult> store({
    required Bytes randomizedPassword,
    required Bytes serverPublicKey,
    required Bytes? serverIdentity,
    required Bytes? clientIdentity,
    required Bytes? testEnvelopeNonce,
  });

  /// Clients recover their Envelope during login with the Recover function.
  Future<RecoverResult> recover({
    required Bytes randomizedPassword,
    required Bytes serverPublicKey,
    required Envelope envelope,
    required Bytes? serverIdentity,
    required Bytes? clientIdentity,
  });
}

class KeyRecoveryImpl implements KeyRecovery {
  final OpaqueBase opaque;

  Suite get suite => opaque.suite;

  KeyRecoveryImpl(this.opaque);

  @override
  Future<StoreResult> store({
    required Bytes randomizedPassword,
    required Bytes serverPublicKey,
    required Bytes? serverIdentity,
    required Bytes? clientIdentity,
    required Bytes? testEnvelopeNonce,
  }) async {
    final envelopeNonce =
        testEnvelopeNonce ?? await opaque.randomSeed(suite.constants.Nn);

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

    final clientPublicKey = (await opaque.deriveAuthKeyPair(seed)).public;
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
        cleartextCreds.serialize(),
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

  @override
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
    final clientKeyPair = await opaque.deriveAuthKeyPair(seed);
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
        cleartextCreds.serialize(),
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
