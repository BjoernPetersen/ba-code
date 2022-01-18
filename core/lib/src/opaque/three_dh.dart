import 'package:cryptography/helpers.dart';
import 'package:opaque/src/data_conversion.dart';
import 'package:opaque/src/model/model.dart';
import 'package:opaque/src/opaque/opaque.dart';
import 'package:opaque/src/util.dart';

class KE1 {
  final CredentialRequest credentialRequest;
  final AuthInit authInit;

  KE1({
    required this.credentialRequest,
    required this.authInit,
  });

  List<Bytes> asBytesList() => [
        ...credentialRequest.asBytesList(),
        ...authInit.asBytesList(),
      ];

  static int size(Constants constants) {
    return CredentialRequest.size(constants) + AuthInit.size(constants);
  }

  factory KE1.fromBytes(Constants constants, Bytes bytes) {
    if (bytes.length != size(constants)) {
      throw ArgumentError('Invalid data size', 'bytes');
    }
    final buffer = bytes.buffer;
    return KE1(
      credentialRequest: CredentialRequest.fromBytes(
        constants, buffer.asUint8List(0, CredentialRequest.size(constants)),
      ),
      authInit: AuthInit.fromBytes(
        constants,
        buffer.asUint8List(CredentialRequest.size(constants)),
      ),
    );
  }
}

class KE2 {
  final CredentialResponse credentialResponse;
  final AuthResponse authResponse;

  KE2({
    required this.credentialResponse,
    required this.authResponse,
  });

  KE2 withServerMac(Bytes serverMac) => KE2(
        credentialResponse: credentialResponse,
        authResponse: authResponse.withServerMac(serverMac),
      );
}

typedef KE3 = AuthFinish;

class ClientFinalizeResult {
  final KE3 ke3;
  final Bytes sessionKey;

  ClientFinalizeResult({
    required this.ke3,
    required this.sessionKey,
  });
}

class DeriveKeysResult {
  final Bytes km2;
  final Bytes km3;
  final Bytes sessionKey;

  DeriveKeysResult({
    required this.km2,
    required this.km3,
    required this.sessionKey,
  });
}

class ThreeDiffieHellman {
  final Opaque opaque;

  Suite get suite => opaque.suite;

  ThreeDiffieHellman(this.opaque);

  Future<Bytes> _preamble({
    required Bytes clientIdentity,
    required KE1 ke1,
    required Bytes serverIdentity,
    required KE2 ke2,
  }) async {
    // TODO literally RFCXXXX?
    // FIXME: include context
    return concatBytes([
      'RFCXXXX'.asciiBytes(),
      smallIntToBytes(clientIdentity.lengthInBytes, length: 2),
      clientIdentity,
      ...ke1.asBytesList(),
      smallIntToBytes(serverIdentity.lengthInBytes, length: 2),
      serverIdentity,
      ...ke2.credentialResponse.asBytesList(),
      ke2.authResponse.serverNonce,
      ke2.authResponse.serverKeyshare,
    ]);
  }

  Future<KE1> clientStart({
    required ClientState state,
    required CredentialRequest request,
    Bytes? testClientNonce,
    Bytes? testClientKeyshare,
  }) async {
    final clientNonce =
        testClientNonce ?? await opaque.randomSeed(suite.constants.Nn);
    final keyPair = await opaque.generateAuthKeyPair();
    final ke1 = KE1(
      credentialRequest: request,
      authInit: AuthInit(
        clientNonce: clientNonce,
        clientKeyshare: testClientKeyshare ?? keyPair.public,
      ),
    );

    // TODO: Populate state with ClientState(client_secret, ke1)
    state.clientSecret = clientNonce;
    state.ke1 = ke1;
    // TODO: return ke1, clientSecret
    return ke1;
  }

  Future<ClientFinalizeResult> clientFinalize({
    required ClientState state,
    required Bytes clientIdentity,
    required Bytes clientPrivateKey,
    required Bytes serverIdentity,
    required Bytes serverPublicKey,
    required KE2 ke2,
  }) async {
    final ikm = await _tripleDiffieKeyMaterial(
      state.clientSecret,
      ke2.authResponse.serverKeyshare,
      state.clientSecret,
      serverPublicKey,
      clientPrivateKey,
      ke2.authResponse.serverKeyshare,
    );
    final preamble = await _preamble(
      clientIdentity: clientIdentity,
      ke1: state.ke1,
      serverIdentity: serverIdentity,
      ke2: ke2,
    );
    final deriveKeysResult = await _deriveKeys(ikm: ikm, preamble: preamble);
    final expectedServerMac = await suite.kdf.mac(
      key: deriveKeysResult.km2,
      msg: await suite.hash(preamble),
    );
    if (!constantTimeBytesEquality.equals(
        ke2.authResponse.serverMac, expectedServerMac)) {
      throw HandshakeException();
    }
    final clientMac = await suite.kdf.mac(
      key: deriveKeysResult.km3,
      msg: await suite.hash(concatBytes([preamble, expectedServerMac])),
    );
    final ke3 = KE3(clientMac: clientMac);
    return ClientFinalizeResult(
      ke3: ke3,
      sessionKey: deriveKeysResult.sessionKey,
    );
  }

  Future<KE2> serverResponse({
    required ServerState state,
    required Bytes serverIdentity,
    required Bytes serverPrivateKey,
    required Bytes clientIdentity,
    required Bytes clientPublicKey,
    required KE1 ke1,
    required CredentialResponse credentialResponse,
    required Bytes? testServerNonce,
    required KeyPair? testServerKeyPair,
  }) async {
    final serverNonce =
        testServerNonce ?? await opaque.randomSeed(suite.constants.Nn);
    final keyPair = testServerKeyPair ?? await opaque.generateAuthKeyPair();
    final ke2 = KE2(
      authResponse: AuthResponse(
        serverMac: Bytes(0),
        serverNonce: serverNonce,
        serverKeyshare: keyPair.public,
      ),
      credentialResponse: credentialResponse,
    );
    final preamble = await _preamble(
      clientIdentity: clientIdentity,
      ke1: ke1,
      serverIdentity: serverIdentity,
      ke2: ke2,
    );
    final ikm = await _tripleDiffieKeyMaterial(
      keyPair.private,
      ke1.authInit.clientKeyshare,
      serverPrivateKey,
      ke1.authInit.clientKeyshare,
      keyPair.private,
      clientPublicKey,
    );
    final deriveKeysResult = await _deriveKeys(ikm: ikm, preamble: preamble);
    final serverMac = await suite.kdf.mac(
      key: deriveKeysResult.km2,
      msg: await suite.hash(preamble),
    );
    final expectedClientMac = await suite.kdf.mac(
      key: deriveKeysResult.km3,
      msg: await suite.hash(concatBytes([preamble, serverMac])),
    );
    state.expectedClientMac = expectedClientMac;
    state.sessionKey = deriveKeysResult.sessionKey;
    return ke2.withServerMac(serverMac);
  }

  Future<Bytes> serverFinish({
    required ServerState state,
    required KE3 ke3,
  }) async {
    if (!constantTimeBytesEquality.equals(
      ke3.clientMac,
      state.expectedClientMac,
    )) {
      throw HandshakeException();
    }
    return state.sessionKey;
  }

  Future<Bytes> _tripleDiffieKeyMaterial(
    Bytes sk1,
    Bytes pk1,
    Bytes sk2,
    Bytes pk2,
    Bytes sk3,
    Bytes pk3,
  ) async {
    final dh1 = await suite.oprf.multiply(
      serializedScalar: sk1,
      serializedElement: pk1,
    );
    final dh2 = await suite.oprf.multiply(
      serializedScalar: sk2,
      serializedElement: pk2,
    );
    final dh3 = await suite.oprf.multiply(
      serializedScalar: sk3,
      serializedElement: pk3,
    );
    return concatBytes([dh1, dh2, dh3]);
  }

  Future<DeriveKeysResult> _deriveKeys({
    required Bytes ikm,
    required Bytes preamble,
  }) async {
    final prk = await suite.kdf.extract(inputMaterial: ikm);
    final hashedPreamble = await suite.hash(preamble);
    final handshakeSecret = await _deriveSecret(
      prk,
      'HandshakeSecret',
      hashedPreamble,
    );
    final sessionKey = await _deriveSecret(prk, 'SessionKey', hashedPreamble);
    final km2 = await _deriveSecret(handshakeSecret, 'ServerMAC', List.empty());
    final km3 = await _deriveSecret(handshakeSecret, 'ClientMAC', List.empty());
    return DeriveKeysResult(
      km2: km2,
      km3: km3,
      sessionKey: sessionKey,
    );
  }

  Bytes _customLabel(int length, String label, Bytes context) {
    return concatBytes([
      smallIntToBytes(length, length: 2),
      'OPAQUE-'.asciiBytes(),
      label.asciiBytes(),
      context,
    ]);
  }

  Future<Bytes> _expandLabel(
    Bytes secret,
    String label,
    List<int> context,
    int length,
  ) async {
    // TODO context instead of nil
    return await suite.kdf.expand(
      key: secret,
      info: _customLabel(length, label, Bytes(0)),
      l: length,
    );
  }

  Future<Bytes> _deriveSecret(
    Bytes secret,
    String label,
    List<int> transcriptHash,
  ) async {
    return await _expandLabel(
      secret,
      label,
      transcriptHash,
      suite.constants.Nx,
    );
  }
}
