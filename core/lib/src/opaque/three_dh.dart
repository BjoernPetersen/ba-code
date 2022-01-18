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
    return KE1(
      credentialRequest: CredentialRequest.fromBytes(
        constants,
        bytes.slice(0, CredentialRequest.size(constants)),
      ),
      authInit: AuthInit.fromBytes(
        constants,
        bytes.slice(CredentialRequest.size(constants)),
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

  List<Bytes> asBytesList() => [
        ...credentialResponse.asBytesList(),
        ...authResponse.asBytesList(),
      ];

  static int size(Constants constants) {
    return CredentialResponse.size(constants) + AuthResponse.size(constants);
  }

  factory KE2.fromBytes(Constants constants, Bytes bytes) {
    if (bytes.length != size(constants)) {
      throw ArgumentError('Invalid data size', 'bytes');
    }
    return KE2(
      credentialResponse: CredentialResponse.fromBytes(
        constants,
        bytes.slice(0, CredentialResponse.size(constants)),
      ),
      authResponse: AuthResponse.fromBytes(
        constants,
        bytes.slice(
          CredentialResponse.size(constants),
          AuthResponse.size(constants),
        ),
      ),
    );
  }
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
  final Bytes context;

  Suite get suite => opaque.suite;

  ThreeDiffieHellman(this.opaque, this.context);

  Future<Bytes> _preamble({
    required Bytes clientIdentity,
    required KE1 ke1,
    required Bytes serverIdentity,
    required KE2 ke2,
    required Bytes context,
  }) async {
    return concatBytes([
      'RFCXXXX'.asciiBytes(),
      smallIntToBytes(context.length, length: 2),
      context,
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
      KeyPair(
        private: state.clientSecret,
        public: ke2.authResponse.serverKeyshare,
      ),
      KeyPair(
        private: state.clientSecret,
        public: serverPublicKey,
      ),
      KeyPair(
        private: clientPrivateKey,
        public: ke2.authResponse.serverKeyshare,
      ),
    );
    final preamble = await _preamble(
      clientIdentity: clientIdentity,
      ke1: state.ke1,
      serverIdentity: serverIdentity,
      ke2: ke2,
      context: context,
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
      context: context,
    );
    final ikm = await _tripleDiffieKeyMaterial(
      KeyPair(
        private: keyPair.private,
        public: ke1.authInit.clientKeyshare,
      ),
      KeyPair(
        private: serverPrivateKey,
        public: ke1.authInit.clientKeyshare,
      ),
      KeyPair(
        private: keyPair.private,
        public: clientPublicKey,
      ),
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
    KeyPair keyPair1,
    KeyPair keyPair2,
    KeyPair keyPair3,
  ) async {
    final dh1 = await suite.oprf.multiply(
      serializedScalar: keyPair1.private,
      serializedElement: keyPair1.public,
    );
    final dh2 = await suite.oprf.multiply(
      serializedScalar: keyPair2.private,
      serializedElement: keyPair2.public,
    );
    final dh3 = await suite.oprf.multiply(
      serializedScalar: keyPair3.private,
      serializedElement: keyPair3.public,
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
    final km2 = await _deriveSecret(handshakeSecret, 'ServerMAC', Bytes(0));
    final km3 = await _deriveSecret(handshakeSecret, 'ClientMAC', Bytes(0));
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
    Bytes context,
    int length,
  ) async {
    return await suite.kdf.expand(
      key: secret,
      info: _customLabel(length, label, context),
      l: length,
    );
  }

  Future<Bytes> _deriveSecret(
    Bytes secret,
    String label,
    Bytes transcriptHash,
  ) async {
    return await _expandLabel(
      secret,
      label,
      transcriptHash,
      suite.constants.Nx,
    );
  }
}
