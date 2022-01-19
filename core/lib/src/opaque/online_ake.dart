import 'package:opaque/src/model/model.dart';
import 'package:opaque/src/opaque/credential_retrieval.dart';
import 'package:opaque/src/opaque/opaque.dart';
import 'package:opaque/src/opaque/three_dh.dart';

class ClientFinishResult {
  final KE3 ke3;
  final Bytes sessionKey;
  final Bytes exportKey;

  ClientFinishResult({
    required this.ke3,
    required this.sessionKey,
    required this.exportKey,
  });
}

abstract class ClientOnlineAke {
  Future<KE1> init({required Bytes password});

  Future<ClientFinishResult> finish({
    required Bytes clientIdentity,
    required Bytes serverIdentity,
    required KE2 ke2,
  });
}

class ClientOnlineAkeImpl implements ClientOnlineAke {
  final Opaque opaque;
  final ClientState _state;
  final CredentialRetrieval _credentialRetrieval;
  final Bytes dhContext;
  final ThreeDiffieHellman _threeDh;

  ClientOnlineAkeImpl(this.opaque, this.dhContext, this._state)
      : _credentialRetrieval = CredentialRetrieval(opaque),
        _threeDh = ThreeDiffieHellman(opaque, dhContext);

  Suite get suite => opaque.suite;

  @override
  Future<KE1> init({
    required Bytes password,
    Bytes? testBlind,
    Bytes? testNonce,
    Bytes? testKeyshare,
  }) async {
    final result = await _credentialRetrieval.createCredentialRequest(
      password: password,
      blind: testBlind,
    );
    _state.blind = result.blind;
    return await _threeDh.clientStart(
      state: _state,
      request: result.request,
      testClientNonce: testNonce,
      testClientKeyshare: testKeyshare,
    );
  }

  @override
  Future<ClientFinishResult> finish({
    required Bytes clientIdentity,
    required Bytes serverIdentity,
    required KE2 ke2,
  }) async {
    final recoveredCreds = await _credentialRetrieval.recoverCredentials(
      password: _state.password,
      blind: _state.blind,
      response: ke2.credentialResponse,
      serverIdentity: serverIdentity,
      clientIdentity: clientIdentity,
    );
    final finalizeResult = await _threeDh.clientFinalize(
      state: _state,
      clientIdentity: clientIdentity,
      clientPrivateKey: recoveredCreds.clientPrivateKey,
      serverIdentity: serverIdentity,
      serverPublicKey: recoveredCreds.serverPublicKey,
      ke2: ke2,
    );
    return ClientFinishResult(
      ke3: finalizeResult.ke3,
      sessionKey: finalizeResult.sessionKey,
      exportKey: recoveredCreds.exportKey,
    );
  }
}

abstract class ServerOnlineAke {
  /// Input:
  /// - [serverIdentity], the optional encoded server identity, which is set to
  ///   [serverPublicKey] if nil.
  /// - [serverPrivateKey], the server's private key.
  /// - [serverPublicKey], the server's public key.
  /// - [record], the client's RegistrationRecord structure.
  /// - [credentialIdentifier], an identifier that uniquely represents the credential.
  /// - [oprfSeed], the server-side seed of Nh bytes used to generate an oprf_key.
  /// - [ke1], a KE1 message structure.
  /// - [clientIdentity], the encoded client identity.
  ///
  /// Output:
  /// - ke2, a KE2 structure.
  Future<KE2> init({
    required Bytes? serverIdentity,
    required Bytes serverPrivateKey,
    required Bytes serverPublicKey,
    required RegistrationRecord record,
    required Bytes credentialIdentifier,
    required Bytes oprfSeed,
    required KE1 ke1,
    required Bytes clientIdentity,
  });

  Future<Bytes> serverFinish({
    required KE3 ke3,
  });
}

class ServerOnlineAkeImpl implements ServerOnlineAke {
  final Opaque opaque;
  final ServerState _state;
  final CredentialRetrieval _credentialRetrieval;
  final Bytes dhContext;
  final ThreeDiffieHellman _threeDh;

  ServerOnlineAkeImpl(this.opaque, this.dhContext, this._state)
      : _credentialRetrieval = CredentialRetrieval(opaque),
        _threeDh = ThreeDiffieHellman(opaque, dhContext);

  Suite get suite => opaque.suite;

  @override
  Future<KE2> init({
    required Bytes? serverIdentity,
    required Bytes serverPrivateKey,
    required Bytes serverPublicKey,
    required RegistrationRecord record,
    required Bytes credentialIdentifier,
    required Bytes oprfSeed,
    required KE1 ke1,
    required Bytes clientIdentity,
    Bytes? testMaskingNonce,
    Bytes? testNonce,
    KeyPair? testKeyPair,
  }) async {
    final response = await _credentialRetrieval.createCredentialResponse(
      request: ke1.credentialRequest,
      serverPublicKey: serverPublicKey,
      record: record,
      credentialIdentifier: credentialIdentifier,
      oprfSeed: oprfSeed,
      testMaskingNonce: testMaskingNonce,
    );
    return await _threeDh.serverResponse(
      state: _state,
      serverIdentity: serverIdentity ?? serverPublicKey,
      serverPrivateKey: serverPrivateKey,
      clientIdentity: clientIdentity,
      clientPublicKey: record.clientPublicKey,
      ke1: ke1,
      credentialResponse: response,
      testServerNonce: testNonce,
      testServerKeyPair: testKeyPair,
    );
  }

  @override
  Future<Bytes> serverFinish({
    required KE3 ke3,
  }) {
    return _threeDh.serverFinish(state: _state, ke3: ke3);
  }
}
