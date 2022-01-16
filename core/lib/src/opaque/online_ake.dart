import 'package:opaque/src/model/model.dart';
import 'package:opaque/src/opaque/three_dh.dart';
import 'package:opaque/src/opaque/credential_retrieval.dart';
import 'package:opaque/src/opaque/opaque.dart';

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
  final ThreeDiffieHellman _threeDh;

  ClientOnlineAkeImpl(this.opaque, this._state)
      : _credentialRetrieval = CredentialRetrieval(opaque),
        _threeDh = ThreeDiffieHellman(opaque);

  Suite get suite => opaque.suite;

  @override
  Future<KE1> init({required Bytes password}) async {
    final result = await _credentialRetrieval.createCredentialRequest(
      password: password,
    );
    _state.blind = result.blind;
    return await _threeDh.clientStart(state: _state, request: result.request);
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
    required ServerState state,
    required KE3 ke3,
  });
}

class ServerOnlineAkeImpl implements ServerOnlineAke {
  final Opaque opaque;
  final ServerState _state;
  final CredentialRetrieval _credentialRetrieval;
  final ThreeDiffieHellman _threeDh;

  ServerOnlineAkeImpl(this.opaque, this._state)
      : _credentialRetrieval = CredentialRetrieval(opaque),
        _threeDh = ThreeDiffieHellman(opaque);

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
  }) async {
    final response = await _credentialRetrieval.createCredentialResponse(
      request: ke1.credentialRequest,
      serverPublicKey: serverPublicKey,
      record: record,
      credentialIdentifier: credentialIdentifier,
      oprfSeed: oprfSeed,
    );
    return await _threeDh.serverResponse(
      state: _state,
      // TODO is this correct?
      serverIdentity: serverIdentity ?? Bytes(0),
      serverPrivateKey: serverPrivateKey,
      clientIdentity: clientIdentity,
      clientPublicKey: record.clientPublicKey,
      ke1: ke1,
      credentialResponse: response,
    );
  }

  @override
  Future<Bytes> serverFinish({
    required ServerState state,
    required KE3 ke3,
  }) {
    return _threeDh.serverFinish(state: state, ke3: ke3);
  }
}
