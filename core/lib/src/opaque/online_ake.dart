import 'package:opaque/src/model/model.dart';
import 'package:opaque/src/opaque/3dh.dart';
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
