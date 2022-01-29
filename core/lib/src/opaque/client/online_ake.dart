import 'package:opaque/src/model/model.dart';
import 'package:opaque/src/opaque/client/credential_retrieval.dart';
import 'package:opaque/src/opaque/opaque_client.dart';
import 'package:opaque/src/opaque/three_dh.dart';

class FinishResult {
  final KE3 ke3;
  final Bytes sessionKey;
  final Bytes exportKey;

  FinishResult({
    required this.ke3,
    required this.sessionKey,
    required this.exportKey,
  });
}

abstract class OnlineAke {
  Future<KE1> init({required Bytes password});

  Future<FinishResult> finish({
    required Bytes clientIdentity,
    required Bytes serverIdentity,
    required KE2 ke2,
  });
}

class OnlineAkeImpl implements OnlineAke {
  final Opaque opaque;
  final ClientState _state;
  final CredentialRetrieval _credentialRetrieval;
  final Bytes dhContext;
  final ThreeDiffieHellman _threeDh;

  OnlineAkeImpl(this.opaque, this.dhContext, this._state)
      : _credentialRetrieval = CredentialRetrieval(opaque),
        _threeDh = ThreeDiffieHellman(opaque, dhContext);

  Suite get suite => opaque.suite;

  @override
  Future<KE1> init({
    required Bytes password,
    Bytes? testBlind,
    Bytes? testNonce,
    Bytes? testPrivateKey,
    Bytes? testKeyshare,
  }) async {
    final result = await _credentialRetrieval.createCredentialRequest(
      password: password,
      blind: testBlind,
    );
    _state.blind = result.blind;
    _state.password = password;
    final KeyPair? testKeyPair;
    if (testPrivateKey != null && testKeyshare != null) {
      testKeyPair = KeyPair(
        private: testPrivateKey,
        public: testKeyshare,
      );
    } else {
      testKeyPair = null;
    }
    return await _threeDh.clientStart(
      state: _state,
      request: result.request,
      testClientNonce: testNonce,
      testClientKeypair: testKeyPair,
    );
  }

  @override
  Future<FinishResult> finish({
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
    return FinishResult(
      ke3: finalizeResult.ke3,
      sessionKey: finalizeResult.sessionKey,
      exportKey: recoveredCreds.exportKey,
    );
  }
}
