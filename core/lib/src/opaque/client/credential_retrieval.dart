import 'package:opaque/src/model/model.dart';
import 'package:opaque/src/opaque/client/key_recovery.dart';
import 'package:opaque/src/opaque/client/opaque.dart';
import 'package:opaque/src/util.dart';

class CredentialRequestResult {
  final Bytes blind;
  final CredentialRequest request;

  CredentialRequestResult({
    required this.blind,
    required this.request,
  });
}

class RecoverCredentialsResult {
  final Bytes clientPrivateKey;
  final Bytes serverPublicKey;
  final Bytes exportKey;

  RecoverCredentialsResult({
    required this.clientPrivateKey,
    required this.serverPublicKey,
    required this.exportKey,
  });
}

class CredentialRetrieval {
  final Opaque opaque;

  Suite get suite => opaque.suite;

  CredentialRetrieval(this.opaque);

  Future<CredentialRequestResult> createCredentialRequest({
    required Bytes password,
    Bytes? blind,
  }) async {
    final blindPair = await suite.oprf.blind(
      input: password,
      blind: blind,
    );
    final request = CredentialRequest(data: blindPair.blindedElement);
    return CredentialRequestResult(
      blind: blindPair.blind,
      request: request,
    );
  }

  Future<RecoverCredentialsResult> recoverCredentials({
    required Bytes password,
    required Bytes blind,
    required CredentialResponse response,
    required Bytes serverIdentity,
    required Bytes clientIdentity,
  }) async {
    final y = await suite.oprf.finalize(
      input: password,
      blind: blind,
      evaluatedElement: response.data,
      info: Bytes(0),
    );
    final randomizedPassword = await suite.kdf.extract(
      inputMaterial: concatBytes([y, await suite.mhf.harden(y)]),
    );
    final maskingKey = await suite.kdf.expand(
      key: randomizedPassword,
      info: 'MaskingKey'.asciiBytes(),
      l: suite.constants.Nh,
    );

    final credentialResponsePad = await suite.kdf.expand(
      key: maskingKey,
      info: concatBytes([
        response.maskingNonce,
        'CredentialResponsePad'.asciiBytes(),
      ]),
      l: suite.constants.Npk + Envelope.size(suite.constants),
    );
    final xored = credentialResponsePad ^ response.maskedResponse;
    final serverPublicKey = xored.slice(0, suite.constants.Npk);
    final envelopeBytes = xored.slice(
      suite.constants.Npk,
      Envelope.size(suite.constants),
    );
    final Envelope envelope = Envelope.fromBytes(
      suite.constants,
      envelopeBytes,
    );
    final recoverResult = await KeyRecoveryImpl(opaque).recover(
      randomizedPassword: randomizedPassword,
      serverPublicKey: serverPublicKey,
      envelope: envelope,
      clientIdentity: clientIdentity,
      serverIdentity: serverIdentity,
    );
    return RecoverCredentialsResult(
      clientPrivateKey: recoverResult.clientPrivateKey,
      serverPublicKey: serverPublicKey,
      exportKey: recoverResult.exportKey,
    );
  }
}
