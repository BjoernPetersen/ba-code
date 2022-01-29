import 'package:opaque/src/model/model.dart';
import 'package:opaque/src/opaque/opaque_server.dart';
import 'package:opaque/src/util.dart';

class CredentialRequestResult {
  final Bytes blind;
  final CredentialRequest request;

  CredentialRequestResult({required this.blind, required this.request});
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

  Future<CredentialResponse> createCredentialResponse({
    required CredentialRequest request,
    required Bytes serverPublicKey,
    required RegistrationRecord record,
    required Bytes credentialIdentifier,
    required Bytes oprfSeed,
    required Bytes? testMaskingNonce,
  }) async {
    final seed = await suite.kdf.expand(
      key: oprfSeed,
      info: concatBytes([credentialIdentifier, 'OprfKey'.asciiBytes()]),
      l: suite.constants.Nok,
    );
    final oprfKey = (await opaque.deriveKeyPair(seed)).private;
    final z = await suite.oprf.evaluate(
      privateKey: oprfKey,
      blindedElement: request.data,
      info: Bytes(0),
    );
    final maskingNonce =
        testMaskingNonce ?? await opaque.randomSeed(suite.constants.Nn);
    final credentialResponsePad = await suite.kdf.expand(
      key: record.maskingKey,
      info: concatBytes([maskingNonce, 'CredentialResponsePad'.asciiBytes()]),
      l: suite.constants.Npk + Envelope.size(suite.constants),
    );
    final maskedResponse = credentialResponsePad ^
        concatBytes([
          serverPublicKey,
          ...record.envelope.asBytesList(),
        ]);
    return CredentialResponse(
      data: z,
      maskingNonce: maskingNonce,
      maskedResponse: maskedResponse,
    );
  }
}
