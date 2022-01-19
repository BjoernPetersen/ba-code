import 'package:opaque/src/model/model.dart';
import 'package:opaque/src/opaque/opaque.dart';
import 'package:opaque/src/util.dart';

class CreateRegistrationRequestResult {
  final RegistrationRequest request;
  final Bytes blind;

  CreateRegistrationRequestResult({
    required this.request,
    required this.blind,
  });
}

class FinalizeRequestResult {
  final RegistrationRecord record;
  final Bytes exportKey;

  FinalizeRequestResult({
    required this.record,
    required this.exportKey,
  });
}

abstract class OfflineRegistration {
  Future<CreateRegistrationRequestResult> createRegistrationRequest({
    required Bytes password,
    Bytes? blind,
  });

  Future<RegistrationResponse> createRegistrationResponse({
    required RegistrationRequest request,
    required Bytes serverPublicKey,
    required Bytes credentialIdentifier,
    required Bytes oprfSeed,
  });

  Future<FinalizeRequestResult> finalizeRequest({
    required Bytes password,
    required Bytes blind,
    required RegistrationResponse response,
    required Bytes? serverIdentity,
    required Bytes clientIdentity,
  });
}

class OfflineRegistrationImpl implements OfflineRegistration {
  final Opaque opaque;

  OfflineRegistrationImpl(this.opaque);

  Suite get suite => opaque.suite;

  @override
  Future<CreateRegistrationRequestResult> createRegistrationRequest({
    required Bytes password,
    Bytes? blind,
  }) async {
    final blindPair = await suite.oprf.blind(
      input: password,
      blind: blind,
    );
    final request = RegistrationRequest(data: blindPair.blindedElement);
    return CreateRegistrationRequestResult(
      request: request,
      blind: blindPair.blind,
    );
  }

  @override
  Future<RegistrationResponse> createRegistrationResponse({
    required RegistrationRequest request,
    required Bytes serverPublicKey,
    required Bytes credentialIdentifier,
    required Bytes oprfSeed,
  }) async {
    final seed = await suite.kdf.expand(
      key: oprfSeed,
      info: concatBytes([credentialIdentifier, 'OprfKey'.asciiBytes()]),
      l: suite.constants.Nseed,
    );
    final oprfKey = (await opaque.deriveKeyPair(seed)).private;
    final z = await suite.oprf.evaluate(
      privateKey: oprfKey,
      blindedElement: request.data,
      info: Bytes(0),
    );
    return RegistrationResponse(data: z, serverPublicKey: serverPublicKey);
  }

  @override
  Future<FinalizeRequestResult> finalizeRequest({
    required Bytes password,
    required Bytes blind,
    required RegistrationResponse response,
    required Bytes? serverIdentity,
    required Bytes clientIdentity,
    Bytes? testEnvelopeNonce,
  }) async {
    final y = await suite.oprf.finalize(
      input: password,
      blind: blind,
      evaluatedElement: response.data,
      info: Bytes(0),
    );
    final randomizedPassword = await suite.kdf.extract(
      inputMaterial: concatBytes([
        y,
        await suite.mhf.harden(y),
      ]),
    );
    final storeResult = await opaque.keyRecovery.store(
      randomizedPassword: randomizedPassword,
      serverPublicKey: response.serverPublicKey,
      clientIdentity: clientIdentity,
      serverIdentity: serverIdentity,
      testEnvelopeNonce: testEnvelopeNonce,
    );
    final record = RegistrationRecord(
      clientPublicKey: storeResult.clientPublicKey,
      maskingKey: storeResult.maskingKey,
      envelope: storeResult.envelope,
    );
    return FinalizeRequestResult(
      record: record,
      exportKey: storeResult.exportKey,
    );
  }
}
