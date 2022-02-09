import 'package:opaque/src/model/model.dart';
import 'package:opaque/src/opaque/client/key_recovery.dart';
import 'package:opaque/src/opaque/client/opaque.dart';
import 'package:opaque/src/util.dart';

class CreateRegistrationRequestResult {
  /// The request, which should be sent to the server.
  final RegistrationRequest request;

  /// The blind value, which is later required to unblind the response.
  final Bytes blind;

  CreateRegistrationRequestResult({
    required this.request,
    required this.blind,
  });
}

class FinalizeRequestResult {
  /// Should be sent to the server to finish the registration.
  final RegistrationRecord record;

  /// An export key which can be used to encrypt data for storage on the server
  /// (the server does not know this key).
  final Bytes exportKey;

  FinalizeRequestResult({
    required this.record,
    required this.exportKey,
  });
}

abstract class OfflineRegistration {
  /// Creates the initial registration request.
  Future<CreateRegistrationRequestResult> createRegistrationRequest({
    required Bytes password,
    Bytes? blind,
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
    final storeResult = await KeyRecoveryImpl(opaque).store(
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
