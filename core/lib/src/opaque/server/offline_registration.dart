import 'package:opaque/src/model/model.dart';
import 'package:opaque/src/opaque/server/opaque.dart';
import 'package:opaque/src/util.dart';

abstract class OfflineRegistration {
  /// Generates an OPRF seed which is later passed to
  /// [createRegistrationResponse].
  /// The seed should be saved, because it's required during login as well.
  Future<Bytes> generateOprfSeed();

  Future<RegistrationResponse> createRegistrationResponse({
    required RegistrationRequest request,
    required Bytes serverPublicKey,
    required Bytes credentialIdentifier,
    required Bytes oprfSeed,
  });
}

class OfflineRegistrationImpl implements OfflineRegistration {
  final Opaque opaque;

  OfflineRegistrationImpl(this.opaque);

  Suite get suite => opaque.suite;

  @override
  Future<Bytes> generateOprfSeed() async {
    return randomSeed(suite.constants.Nh);
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
}
