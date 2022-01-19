import 'package:opaque/client.dart';
import 'package:opaque/server.dart';
import 'package:opaque/src/opaque/offline_registration.dart';
import 'package:test/test.dart';

import '../util.dart';
import 'test_vectors.dart';

void main() {
  group('request', () {
    for (final vector in vectors) {
      test(vector.name, () async {
        final opaque = Opaque(vector.suite);

        final registration = opaque.offlineRegistration;
        final result = await registration.createRegistrationRequest(
          password: vector.input.password.hexDecode(),
          blind: vector.input.blindRegistration.hexDecode(),
        );
        final request = result.request;

        //expect(blind.hexEncode(), vector.input.blindRegistration);
        expect(request.data.hexEncode(), vector.output.registrationRequest);
      });
    }
  });

  group('response', () {
    for (final vector in vectors) {
      test(vector.name, () async {
        final opaque = Opaque(vector.suite);

        final registration = opaque.offlineRegistration;
        final response = await registration.createRegistrationResponse(
          request: RegistrationRequest(
            data: vector.output.registrationRequest.hexDecode(),
          ),
          serverPublicKey: vector.input.serverPublicKey.hexDecode(),
          credentialIdentifier: vector.input.credentialIdentifier.hexDecode(),
          oprfSeed: vector.input.oprfSeed.hexDecode(),
        );

        expect(
          response.serverPublicKey.hexEncode(),
          vector.input.serverPublicKey,
        );
        expect(
          response.data.hexEncode() + response.serverPublicKey.hexEncode(),
          vector.output.registrationResponse,
        );
      });
    }
  });

  group('finalize', () {
    for (final vector in vectors) {
      group(vector.name, () {
        final opaque = Opaque(vector.suite);

        final registration =
            opaque.offlineRegistration as OfflineRegistrationImpl;
        late final FinalizeRequestResult result;

        setUpAll(() async {
          result = await registration.finalizeRequest(
            password: vector.input.password.hexDecode(),
            blind: vector.input.blindRegistration.hexDecode(),
            response: RegistrationResponse.fromBytes(
              opaque.suite.constants,
              vector.output.registrationResponse.hexDecode(),
            ),
            serverIdentity: vector.input.serverIdentity?.hexDecode(),
            clientIdentity: vector.input.clientIdentity?.hexDecode() ??
                vector.intermediate.clientPublicKey.hexDecode(),
            testEnvelopeNonce: vector.input.envelopeNonce.hexDecode(),
          );
        });

        test('exportKey', () {
          expect(result.exportKey.hexEncode(), vector.output.exportKey);
        });
        test('envelope', () {
          expect(
            result.record.envelope.toBytes().hexEncode(),
            vector.intermediate.envelope,
          );
        });
      });
    }
  });
}
