import 'package:opaque/server.dart';
import 'package:opaque/src/opaque/server/online_ake.dart';
import 'package:test/test.dart';

import '../util.dart';
import 'state_impl.dart';
import 'test_vectors.dart';

void main() {
  group('ServerInit', () {
    for (final vector in vectors) {
      group(vector.name, () {
        final opaque = Opaque(vector.suite);

        final serverState = MemoryServerState();
        final serverAke = opaque.getOnlineAke(
          serverState,
          dhContext: vector.context.hexDecode(),
        ) as OnlineAkeImpl;

        late final KE2 ke2;

        setUpAll(() async {
          ke2 = await _serverInit(serverAke, vector);
        });

        final expectedKe2 = KE2.fromBytes(
          vector.suite.constants,
          vector.output.ke2.hexDecode(),
        );

        test('authResponse.serverNonce', () {
          expect(
            ke2.authResponse.serverNonce.hexEncode(),
            expectedKe2.authResponse.serverNonce.hexEncode(),
          );
        });
        test('authResponse.serverKeyshare', () {
          expect(
            ke2.authResponse.serverKeyshare.hexEncode(),
            expectedKe2.authResponse.serverKeyshare.hexEncode(),
          );
        });
        test('authResponse.serverMac', () {
          expect(
            ke2.authResponse.serverMac.hexEncode(),
            expectedKe2.authResponse.serverMac.hexEncode(),
          );
        });

        test('credentialResponse.maskingNonce', () {
          expect(
            ke2.credentialResponse.maskingNonce.hexEncode(),
            expectedKe2.credentialResponse.maskingNonce.hexEncode(),
          );
        });
        test('credentialResponse.maskedResponse', () {
          expect(
            ke2.credentialResponse.maskedResponse.hexEncode(),
            expectedKe2.credentialResponse.maskedResponse.hexEncode(),
          );
        });
        test('credentialResponse.data', () {
          expect(
            ke2.credentialResponse.data.hexEncode(),
            expectedKe2.credentialResponse.data.hexEncode(),
          );
        });

        test('Full match', () {
          expect(
            ke2.asBytesList().map((e) => e.hexEncode()).reduce((a, b) => a + b),
            vector.output.ke2,
          );
        });
      });
    }
  });

  group('ServerFinish', () {
    for (final vector in vectors) {
      group(vector.name, () {
        final opaque = Opaque(vector.suite);

        final serverState = MemoryServerState();

        final serverAke = opaque.getOnlineAke(
          serverState,
          dhContext: vector.context.hexDecode(),
        ) as OnlineAkeImpl;

        late final Bytes result;

        setUpAll(() async {
          // Do init to populate state
          await _serverInit(serverAke, vector);

          result = await serverAke.serverFinish(
            ke3: KE3.fromBytes(
              opaque.suite.constants,
              vector.output.ke3.hexDecode(),
            ),
          );
        });

        test('sessionKey is returned', () {
          expect(
            result.hexEncode(),
            vector.output.sessionKey,
          );
        });
      });
    }
  });
}

Future<KE2> _serverInit(OnlineAkeImpl serverAke, Vector vector) {
  return serverAke.init(
    serverIdentity: vector.input.serverIdentity?.hexDecode(),
    serverPrivateKey: vector.input.serverPrivateKey.hexDecode(),
    serverPublicKey: vector.input.serverPublicKey.hexDecode(),
    record: RegistrationRecord.fromBytes(
      vector.suite.constants,
      vector.output.registrationUpload.hexDecode(),
    ),
    credentialIdentifier: vector.input.credentialIdentifier.hexDecode(),
    oprfSeed: vector.input.oprfSeed.hexDecode(),
    ke1: KE1.fromBytes(
      vector.suite.constants,
      vector.output.ke1.hexDecode(),
    ),
    clientIdentity: vector.input.clientIdentity?.hexDecode() ??
        vector.intermediate.clientPublicKey.hexDecode(),
    testNonce: vector.input.serverNonce.hexDecode(),
    testMaskingNonce: vector.input.maskingNonce.hexDecode(),
    testKeyPair: KeyPair(
      private: vector.input.serverPrivateKeyshare.hexDecode(),
      public: vector.input.serverKeyshare.hexDecode(),
    ),
  );
}
