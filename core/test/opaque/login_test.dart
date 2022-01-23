import 'package:opaque/server.dart';
import 'package:opaque/src/opaque/online_ake.dart';
import 'package:test/test.dart';

import '../util.dart';
import 'state_impl.dart';
import 'test_vectors.dart';

void main() {
  group('ClientInit', () {
    for (final vector in vectors) {
      test(vector.name, () async {
        final opaque = Opaque(vector.suite);

        final clientState = MemoryClientState();
        final clientAke = opaque.getClientAke(
          clientState,
          dhContext: vector.context.hexDecode(),
        ) as ClientOnlineAkeImpl;

        final ke1 = await clientAke.init(
          password: vector.input.password.hexDecode(),
          testBlind: vector.input.blindLogin.hexDecode(),
          testNonce: vector.input.clientNonce.hexDecode(),
          testKeyshare: vector.input.clientKeyshare.hexDecode(),
          testPrivateKey: vector.input.clientPrivateKeyshare.hexDecode(),
        );

        expect(
          ke1.asBytesList().map((e) => e.hexEncode()).reduce((a, b) => a + b),
          vector.output.ke1,
        );
      });
    }
  });

  group('ServerInit', () {
    for (final vector in vectors) {
      group(vector.name, () {
        final opaque = Opaque(vector.suite);

        final serverState = MemoryServerState();
        final serverAke = opaque.getServerAke(
          serverState,
          dhContext: vector.context.hexDecode(),
        ) as ServerOnlineAkeImpl;

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

  group('ClientFinish', () {
    for (final vector in vectors) {
      group(vector.name, () {
        final opaque = Opaque(vector.suite);

        final clientState = MemoryClientState();

        // Restore state that would be present if init had been done
        clientState.blind = vector.input.blindLogin.hexDecode();
        clientState.ke1 = KE1.fromBytes(
          opaque.suite.constants,
          vector.output.ke1.hexDecode(),
        );
        clientState.password = vector.input.password.hexDecode();
        clientState.clientSecret =
            vector.input.clientPrivateKeyshare.hexDecode();

        final clientAke = opaque.getClientAke(
          clientState,
          dhContext: vector.context.hexDecode(),
        ) as ClientOnlineAkeImpl;

        late final ClientFinishResult result;
        setUpAll(() async {
          result = await clientAke.finish(
            clientIdentity: vector.input.clientIdentity?.hexDecode() ??
                vector.intermediate.clientPublicKey.hexDecode(),
            serverIdentity: vector.input.serverIdentity?.hexDecode() ??
                vector.input.serverPublicKey.hexDecode(),
            ke2: KE2.fromBytes(
              opaque.suite.constants,
              vector.output.ke2.hexDecode(),
            ),
          );
        });

        test('sessionKey', () {
          expect(result.sessionKey.hexEncode(), vector.output.sessionKey);
        });
        test('exportKey', () {
          expect(result.exportKey.hexEncode(), vector.output.exportKey);
        });
        test('clientMac', () {
          expect(
            concatBytes(result.ke3.asBytesList()).hexEncode(),
            vector.output.ke3,
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

        final serverAke = opaque.getServerAke(
          serverState,
          dhContext: vector.context.hexDecode(),
        ) as ServerOnlineAkeImpl;

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

Future<KE2> _serverInit(ServerOnlineAkeImpl serverAke, Vector vector) {
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
