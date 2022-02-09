import 'package:opaque/client.dart';
import 'package:opaque/src/opaque/client/online_ake.dart';
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
        final clientAke = opaque.getOnlineAke(
          clientState,
          dhContext: vector.context.hexDecode(),
        ) as OnlineAkeImpl;

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

        final clientAke = opaque.getOnlineAke(
          clientState,
          dhContext: vector.context.hexDecode(),
        ) as OnlineAkeImpl;

        late final FinishResult result;
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
}
