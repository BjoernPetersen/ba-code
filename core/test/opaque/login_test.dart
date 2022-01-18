import 'package:opaque/client.dart';
import 'package:opaque/server.dart';
import 'package:opaque/src/opaque/online_ake.dart';
import 'package:opaque/src/opaque/three_dh.dart';
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
        final clientAke = opaque.getClientAke(clientState);

        final result = await clientAke.init(
          password: vector.input.password.hexDecode(),
          testBlind: vector.input.blindLogin.hexDecode(),
          testNonce: vector.input.clientNonce.hexDecode(),
          testKeyshare: vector.input.clientKeyshare.hexDecode(),
        );

        expect(
          result
              .asBytesList()
              .map((e) => e.hexEncode())
              .reduce((a, b) => a + b),
          vector.output.ke1,
        );
      });
    }
  });

  group('ServerInit', () {
    for (final vector in vectors) {
      test(vector.name, () async {
        final opaque = Opaque(vector.suite);

        final serverState = MemoryServerState();
        final serverAke =
            opaque.getServerAke(serverState) as ServerOnlineAkeImpl;

        final ke1 = vector.output.ke1.hexDecode();

        final result = await serverAke.init(
          serverIdentity: vector.input.serverIdentity?.hexDecode(),
          serverPrivateKey: vector.input.serverPrivateKey.hexDecode(),
          serverPublicKey: vector.input.serverPublicKey.hexDecode(),
          record: RegistrationRecord.fromBytes(
            opaque.suite.constants,
            vector.output.registrationUpload.hexDecode(),
          ),
          credentialIdentifier: vector.input.credentialIdentifier.hexDecode(),
          oprfSeed: vector.input.oprfSeed.hexDecode(),
          ke1: KE1.fromBytes(
            opaque.suite.constants,
            vector.output.ke1.hexDecode(),
          ),
          clientIdentity: vector.input.clientIdentity?.hexDecode() ??
              vector.intermediate.clientPublicKey.hexDecode(),
          testNonce: vector.input.serverNonce.hexDecode(),
          testMaskingNonce: vector.input.maskingNonce.hexDecode(),
          testKeyPair: KeyPair(
            private: vector.input.serverPrivateKey.hexDecode(),
            public: vector.input.serverPublicKey.hexDecode(),
          ),
        );
      });
    }
  });
}
