import 'package:opaque/src/model/model.dart';
import 'package:test/test.dart';

import '../util.dart';
import 'test_vectors.dart';

void main() {
  group('Extract Real Test Vectors from OPAQUE irtf', () {
    for (final vector in vectors) {
      test('Vector ${vector.name}', () async {
        final ke2 = KE2.fromBytes(
          vector.suite.constants,
          vector.output.ke2.hexDecode(),
        );
        final y = await vector.suite.oprf.finalize(
          input: vector.input.password.hexDecode(),
          blind: vector.input.blindLogin.hexDecode(),
          evaluatedElement: ke2.credentialResponse.data,
          info: Bytes(0),
        );
        final randomizedPassword = await vector.suite.kdf.extract(
          inputMaterial: concatBytes([y, await vector.suite.mhf.harden(y)]),
        );
        expect(
          randomizedPassword.hexEncode(),
          vector.intermediate.randomizedPwd,
        );
      });
    }
  });
}
