import 'package:opaque/src/oprf/oprf.dart';
import 'package:opaque/src/oprf/oprf_impl.dart';
import 'package:opaque/src/oprf/prime_order_group.dart';
import 'package:test/test.dart';

import '../util.dart';

void main() {
  group('p256', () {
    final oprf = OprfImpl.p256();
    final seed =
        'a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3'
            .hexDecode();
    final skSm =
        'c15d9e9ab36d495d9d62954db6aafe06d3edabf41600d58f9be0737af2719e97';
    testVectors(oprf, seed, skSm, p256Vectors);
  });

  group('p384', () {
    final oprf = OprfImpl.p384();
    final seed =
        'a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3'
            .hexDecode();
    final skSm =
        'b9ff42e68ef6f8eaa3b4d15d15ceb6f3f36b9dc332a3473d64840fc7b44626c6e70336bdecbe01d9c512b7e7d7e6af21';
    testVectors(oprf, seed, skSm, p384Vectors);
  });
}

void testVectors(
  OprfImpl oprf,
  Bytes seed,
  String skSm,
  List<Vector> vectors,
) {
  final secretKey = decodeKey(oprf.group, skSm);
  group('deriveKey', () {
    test('test vector key', () async {
      final keyPair = await oprf.deriveKeyPair(seed: seed);
      expect(keyPair.private.hexEncode(), skSm);
    });
  });

  group('POPRF base mode test vectors', () {
    group('Blind', () {
      for (final vector in vectors) {
        test(vector.name, () async {
          final BlindPair blinds = await oprf.blind(
            input: vector.input,
            blind: vector.blind,
          );
          expect(blinds.blind, vector.blind);
          expect(
            blinds.blindedElement.hexEncode(),
            vector.blindedElement.hexEncode(),
          );
        });
      }
    });

    group(
      'Unblind',
      () {
        for (final vector in vectors) {
          test(vector.name, () async {
            final unblinded = await oprf.unblind(
              blind: vector.blind,
              blindedElement: vector.blindedElement,
            );

            // We're hashing before actually blinding, so we obviously can't
            // get our input back.
            final hashedToGroup = await oprf.group.hashToGroup(
              data: vector.input,
              domainSeparator: oprf.contextString,
            );
            final expected = oprf.group.serializeElement(hashedToGroup);
            expect(unblinded.hexEncode(), expected.hexEncode());
          });
        }
      },
    );

    group('Evaluate', () {
      for (final vector in vectors) {
        test(vector.name, () async {
          final evaluatedElement = await oprf.evaluate(
            privateKey: secretKey,
            blindedElement: vector.blindedElement,
            info: vector.info,
          );

          expect(
            evaluatedElement.hexEncode(),
            vector.evaluationElement.hexEncode(),
          );
        });
      }
    });

    group('Finalize', () {
      for (final vector in vectors) {
        test(vector.name, () async {
          final output = await oprf.finalize(
            input: vector.input,
            blind: vector.blind,
            evaluatedElement: vector.evaluationElement,
            info: vector.info,
          );
          expect(output.hexEncode(), vector.output.hexEncode());
        });
      }
    });
  });
}

Bytes decodeKey(PrimeOrderGroup primeGroup, String key) {
  final bytes = key.hexDecode();
  return bytes;
  // TODO: should be deserialized here?
  //return primeGroup.deserializeScalar(bytes);
}

BigInt parseHexInt(String s) {
  return BigInt.parse(s, radix: 16);
}

class Vector {
  final String name;
  final Bytes input;
  final PublicInput info;
  final Bytes blind;
  final Bytes blindedElement;
  final Bytes evaluationElement;
  final Bytes output;

  Vector({
    required String input,
    required String info,
    required String blind,
    required String blindedElement,
    required String evaluationElement,
    required String output,
  })  : name = input,
        input = input.hexDecode(),
        info = info.hexDecode(),
        blind = blind.hexDecode(),
        blindedElement = blindedElement.hexDecode(),
        evaluationElement = evaluationElement.hexDecode(),
        output = output.hexDecode();
}

final List<Vector> p256Vectors = [
  Vector(
    input: '00',
    info: '7465737420696e666f',
    blind: '5d9e7f6efd3093c32ecceabd57fb03cf760c926d2a7bfa265babf29ec98af0d0',
    blindedElement:
        '03e9097c54d2ea05f99424bdf984ea30ecc3614029bd5f1139e70c4e1ae3bdbd92',
    evaluationElement:
        '0202e4d1a338659c211900c39855f30025359928d261e6c9558d667b3fbbc811cd',
    output: '15b96275d06b85741f491fe0cad5cb835baa6c39066cbea73132dcf95e858e1c',
  ),
  Vector(
    input: '5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a',
    info: '7465737420696e666f',
    blind: '825155ab61f17605af2ae2e935c78d857c9407bcd45128d57d338f1671b5fcbe',
    blindedElement:
        '03fa1ea45dd58d6b516c1252f2791610bf5ff1828c93be8af66786f45fb4d14db5',
    evaluationElement:
        '02657822553416d91bb3d707040fd0d5a0555f5cbae7519df3a297747a3ad1dd57',
    output: 'e97f3f451f3cfce45a530dec0a0dec934cd78c5b656771549072ee236ce070b9',
  ),
];

final List<Vector> p384Vectors = [
  Vector(
    input: '00',
    info: '7465737420696e666f',
    blind:
        '359073c015b92d15450f7fb395bf52c6ea98384c491fe4e4d423b59de7b0df382902c13bdc9993d3717bda68fc080b99',
    blindedElement:
        '0285d803c65fda56993a296b99e8f4944e45cccb9b322bbc265c91a21d2c9cd146212aefbf3126ed59d84c32d6ab823b66',
    evaluationElement:
        '026061a4ccfe38777e725855c96570fe85303cd70567007e489d0aa8bfced0e47579ecbc290e5150b9e84bf25188294f7e',
    output:
        'bc2c3c895f96d769703aec18359cbc0e84b41248559f0bd44f1e54675223c77e00874bbe61c1c320d3c95aee5a8c752f',
  ),
  Vector(
    input: '5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a',
    info: '7465737420696e666f',
    blind:
        '21ece4f9b6ffd01ce82082545413bd9bb5e8f3c63b86ae88d9ce0530b01cb1c23382c7ec9bdd6e75898e4877d8e2bc17',
    blindedElement:
        '0211dd06e40b902006c33a92dc476a7c708b6b46c990656239cd6867ff0be5867d859517eaf7ea9bad10702b80a9dc6bdc',
    evaluationElement:
        '03a1d34b657f6267b29338592e3c769db5d3fc8713bf2eb7238efb8138d5af8c56f9437315a5c58761b35cbfc0e1d2511d',
    output:
        'ee37530d0d7b20635fbc476317343b257750ffb3e83a2865ce2a46e59591f854b8301d6ca7d063322314a33b953c8bd5',
  ),
];
