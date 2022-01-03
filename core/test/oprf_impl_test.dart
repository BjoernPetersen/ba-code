import 'package:convert/convert.dart';
import 'package:opaque/core.dart';
import 'package:opaque/src/oprf/oprf_impl.dart';
import 'package:opaque/src/oprf/prime_order_group.dart';
import 'package:opaque/src/oprf/util.dart';
import 'package:test/test.dart';

void main() {
  final primeGroup = PrimeOrderGroup.p384();
  final oprf = OprfImpl(primeGroup);
  final seed = hexDecode(
    'a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3',
  );
  final skSm =
      'b9ff42e68ef6f8eaa3b4d15d15ceb6f3f36b9dc332a3473d64840fc7b44626c6e70336bdecbe01d9c512b7e7d7e6af21';
  final secretKey = decodeKey(primeGroup, skSm);

  group('deriveKey', () {
    test('test vector key', () async {
      final keyPair = await oprf.deriveKeyPair(seed);
      expect(keyPair.private, skSm);
    });
  });

  group('POPRF base mode test vectors', () {
    group('Blind', () {
      for (final vector in vectors) {
        test(vector.name, () async {
          final BlindPair blinds = await oprf.blind(
            vector.input,
            blind: vector.blind,
          );
          expect(blinds.blind, vector.blind);
          expect(
            blinds.blindedElement,
            vector.blindedElement,
          );
        });
      }
    });

    group('Evaluate', () {
      for (final vector in vectors) {
        test(vector.name, () async {
          final evaluatedElement = await oprf.evaluate(
            privateKey: secretKey,
            input: vector.input,
            info: vector.info,
          );

          expect(
            evaluatedElement,
            vector.evaluationElement,
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
          expect(output, vector.output);
        });
      }
    });
  });
}

extension on Bytes {
  String asString() {
    return hex.encode(this);
  }
}

Bytes decodeKey(PrimeOrderGroup primeGroup, String key) {
  final bytes = hexDecode(key);
  return bytes;
  // TODO: should be deserialized here?
  //return primeGroup.deserializeScalar(bytes);
}

BigInt parseHexInt(String s) {
  return BigInt.parse(s, radix: 16);
}

Bytes hexDecode(String s) {
  return Bytes.fromList(hex.decode(s));
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
        input = hexDecode(input),
        info = hexDecode(info),
        blind = hexDecode(blind),
        blindedElement = hexDecode(blindedElement),
        evaluationElement = hexDecode(evaluationElement),
        output = hexDecode(output);
}

final List<Vector> vectors = [
  Vector(
    input: '00',
    info: '7465737420696e666f',
    blind: 'c604c785ada70d77a5256ae21767de8c3304115237d262134f5e46e512cf8e03',
    blindedElement:
        '744441a5d3ee12571a84d34812443eba2b6521a47265ad655f01e759b3dd7d35',
    evaluationElement:
        '4254c503ee2013262473eec926b109b018d699b8dd954ee878bc17b159696353',
    output:
        '9aef8983b729baacb7ecf1be98d1276ca29e7d62dbf39bc595be018b66b199119f18579a9ae96a39d7d506c9e00f75b433a870d76ba755a3e7196911fff89ff3',
  ),
  Vector(
    input: '5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a',
    info: '7465737420696e666f',
    blind: '5ed895206bfc53316d307b23e46ecc6623afb3086da74189a416012be037e50b',
    blindedElement:
        'f4eeea4e1bcb2ec818ee2d5c1fcec56c24064a9ff4bea5b3dd6877800fc28e4d',
    evaluationElement:
        '185dae43b6209dacbc41a62fd4889700d11eeeff4e83ffbc72d54daee7e25659',
    output:
        'f556e2d83e576b4edc890472572d08f0d90d2ecc52a73b35b2a8416a72ff676549e3a83054fdf4fd16fe03e03bee7bb32cbd83c7ca212ea0d03b8996c2c268b2',
  ),
];
