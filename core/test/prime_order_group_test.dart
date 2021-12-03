import 'dart:convert';

import 'package:opaque/src/oprf/prime_order_group.dart';
import 'package:test/test.dart';

final vectors = [
  Vector(
    msg: '',
    p: Point(
      x: 'eb9fe1b4f4e14e7140803c1d99d0a93cd823d2b024040f9c067a8eca1f5a2eeac9ad604973527a356f3fa3aeff0e4d83',
      y: '0c21708cff382b7f4643c07b105c2eaec2cead93a917d825601e63c8f21f6abd9abc22c93c2bed6f235954b25048bb1a',
    ),
    u: [
      '25c8d7dc1acd4ee617766693f7f8829396065d1b447eedb155871feffd9c6653279ac7e5c46edb7010a0e4ff64c9f3b4',
      '59428be4ed69131df59a0c6a8e188d2d4ece3f1b2a3a02602962b47efa4d7905945b1e2cc80b36aa35c99451073521ac',
    ],
    q0: Point(
      x: 'e4717e29eef38d862bee4902a7d21b44efb58c464e3e1f0d03894d94de310f8ffc6de86786dd3e15a1541b18d4eb2846',
      y: '6b95a6e639822312298a47526bb77d9cd7bcf76244c991c8cd70075e2ee6e8b9a135c4a37e3c0768c7ca871c0ceb53d4',
    ),
    q1: Point(
      x: '509527cfc0750eedc53147e6d5f78596c8a3b7360e0608e2fab0563a1670d58d8ae107c9f04bcf90e89489ace5650efd',
      y: '33337b13cb35e173fdea4cb9e8cce915d836ff57803dbbeb7998aa49d17df2ff09b67031773039d09fbd9305a1566bc4',
    ),
  ),
  Vector(
    msg: 'abc',
    p: Point(
      x: 'e02fc1a5f44a7519419dd314e29863f30df55a514da2d655775a81d413003c4d4e7fd59af0826dfaad4200ac6f60abe1',
      y: '01f638d04d98677d65bef99aef1a12a70a4cbb9270ec55248c04530d8bc1f8f90f8a6a859a7c1f1ddccedf8f96d675f6',
    ),
    u: [
      '53350214cb6bef0b51abb791b1c4209a2b4c16a0c67e1ab1401017fad774cd3b3f9a8bcdf7f6229dd8dd5a075cb149a0',
      'c0473083898f63e03f26f14877a2407bd60c75ad491e7d26cbc6cc5ce815654075ec6b6898c7a41d74ceaf720a10c02e',
    ],
    q0: Point(
      x: 'fc853b69437aee9a19d5acf96a4ee4c5e04cf7b53406dfaa2afbdd7ad2351b7f554e4bbc6f5db4177d4d44f933a8f6ee',
      y: '7e042547e01834c9043b10f3a8221c4a879cb156f04f72bfccab0c047a304e30f2aa8b2e260d34c4592c0c33dd0c6482',
    ),
    q1: Point(
      x: '57912293709b3556b43a2dfb137a315d256d573b82ded120ef8c782d607c05d930d958e50cb6dc1cc480b9afc38c45f1',
      y: 'de9387dab0eef0bda219c6f168a92645a84665c4f2137c14270fb424b7532ff84843c3da383ceea24c47fa343c227bb8',
    ),
  ),
];

void main() {
  final primeOrderGroup = PrimeOrderGroupImpl();
  final dst = 'QUUX-V01-CS02-with-P384_XMD:SHA-384_SSWU_RO_';

  group('hash_to_field', () {
    for (final vector in vectors) {
      final messageBytes =
          AsciiEncoder().convert(vector.msg).buffer.asByteData();
      test('Message "${vector.msg}"', () async {
        final result = await primeOrderGroup.hashToField(messageBytes, dst);
        expect(result, vector.u);
      });
    }
  });
}

class Vector {
  final String msg;
  final Point p;
  final List<BigInt> u;
  final Point q0;
  final Point q1;

  Vector({
    required this.msg,
    required this.p,
    required List<String> u,
    required this.q0,
    required this.q1,
  }) : u = u.map((s) => BigInt.parse(s, radix: 16)).toList(growable: false);
}

class Point {
  final BigInt x;
  final BigInt y;

  Point({
    required String x,
    required String y,
  })  : x = BigInt.parse(x, radix: 16),
        y = BigInt.parse(y, radix: 16);
}
