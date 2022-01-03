import 'package:opaque/src/oprf/prime_order_group.dart';
import 'package:opaque/src/oprf/util.dart';
import 'package:test/test.dart';

void main() {
  final primeOrderGroup = PrimeOrderGroupImpl();
  final dst = 'QUUX-V01-CS02-with-P384_XMD:SHA-384_SSWU_RO_'.asciiBytes();

  group('hash_to_field', () {
    for (final vector in vectors) {
      final messageBytes = vector.msg.asciiBytes();
      test('Message "${vector.msg}"', () async {
        final result = await primeOrderGroup.hashToField(messageBytes, dst);
        final resultInts =
            result.map((e) => e.toBigInteger()!).toList(growable: false);
        expect(resultInts, vector.u);
      });
    }
  });

  group(
    'hash_to_group',
    () {
      for (final vector in vectors) {
        final messageBytes = vector.msg.asciiBytes();
        test('Message "${vector.msg}"', () async {
          final result = await primeOrderGroup.hashToCurve(messageBytes, dst);
          expect(result.x?.toBigInteger(), vector.p.x);
          expect(result.y?.toBigInteger(), vector.p.y);
        });
      }
    },
  );
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
  Vector(
    msg: 'abcdef0123456789',
    p: Point(
      x: 'bdecc1c1d870624965f19505be50459d363c71a699a496ab672f9a5d6b78676400926fbceee6fcd1780fe86e62b2aa89',
      y: '57cf1f99b5ee00f3c201139b3bfe4dd30a653193778d89a0accc5e0f47e46e4e4b85a0595da29c9494c1814acafe183c',
    ),
    u: [
      'aab7fb87238cf6b2ab56cdcca7e028959bb2ea599d34f68484139dde85ec6548a6e48771d17956421bdb7790598ea52e',
      '26e8d833552d7844d167833ca5a87c35bcfaa5a0d86023479fb28e5cd6075c18b168bf1f5d2a0ea146d057971336d8d1',
    ],
    q0: Point(
      x: '0ceece45b73f89844671df962ad2932122e878ad2259e650626924e4e7f132589341dec1480ebcbbbe3509d11fb570b7',
      y: 'fafd71a3115298f6be4ae5c6dfc96c400cfb55760f185b7b03f3fa45f3f91eb65d27628b3c705cafd0466fafa54883ce',
    ),
    q1: Point(
      x: 'dea1be8d3f9be4cbf4fab9d71d549dde76875b5d9b876832313a083ec81e528cbc2a0a1d0596b3bcb0ba77866b129776',
      y: 'eb15fe71662214fb03b65541f40d3eb0f4cf5c3b559f647da138c9f9b7484c48a08760e02c16f1992762cb7298fa52cf',
    ),
  ),
  Vector(
    msg:
        'q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq',
    p: Point(
      x: '03c3a9f401b78c6c36a52f07eeee0ec1289f178adf78448f43a3850e0456f5dd7f7633dd31676d990eda32882ab486c0',
      y: 'cc183d0d7bdfd0a3af05f50e16a3f2de4abbc523215bf57c848d5ea662482b8c1f43dc453a93b94a8026db58f3f5d878',
    ),
    u: [
      '04c00051b0de6e726d228c85bf243bf5f4789efb512b22b498cde3821db9da667199b74bd5a09a79583c6d353a3bb41c',
      '97580f218255f899f9204db64cd15e6a312cb4d8182375d1e5157c8f80f41d6a1a4b77fb1ded9dce56c32058b8d5202b',
    ],
    q0: Point(
      x: '051a22105e0817a35d66196338c8d85bd52690d79bba373ead8a86dd9899411513bb9f75273f6483395a7847fb21edb4',
      y: 'f168295c1bbcff5f8b01248e9dbc885335d6d6a04aea960f7384f746ba6502ce477e624151cc1d1392b00df0f5400c06',
    ),
    q1: Point(
      x: '6ad7bc8ed8b841efd8ad0765c8a23d0b968ec9aa360a558ff33500f164faa02bee6c704f5f91507c4c5aad2b0dc5b943',
      y: '47313cc0a873ade774048338fc34ca5313f96bbf6ae22ac6ef475d85f03d24792dc6afba8d0b4a70170c1b4f0f716629',
    ),
  ),
  Vector(
    msg:
        'a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    p: Point(
      x: '7b18d210b1f090ac701f65f606f6ca18fb8d081e3bc6cbd937c5604325f1cdea4c15c10a54ef303aabf2ea58bd9947a4',
      y: 'ea857285a33abb516732915c353c75c576bf82ccc96adb63c094dde580021eddeafd91f8c0bfee6f636528f3d0c47fd2',
    ),
    u: [
      '480cb3ac2c389db7f9dac9c396d2647ae946db844598971c26d1afd53912a1491199c0a5902811e4b809c26fcd37a014',
      'd28435eb34680e148bf3908536e42231cba9e1f73ae2c6902a222a89db5c49c97db2f8fa4d4cd6e424b17ac60bdb9bb6',
    ],
    q0: Point(
      x: '42e6666f505e854187186bad3011598d9278b9d6e3e4d2503c3d236381a56748dec5d139c223129b324df53fa147c4df',
      y: '8ee51dbda46413bf621838cc935d18d617881c6f33f3838a79c767a1e5618e34b22f79142df708d2432f75c7366c8512',
    ),
    q1: Point(
      x: '4ff01ceeba60484fa1bc0d825fe1e5e383d8f79f1e5bb78e5fb26b7a7ef758153e31e78b9d60ce75c5e32e43869d4e12',
      y: '0f84b978fac8ceda7304b47e229d6037d32062e597dc7a9b95bcd9af441f3c56c619a901d21635f9ec6ab4710b9fcd0e',
    ),
  ),
];
