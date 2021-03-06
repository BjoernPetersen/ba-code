import 'package:opaque/src/opaque/key_derivation.dart';
import 'package:test/test.dart';

import '../util.dart';

void main() {
  group('Expand Real Test Vectors from OPAQUE irtf', () {
    for (int i = 0; i < vectors.length; i += 1) {
      test('Vector $i', () async {
        final vector = vectors[i];
        final authKey = await vector.kdf.expand(
          key: vector.randomizedPassword,
          info: concatBytes([
            vector.envelopeNonce,
            'AuthKey'.asciiBytes(),
          ]),
          l: vector.kdf.outputSize,
        );
        expect(authKey.hexEncode(), vector.authKey.hexEncode());
      });
    }
  });
}

class Vector {
  final KeyDerivationFunction kdf;
  final Bytes randomizedPassword;
  final Bytes envelopeNonce;
  final Bytes authKey;

  Vector.sha256({
    required String randomizedPassword,
    required String envelopeNonce,
    required String authKey,
  })  : kdf = KeyDerivationFunction.hkdfSha256(),
        randomizedPassword = randomizedPassword.hexDecode(),
        envelopeNonce = envelopeNonce.hexDecode(),
        authKey = authKey.hexDecode();

  Vector.sha512({
    required String randomizedPassword,
    required String envelopeNonce,
    required String authKey,
  })  : kdf = KeyDerivationFunction.hkdfSha512(),
        randomizedPassword = randomizedPassword.hexDecode(),
        envelopeNonce = envelopeNonce.hexDecode(),
        authKey = authKey.hexDecode();
}

/// Taken from https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-07.html#appendix-D.1
final vectors = [
  Vector.sha512(
    randomizedPassword:
        '024d0bc2c5e95421951227ee87d8c5488e6dc537b2bf014452edb714bb98f0ef9590b1cca3345f2a1d0afff79967875306e07326b311662d5975b24e8207594e',
    envelopeNonce:
        '71b8f14b7a1059cdadc414c409064a22cf9e970b0ffc6f1fc6fdd539c4676775',
    authKey:
        '72c837a116b444f86229d432ea48221327339704fd2451704766bb3d42d10796a2be4083998a78f31f52f3d2fff6ace6b9c2fa9dae1ce64ee36cc867f6cc9e48',
  ),
  Vector.sha512(
    randomizedPassword:
        '16decdbba6912903b7ae38de7040a79ebc59c9fbbac04add8a7100ff8aedbb9530c4e664bd08b2689a607e99923e80563a8379ddfdb37801718ed043fb7bca07',
    envelopeNonce:
        'd0c7b0f0047682bd87a87e0c3553b9bcdce7e1ae3348570df20bf2747829b2d2',
    authKey:
        '8820ff275662bf91d4ebcca74c9b90913eb3ee8151047926ad754da823e98800db56a79c68b44d76ad906d26ed8b9e25d8ea862cfc6c2f0da86c623f6a24961a',
  ),
  Vector.sha256(
    randomizedPassword:
        'c741d0a042e653ee4ccf24648aee4e3b4c500cc28feb3a72eea0f24f69006693',
    envelopeNonce:
        '2527e48c983deeb54c9c6337fdd9e120de85343dc7887f00248f1acacc4a8319',
    authKey: '4e01ca008eb4f84b8cee1b84b3abfaeb4f2c7fb41d2c8ad0f4fe89d74e6f0fc5',
  ),
  Vector.sha256(
    randomizedPassword:
        '0588794becaf8f5fee7921cb467e4ce8b3c048e7b42d815ed306def278c231d3',
    envelopeNonce:
        '75c245690f9669a9af5699e8b23d6d1fa9e697aeb4526267d942b842e4426e42',
    authKey: 'b894fa35f63413029fcc70e80a0d1b59d1c90c3c255bfb11cf7b58fb136d2aee',
  ),
];
