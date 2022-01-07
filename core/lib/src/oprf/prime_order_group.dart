import 'dart:math';

import 'package:convert/convert.dart';
import 'package:opaque/src/oprf/data_conversion.dart';
import 'package:opaque/src/oprf/uniform_message_expander.dart';
import 'package:opaque/src/oprf/util.dart';
import 'package:pointycastle/api.dart';
import 'package:pointycastle/ecc/api.dart';
import 'package:pointycastle/ecc/curves/secp384r1.dart';
import 'package:pointycastle/ecc/ecc_fp.dart' as fp;
import 'package:pointycastle/random/fortuna_random.dart';

/// Interface defined by Internet-Draft `draft-irtf-cfrg-voprf-08`.
abstract class PrimeOrderGroup<Element extends ECPoint,
    Scalar extends ECFieldElement> {
  static PrimeOrderGroup<ECPoint, ECFieldElement> p384() =>
      PrimeOrderGroupImpl();

  BigInt get order;

  Element get identity;

  Future<Element> hashToGroup({
    required Bytes data,
    required Bytes domainSeparator,
  });

  Future<Scalar> hashToScalar({
    required Bytes data,
    required Bytes domainSeparator,
  });

  Scalar randomScalar();

  Bytes serializeElement(Element element);

  Element deserializeElement(Bytes data);

  Bytes serializeScalar(Scalar scalar);

  Scalar deserializeScalar(Bytes data);

  Element scalarBaseMult(Scalar scalar);
}

class PrimeOrderGroupImpl implements PrimeOrderGroup<ECPoint, ECFieldElement> {
  final ECDomainParameters _params;

  final fp.ECCurve _curve;

  PrimeOrderGroupImpl._(
    this._params,
  ) : _curve = _params.curve as fp.ECCurve;

  PrimeOrderGroupImpl()
      : this._(
          ECCurve_secp384r1(),
        );

  @override
  BigInt get order => _params.n;

  BigInt get q => _curve.q!;

  @override
  ECPoint get identity => _curve.infinity!;

  Future<List<ECFieldElement>> hashToField({
    required Bytes data,
    required Bytes domainSeparator,
    int count = 2,
  }) async {
    final l = 72;
    final lengthInBytes = l * count;
    final expander = UniformMessageExpander.sha384(
      lengthInBytes: lengthInBytes,
    );
    final expanded = await expander.expand(data, domainSeparator);
    final result = <ECFieldElement>[];

    // This one took a while
    final modulus = count == 1 ? order : q;

    for (int i = 0; i < count; i += 1) {
      final offset = l * i;
      final tv = expanded.sublist(offset, offset + l);
      // TODO order or q?
      final rawField = bytesToInt(tv).remainder(modulus);
      result.add(_curve.fromBigInteger(rawField));
    }
    return result;
  }

  Future<ECPoint> hashToCurve({
    required Bytes data,
    required Bytes domainSeparator,
  }) async {
    final fields = await hashToField(
      data: data,
      domainSeparator: domainSeparator,
      count: 2,
    );
    final points = fields.map(_mapToCurveSimpleSwu).toList(growable: false);
    final sum = points.reduce((a, b) => (a + b)!);
    return sum;
  }

  BigInt inv(BigInt x) {
    if (x == BigInt.zero) {
      return x;
    }

    return x.modPow(q - BigInt.two, q);
  }

  /// https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-13.html#section-6.6.2
  ECPoint _mapToCurveSimpleSwu(ECFieldElement field) {
    // Values chosen as per https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-13.html#section-8.3
    final ECFieldElement A = _curve.fromBigInteger(BigInt.from(-3));
    final ECFieldElement B = _curve.fromBigInteger(BigInt.parse(
      'b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef',
      radix: 16,
    ));
    final ECFieldElement Z = _curve.fromBigInteger(BigInt.from(-12));
    final ECFieldElement u = field;

    final ECFieldElement one = _curve.fromBigInteger(BigInt.one);

    // TODO: check which one is "more right"
    //final tv1 =_curve.fromBigInteger(inv(((Z.square() * u.modPow(4, _curve)) + (Z * u.square())).toBigInteger()!));
    final tv1 =
        ((Z.square() * u.modPow(4, _curve)) + (Z * u.square())).invert();
    final ECFieldElement x1;
    if (tv1.isZero) {
      x1 = B / (Z * A);
    } else {
      x1 = (-B / A) * (one + tv1);
    }

    final ECFieldElement x;
    final ECFieldElement y;
    final gx1 = x1.modPow(3, _curve) + (A * x1) + B;
    // TODO: check isSquare instead?
    final gx1sqrt = gx1.positive.sqrt();
    if (gx1sqrt != null) {
      x = x1;
      y = gx1sqrt;
    } else {
      x = Z * u.square() * x1;
      final gx2 = x.modPow(3, _curve) + (A * x) + B;
      y = gx2.positive.sqrt()!;
    }

    final xInt = x.toBigInteger()!;
    final yInt = y.toBigInteger()!;
    if (u.sign == y.sign) {
      return _curve.createPoint(xInt, yInt);
    } else {
      return _curve.createPoint(xInt, -yInt);
    }
  }

  @override
  Future<ECPoint> hashToGroup({
    required Bytes data,
    required Bytes domainSeparator,
  }) {
    final prefix = 'HashToGroup-';
    final fullDomainSeparator = concatBytes([
      prefix.asciiBytes(),
      domainSeparator,
    ]);
    return hashToCurve(data: data, domainSeparator: fullDomainSeparator);
  }

  @override
  Future<ECFieldElement> hashToScalar({
    required Bytes data,
    required Bytes domainSeparator,
  }) async {
    final prefix = 'HashToScalar-';
    final fullDomainSeparator = concatBytes([
      prefix.asciiBytes(),
      domainSeparator,
    ]);
    final hashed = (await hashToField(
      data: data,
      domainSeparator: fullDomainSeparator,
      count: 1,
    ));
    return hashed.single;
  }

  @override
  ECFieldElement randomScalar() {
    // TODO: this random implementation is really sketchy
    final random = FortunaRandom();

    // We need to seed FortunaRandom ourselves...
    final nativeRandom = Random.secure();
    final seed = List.generate(32, (_) => nativeRandom.nextInt(256));
    random.seed(KeyParameter(Bytes.fromList(seed)));

    BigInt scalar = BigInt.zero;

    while (scalar == BigInt.zero || scalar > order) {
      // This might yield zero or a value bigger than order, hence the loop
      scalar = random.nextBigInteger(_curve.fieldSize);
    }

    return _curve.fromBigInteger(scalar);
  }

  // https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.202.2977&rep=rep1&type=pdf
  @override
  Bytes serializeElement(ECPoint element) {
    if (element.isInfinity) {
      return smallIntToBytes(0, length: 49);
    }

    assert(q.isOdd);
    final yTilde = element.y!.toBigInteger()!.remainder(BigInt.two);
    final y = yTilde == BigInt.zero ? 0x02 : 0x03;
    final x = element.x!.toBigInteger()!;

    return concatBytes([
      smallIntToBytes(y, length: 1),
      intToBytes(x, 48),
    ]);
  }

  @override
  ECPoint deserializeElement(Bytes data) {
    final y = data[0];
    final int yTilde;
    if (y == 0x02) {
      yTilde = 0;
    } else if (y == 0x03) {
      yTilde = 1;
    } else {
      throw ArgumentError.value(y, 'y', 'Invalid value for y');
    }

    final x = bytesToInt(data.sublist(1));
    return _curve.decompressPoint(yTilde, x);
  }

  @override
  Bytes serializeScalar(ECFieldElement scalar) {
    return intToBytes(scalar.toBigInteger()!.remainder(order), 48);
  }

  @override
  ECFieldElement deserializeScalar(Bytes data) {
    final raw = bytesToInt(data);
    return _curve.fromBigInteger(raw);
  }

  @override
  ECPoint scalarBaseMult(ECFieldElement scalar) {
    return (_params.G * scalar.toBigInteger())!;
  }
}

extension on ECFieldElement {
  ECFieldElement modPow(int exponent, fp.ECCurve curve) {
    final x = toBigInteger()!;
    return curve.fromBigInteger(
      x.modPow(BigInt.from(exponent), curve.q!),
    );
  }

  ECFieldElement get positive {
    if (sign == -1) {
      return -this;
    } else {
      return this;
    }
  }

  /// https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-13.html#section-4.1
  int get sign {
    // m is 1, so we can simplify the loop
    return toBigInteger()!.remainder(BigInt.two).toInt();
  }

  bool get isZero => toBigInteger() == BigInt.zero;
}
