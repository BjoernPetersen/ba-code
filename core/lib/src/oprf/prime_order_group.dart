import 'dart:typed_data';

import 'package:opaque/src/oprf/data_conversion.dart';
import 'package:opaque/src/oprf/uniform_message_expander.dart';
import 'package:pointycastle/api.dart' show SecureRandom;
import 'package:pointycastle/ecc/api.dart';
import 'package:pointycastle/ecc/curves/secp384r1.dart';
import 'package:pointycastle/ecc/ecc_fp.dart' as fp;

/// Interface defined by Internet-Draft `draft-irtf-cfrg-voprf-08`.
abstract class PrimeOrderGroup<Element, Scalar> {
  BigInt get order;

  Element get identity;

  Future<Element> hashToGroup(ByteData data);

  Future<Scalar> hashToScalar(ByteData data);

  Scalar randomScalar();

  ByteData serializeElement(Element element);

  Element deserializeElement(ByteData data);

  ByteData serializeScalar(Scalar scalar);

  Scalar deserializeScalar(ByteData data);
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

  Future<List<ECFieldElement>> hashToField(
    ByteData data,
    String domainSeparator, {
    int count = 2,
  }) async {
    final l = 72;
    final lengthInBytes = l * count;
    final expander = UniformMessageExpander.sha384(
      lengthInBytes: lengthInBytes,
    );
    final expanded = await expander.expand(data, domainSeparator);
    final result = <ECFieldElement>[];
    for (int i = 0; i < count; i += 1) {
      final offset = l * i;
      final tv = expanded.sublist(offset, offset + l);
      final rawField = bytesToInt(tv).remainder(_curve.q!);
      result.add(_curve.fromBigInteger(rawField));
    }
    return result;
  }

  Future<ECPoint> hashToCurve(
    ByteData data,
    String domainSeparator,
  ) async {
    final fields = await hashToField(data, domainSeparator, count: 2);
    final points = fields.map(_mapToCurveSimpleSwu).toList(growable: false);
    // q1.y is wrong for empty message and abcdef0-9
    final sum = points.reduce((a, b) => (a + b)!);
    // TODO: clear_cofactor
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
    // TODO: sign?
    if (u.sign == y.sign) {
      return _curve.createPoint(xInt, yInt);
    } else {
      return _curve.createPoint(xInt, -yInt);
    }
  }

  @override
  Future<ECPoint> hashToGroup(
    ByteData data, [
    String? domainSeparator,
  ]) {
    final prefix = 'HashToGroup-';
    final dst = domainSeparator == null ? prefix : '$prefix$domainSeparator';
    return hashToCurve(data, dst);
  }

  @override
  Future<ECFieldElement> hashToScalar(
    ByteData data, [
    String? domainSeparator,
  ]) async {
    final prefix = 'HashToScalar-';
    final dst = domainSeparator == null ? prefix : '$prefix$domainSeparator';
    return (await hashToField(data, dst)).single;
  }

  @override
  ECFieldElement randomScalar() {
    final random = SecureRandom();
    BigInt scalar = BigInt.zero;

    while (scalar == BigInt.zero || scalar > order) {
      // This might yield zero or a value bigger than order, hence the loop
      scalar = random.nextBigInteger(_curve.fieldSize);
    }

    return _curve.fromBigInteger(scalar);
  }

  @override
  ByteData serializeElement(ECPoint element) {
    // TODO: implement serializeElement
    throw UnimplementedError();
  }

  @override
  ECPoint deserializeElement(ByteData data) {
    // TODO: implement deserializeElement
    throw UnimplementedError();
  }

  @override
  ByteData serializeScalar(ECFieldElement scalar) {
    // TODO: implement serializeScalar
    throw UnimplementedError();
  }

  @override
  ECFieldElement deserializeScalar(ByteData data) {
    // TODO: implement deserializeScalar
    throw UnimplementedError();
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
