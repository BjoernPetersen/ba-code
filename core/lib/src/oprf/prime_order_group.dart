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
  final UniformMessageExpander _messageExpander;

  final fp.ECCurve _curve;

  PrimeOrderGroupImpl._(
    this._params,
    this._messageExpander,
  ) : _curve = _params.curve as fp.ECCurve;

  PrimeOrderGroupImpl()
      : this._(
          ECCurve_secp384r1(),
          UniformMessageExpander.sha384(),
        );

  @override
  BigInt get order => _params.n;

  @override
  ECPoint get identity => _curve.infinity!;

  Future<List<BigInt>> hashToField(
    ByteData data,
    String domainSeparator,
  ) async {
    final l = 72;
    final count = 2;
    final lengthInBytes = l * count;
    final expander =
        UniformMessageExpander.sha384(lengthInBytes: lengthInBytes);
    final expanded = await expander.expand(data, domainSeparator);
    final result = <BigInt>[];
    for (int i = 0; i < count; i += 1) {
      final offset = l * i;
      final tv = expanded.sublist(offset, offset + l);
      result.add(bytesToInt(tv).remainder(_curve.q!));
    }
    return result;
  }

  Future<ECFieldElement> _hashToField(
    ByteData data,
    String domainSeparator,
  ) async {
    final l = 72;
    final count = 2;
    final expanded = await _messageExpander.expand(data, domainSeparator);
    final result = <BigInt>[];
    for (int i = 0; i < count; i += 1) {
      final offset = l * i;
      final tv = expanded.sublist(offset, offset + l);
      result.add(bytesToInt(tv).remainder(order));
    }
    return _curve.fromBigInteger(result[0]);
  }

  Future<ECPoint> _hashToCurve(ByteData data, String domainSeparator) async {
    final field = await _hashToField(data, domainSeparator);
    final curve = _mapToCurveSimpleSwu(field);
    return curve;
  }

  ECPoint _mapToCurveSimpleSwu(ECFieldElement field) {
    final ECFieldElement A = _curve.a!;
    final ECFieldElement B = _curve.b!;
    // TODO: choose proper Z
    final ECFieldElement Z = _curve.fromBigInteger(BigInt.from(-12));
    final ECFieldElement u = field;

    final ECFieldElement one = _curve.fromBigInteger(BigInt.one);

    final tv1 = (Z.square() * u.modPow(4, _curve)) + (Z * u.square());
    final ECFieldElement x1;
    if (tv1.isZero) {
      x1 = B / (Z * A);
    } else {
      x1 = (-B / A) * (one + tv1);
    }

    final ECFieldElement x;
    final ECFieldElement y;
    final gx1 = x1.modPow(3, _curve) + (A * x1) + B;
    final gx1sqrt = gx1.sqrt();
    if (gx1sqrt != null) {
      x = x1;
      y = gx1sqrt;
    } else {
      x = Z * u.square() * x1;
      final gx2 = x.modPow(3, _curve) + (A * x) + B;
      y = gx2.sqrt()!;
    }

    final xInt = x.toBigInteger()!;
    final yInt = y.toBigInteger()!;
    if (u.sign != y.sign) {
      return _curve.createPoint(xInt, -yInt);
    } else {
      return _curve.createPoint(xInt, yInt);
    }
  }

  @override
  Future<ECPoint> hashToGroup(ByteData data, [String? domainSeparator]) {
    final prefix = 'HashToGroup-';
    final dst = domainSeparator == null ? prefix : '$prefix$domainSeparator';
    return _hashToCurve(data, dst);
  }

  @override
  Future<ECFieldElement> hashToScalar(ByteData data,
      [String? domainSeparator]) {
    final prefix = 'HashToScalar-';
    final dst = domainSeparator == null ? prefix : '$prefix$domainSeparator';
    return _hashToField(data, dst);
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

  int get sign {
    // TODO: check whether this is right
    return toBigInteger()!.sign;
  }

  bool get isZero => toBigInteger() == BigInt.zero;
}
