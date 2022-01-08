import 'dart:typed_data';

import 'package:opaque/src/util.dart';

final _base = BigInt.from(256);

/// https://datatracker.ietf.org/doc/html/rfc8017#section-4.1
Uint8List intToBytes(BigInt number, int length) {
  if (number >= _base.pow(length)) {
    throw ArgumentError.value(
      number,
      'number',
      'input number too large for desired length',
    );
  }

  var remaining = number;
  final result = Uint8List(length);
  for (int i = length - 1; remaining != BigInt.zero && i >= 0; i -= 1) {
    result[i] = (remaining % _base).toInt();
    remaining = remaining ~/ _base;
  }

  return result;
}

/// https://datatracker.ietf.org/doc/html/rfc8017#section-4.1
Bytes smallIntToBytes(int number, {required int length}) {
  return intToBytes(BigInt.from(number), length);
}

/// https://datatracker.ietf.org/doc/html/rfc8017#section-4.2
BigInt bytesToInt(List<int> bytes) {
  BigInt sum = BigInt.from(bytes.last);
  final factor = BigInt.from(256);
  for (int i = 1; i < bytes.length; i += 1) {
    final index = bytes.length - (i + 1);
    sum += BigInt.from(bytes[index]) * factor.pow(i);
  }
  return sum;
}
