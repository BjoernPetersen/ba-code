import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:opaque/src/model/model.dart';

export 'package:opaque/src/model/model.dart' show Bytes;

Bytes concatBytes(List<Bytes> byteLists) {
  final builder = BytesBuilder(copy: false);
  for (final list in byteLists) {
    builder.add(list);
  }
  return builder.toBytes();
}

extension BytesUtils on Bytes {
  Bytes operator ^(Bytes other) {
    if (length != other.length) {
      throw ArgumentError.value(other, 'other', 'Must have equal length');
    }

    final result = Uint8List(length);
    for (int i = 0; i < length; i += 1) {
      result[i] = this[i] ^ other[i];
    }

    return result;
  }

  Bytes slice([int offset = 0, int? length]) {
    return sublist(
      offset,
      length == null ? null : offset + length,
    );
  }
}

extension Ascii on String {
  static final _encoder = AsciiEncoder();

  Bytes asciiBytes() {
    return _encoder.convert(this);
  }
}

Future<Bytes> randomSeed(int length) async {
  final random = Random.secure();
  final result = Bytes(length);
  for (int i = 0; i < length; i += 1) {
    result[i] = random.nextInt(256);
  }
  return result;
}
