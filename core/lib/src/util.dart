import 'dart:convert';
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

extension Ascii on String {
  static final _encoder = AsciiEncoder();

  Bytes asciiBytes() {
    return _encoder.convert(this);
  }
}
