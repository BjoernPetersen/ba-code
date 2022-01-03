import 'dart:convert';
import 'dart:typed_data';

extension CryptoByteData on ByteData {
  @Deprecated('use constantTimeBytesEquality from cryptography')
  bool constantTimeEquals(ByteData other) {
    // TODO: this only works for equally sized arrays
    bool isEqual = true;
    for (int i = 0; i < lengthInBytes; ++i) {
      final a = getInt8(i);
      final b = other.getInt8(i);
      if (a != b) {
        isEqual = false;
      }
    }
    return isEqual;
  }

  @Deprecated('Operate on ByteBuffer')
  ByteData concat(ByteData other) {
    final builder = BytesBuilder(copy: false);
    builder.add(other.buffer.asUint8List());
    final list = builder.toBytes();
    return list.buffer.asByteData();
  }
}

Uint8List concatBytes(List<Uint8List> byteLists) {
  final builder = BytesBuilder(copy: false);
  for (final list in byteLists) {
    builder.add(list);
  }
  return builder.toBytes();
}

ByteBuffer concatBuffers(List<ByteBuffer> buffers) {
  final builder = BytesBuilder(copy: false);
  for (final buffer in buffers) {
    builder.add(buffer.asUint8List());
  }
  return builder.toBytes().buffer;
}

extension Ascii on String {
  static final _encoder = AsciiEncoder();

  Uint8List asciiBytes() {
    return _encoder.convert(this);
  }
}
