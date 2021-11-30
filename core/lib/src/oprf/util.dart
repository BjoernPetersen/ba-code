import 'dart:typed_data';

extension CryptoBytes on ByteData {
  bool constantTimeEquals(ByteData other) {
    // TODO: use constantTimeBytesEquality from cryptography


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

  ByteData concat(ByteData other) {
    final builder = BytesBuilder(copy: false);
    builder.add(other.buffer.asUint8List());
    final list = builder.toBytes();
    return list.buffer.asByteData();
  }
}
